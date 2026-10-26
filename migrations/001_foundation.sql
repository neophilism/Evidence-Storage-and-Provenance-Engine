-- Dedicated Evidence database only. Apply transactionally as a migration owner.
-- The application authenticates as a separate restricted LOGIN granted evidence_runtime.
BEGIN;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='evidence_runtime') THEN
  CREATE ROLE evidence_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
 END IF;
 IF EXISTS (SELECT FROM pg_roles WHERE rolname='evidence_runtime' AND
   (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication)) THEN
  RAISE EXCEPTION 'Unsafe existing evidence_runtime role';
 END IF;
END $$;
CREATE TABLE public.evidence_schema_version (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE public.evidence_project (
 tenant_id text NOT NULL CHECK(length(tenant_id) BETWEEN 1 AND 128),
 project_id text NOT NULL CHECK(length(project_id) BETWEEN 1 AND 128),
 audit_sequence bigint NOT NULL DEFAULT 0 CHECK(audit_sequence>=0), audit_hash text NOT NULL DEFAULT '',
 PRIMARY KEY (tenant_id,project_id)
);
CREATE TABLE public.evidence_record (
 tenant_id text NOT NULL, project_id text NOT NULL,
 kind text NOT NULL CHECK(length(kind) BETWEEN 1 AND 64), id text NOT NULL CHECK(length(id) BETWEEN 1 AND 128),
 revision integer NOT NULL CHECK(revision>0), value jsonb NOT NULL, created_at timestamptz NOT NULL,
 actor_id text NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 128),
 PRIMARY KEY(tenant_id,project_id,kind,id,revision),
 FOREIGN KEY(tenant_id,project_id) REFERENCES public.evidence_project(tenant_id,project_id)
);
CREATE TABLE public.evidence_head (
 tenant_id text NOT NULL, project_id text NOT NULL, kind text NOT NULL, id text NOT NULL, revision integer NOT NULL,
 PRIMARY KEY(tenant_id,project_id,kind,id),
 FOREIGN KEY(tenant_id,project_id,kind,id,revision) REFERENCES public.evidence_record(tenant_id,project_id,kind,id,revision)
);
CREATE TABLE public.evidence_audit (
 tenant_id text NOT NULL, project_id text NOT NULL, sequence bigint NOT NULL CHECK(sequence>0), id text NOT NULL,
 type text NOT NULL, actor_id text NOT NULL, at timestamptz NOT NULL, request_id text NOT NULL,
 payload jsonb NOT NULL, previous_hash text NOT NULL, hash text NOT NULL CHECK(hash ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,project_id,sequence), UNIQUE(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id) REFERENCES public.evidence_project(tenant_id,project_id)
);
CREATE TABLE public.evidence_idempotency (
 tenant_id text NOT NULL, project_id text NOT NULL, actor_id text NOT NULL, key text NOT NULL,
 fingerprint text NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'), result jsonb NOT NULL,
 PRIMARY KEY(tenant_id,project_id,actor_id,key),
 FOREIGN KEY(tenant_id,project_id) REFERENCES public.evidence_project(tenant_id,project_id)
);
CREATE TABLE public.evidence_outbox (
 tenant_id text NOT NULL, project_id text NOT NULL, id text NOT NULL, topic text NOT NULL, payload jsonb NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','completed','dead')),
 available_at timestamptz NOT NULL, lease_until timestamptz, lease_owner text,
 generation integer NOT NULL DEFAULT 0 CHECK(generation>=0), attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
 max_attempts integer NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 100), last_error text,
 PRIMARY KEY(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id) REFERENCES public.evidence_project(tenant_id,project_id),
 CHECK((state='leased' AND lease_until IS NOT NULL AND lease_owner IS NOT NULL) OR
       (state<>'leased' AND lease_until IS NULL AND lease_owner IS NULL)),
 CHECK(generation=attempts AND attempts<=max_attempts)
);
CREATE INDEX evidence_outbox_ready ON public.evidence_outbox (tenant_id,project_id,available_at,id) WHERE state IN ('pending','leased');
CREATE INDEX evidence_record_search ON public.evidence_record USING gin(value jsonb_path_ops);

-- No SECURITY DEFINER functions: normal runtime privileges and RLS apply inside triggers.
CREATE FUNCTION public.evidence_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'Evidence originals, audit and idempotency records are immutable' USING ERRCODE='55000'; END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['evidence_record','evidence_audit','evidence_idempotency'] LOOP
  EXECUTE format('CREATE TRIGGER immutable_rows BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.evidence_immutable()',t);
  EXECUTE format('CREATE TRIGGER immutable_truncate BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.evidence_immutable()',t);
 END LOOP;
END $$;
CREATE FUNCTION public.evidence_append_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE current_revision integer;
BEGIN
 PERFORM 1 FROM public.evidence_project WHERE tenant_id=NEW.tenant_id AND project_id=NEW.project_id FOR UPDATE;
 SELECT revision INTO current_revision FROM public.evidence_head
 WHERE tenant_id=NEW.tenant_id AND project_id=NEW.project_id AND kind=NEW.kind AND id=NEW.id;
 IF NEW.revision <> coalesce(current_revision,0)+1 THEN RAISE EXCEPTION 'Evidence revision must append to the current head' USING ERRCODE='40001'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER append_revision BEFORE INSERT ON public.evidence_record FOR EACH ROW EXECUTE FUNCTION public.evidence_append_revision();
CREATE FUNCTION public.evidence_advance_head() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 THEN RAISE EXCEPTION 'Initial evidence head must be revision one'; END IF;
 ELSE
  IF (NEW.tenant_id,NEW.project_id,NEW.kind,NEW.id) IS DISTINCT FROM (OLD.tenant_id,OLD.project_id,OLD.kind,OLD.id)
    OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'Evidence head must advance exactly one revision'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- INSERT ... ON CONFLICT invokes BEFORE INSERT before the conflict's UPDATE path.
-- Therefore initial-head validation belongs in an AFTER INSERT trigger.
CREATE TRIGGER initial_head AFTER INSERT ON public.evidence_head FOR EACH ROW EXECUTE FUNCTION public.evidence_advance_head();
CREATE TRIGGER advance_head BEFORE UPDATE ON public.evidence_head FOR EACH ROW EXECUTE FUNCTION public.evidence_advance_head();
CREATE FUNCTION public.evidence_append_audit() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p public.evidence_project;
BEGIN
 SELECT * INTO p FROM public.evidence_project WHERE tenant_id=NEW.tenant_id AND project_id=NEW.project_id FOR UPDATE;
 IF NEW.sequence<>p.audit_sequence+1 OR NEW.previous_hash<>p.audit_hash THEN RAISE EXCEPTION 'Evidence audit chain does not extend its head'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER append_audit BEFORE INSERT ON public.evidence_audit FOR EACH ROW EXECUTE FUNCTION public.evidence_append_audit();
CREATE FUNCTION public.evidence_advance_audit_head() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (NEW.tenant_id,NEW.project_id) IS DISTINCT FROM (OLD.tenant_id,OLD.project_id)
    OR NEW.audit_sequence<>OLD.audit_sequence+1 OR NOT EXISTS (
      SELECT FROM public.evidence_audit WHERE tenant_id=NEW.tenant_id AND project_id=NEW.project_id
      AND sequence=NEW.audit_sequence AND hash=NEW.audit_hash AND previous_hash=OLD.audit_hash)
 THEN RAISE EXCEPTION 'Evidence project audit head cannot rewind or skip its audit record'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER advance_audit_head BEFORE UPDATE ON public.evidence_project FOR EACH ROW EXECUTE FUNCTION public.evidence_advance_audit_head();

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['evidence_project','evidence_record','evidence_head','evidence_audit','evidence_idempotency','evidence_outbox'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope_isolation ON public.%I TO evidence_runtime USING (tenant_id = current_setting(''evidence.tenant_id'',true) AND project_id = current_setting(''evidence.project_id'',true)) WITH CHECK (tenant_id = current_setting(''evidence.tenant_id'',true) AND project_id = current_setting(''evidence.project_id'',true))',t);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',t);
 END LOOP;
END $$;
REVOKE ALL ON public.evidence_schema_version FROM PUBLIC;
REVOKE ALL ON FUNCTION public.evidence_immutable(),public.evidence_append_revision(),public.evidence_advance_head(),public.evidence_append_audit(),public.evidence_advance_audit_head() FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO evidence_runtime;
GRANT SELECT ON public.evidence_project TO evidence_runtime;
GRANT INSERT(tenant_id,project_id) ON public.evidence_project TO evidence_runtime;
GRANT SELECT,INSERT ON public.evidence_record,public.evidence_audit,public.evidence_idempotency TO evidence_runtime;
GRANT SELECT,INSERT ON public.evidence_head,public.evidence_outbox TO evidence_runtime;
GRANT UPDATE(revision) ON public.evidence_head TO evidence_runtime;
GRANT UPDATE(state,available_at,lease_until,lease_owner,generation,attempts,last_error) ON public.evidence_outbox TO evidence_runtime;
GRANT UPDATE(audit_sequence,audit_hash) ON public.evidence_project TO evidence_runtime;
INSERT INTO public.evidence_schema_version(version) VALUES (1);
COMMIT;
