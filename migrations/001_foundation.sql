-- Run as a migration role. Runtime connects as evidence_runtime, never as an owner.
CREATE TABLE IF NOT EXISTS evidence_schema_version (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS evidence_project (
 tenant_id text NOT NULL, project_id text NOT NULL, audit_sequence bigint NOT NULL DEFAULT 0,
 audit_hash text NOT NULL DEFAULT '', PRIMARY KEY (tenant_id,project_id)
);
CREATE TABLE IF NOT EXISTS evidence_record (
 tenant_id text NOT NULL, project_id text NOT NULL, kind text NOT NULL, id text NOT NULL,
 revision integer NOT NULL CHECK (revision>0), value jsonb NOT NULL, created_at timestamptz NOT NULL,
 actor_id text NOT NULL, PRIMARY KEY (tenant_id,project_id,kind,id,revision),
 FOREIGN KEY(tenant_id,project_id) REFERENCES evidence_project(tenant_id,project_id)
);
CREATE TABLE IF NOT EXISTS evidence_head (
 tenant_id text NOT NULL, project_id text NOT NULL, kind text NOT NULL, id text NOT NULL, revision integer NOT NULL,
 PRIMARY KEY(tenant_id,project_id,kind,id),
 FOREIGN KEY(tenant_id,project_id,kind,id,revision) REFERENCES evidence_record(tenant_id,project_id,kind,id,revision)
);
CREATE TABLE IF NOT EXISTS evidence_audit (
 tenant_id text NOT NULL, project_id text NOT NULL, sequence bigint NOT NULL, id text NOT NULL,
 type text NOT NULL, actor_id text NOT NULL, at timestamptz NOT NULL, request_id text NOT NULL,
 payload jsonb NOT NULL, previous_hash text NOT NULL, hash text NOT NULL,
 PRIMARY KEY(tenant_id,project_id,sequence), UNIQUE(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id) REFERENCES evidence_project(tenant_id,project_id)
);
CREATE TABLE IF NOT EXISTS evidence_idempotency (
 tenant_id text NOT NULL, project_id text NOT NULL, actor_id text NOT NULL, key text NOT NULL,
 fingerprint text NOT NULL, result jsonb NOT NULL, PRIMARY KEY(tenant_id,project_id,actor_id,key)
);
CREATE TABLE IF NOT EXISTS evidence_outbox (
 tenant_id text NOT NULL, project_id text NOT NULL, id text NOT NULL, topic text NOT NULL, payload jsonb NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','leased','completed','dead')),
 available_at timestamptz NOT NULL, lease_until timestamptz, lease_owner text, generation integer NOT NULL DEFAULT 0,
 attempts integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 5 CHECK(max_attempts>0), last_error text,
 PRIMARY KEY(tenant_id,project_id,id), FOREIGN KEY(tenant_id,project_id) REFERENCES evidence_project(tenant_id,project_id)
);
CREATE INDEX IF NOT EXISTS evidence_outbox_ready ON evidence_outbox (tenant_id,project_id,available_at) WHERE state IN ('pending','leased');
CREATE INDEX IF NOT EXISTS evidence_record_search ON evidence_record USING gin(value jsonb_path_ops);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['evidence_project','evidence_record','evidence_head','evidence_audit','evidence_idempotency','evidence_outbox'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  IF NOT EXISTS (SELECT FROM pg_policies WHERE tablename=t AND policyname='scope_isolation') THEN
   EXECUTE format('CREATE POLICY scope_isolation ON %I USING (tenant_id = current_setting(''evidence.tenant_id'',true) AND project_id = current_setting(''evidence.project_id'',true)) WITH CHECK (tenant_id = current_setting(''evidence.tenant_id'',true) AND project_id = current_setting(''evidence.project_id'',true))',t);
  END IF;
 END LOOP;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='evidence_runtime') THEN CREATE ROLE evidence_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO evidence_runtime;
GRANT SELECT, INSERT ON evidence_project,evidence_record,evidence_audit,evidence_idempotency TO evidence_runtime;
GRANT SELECT,INSERT,UPDATE ON evidence_head,evidence_outbox TO evidence_runtime;
GRANT UPDATE(audit_sequence,audit_hash) ON evidence_project TO evidence_runtime;
INSERT INTO evidence_schema_version(version) VALUES (1) ON CONFLICT DO NOTHING;
