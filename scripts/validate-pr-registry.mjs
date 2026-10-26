import {readFile} from 'node:fs/promises';
import {parsePrRegistry} from '../registry/pr-contract.mjs';
const body = await readFile(new URL('../registry/prs.json', import.meta.url), 'utf8');
const {document} = parsePrRegistry(body, process.env.GITHUB_REPOSITORY || JSON.parse(body).repository);
for (const unit of document.units) for (const number of unit.prs) {
  if (!document.pullRequests.some(pr => pr.number === number)) throw new Error('Missing observed PR');
}
console.log(`Valid PR registry: ${document.repository}, ${document.units.length} approved units; live acceptance is separate.`);
