import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const offenders = [];
function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) { walk(full); continue; }
    if (!full.endsWith('.ts') || full.endsWith('.test.ts')) continue;
    const body = readFileSync(full, 'utf8');
    if (/\bconsole\s*\./.test(body)) offenders.push(full);
  }
}
walk('src');
if (offenders.length > 0) {
  process.stderr.write(`console.* found in shipped source:\n${offenders.join('\n')}\n`);
  process.exit(1);
}
