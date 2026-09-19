// Re-runs the vector test WITHOUT the write flag. The test asserts each file
// byte-for-byte, so any wire change that did not come with a deliberate
// regeneration fails here rather than shipping.
import { spawnSync } from 'node:child_process';

const result = spawnSync(
  process.execPath,
  ['node_modules/vitest/vitest.mjs', 'run', 'src/wire/vectors.test.ts', 'src/wire/invite.test.ts', 'src/wire/channel-check.test.ts'],
  { stdio: 'inherit', env: { ...process.env, WRITE_VECTORS: '' } },
);
process.exit(result.status ?? 1);
