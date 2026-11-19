'use strict';

const fs = require('node:fs');
const path = require('node:path');

// execve replaces this trusted action process. A credential-bearing Node
// wrapper must not remain above the transitive installer process tree.
// https://nodejs.org/docs/latest-v24.x/api/process.html#processexecvefile-args-env
if (process.platform !== 'linux' || typeof process.execve !== 'function') {
  throw new Error('Bound PHP setup requires Linux and the runner Node execve API');
}
const program = path.resolve(__dirname, '../../../scripts/php_setup/setup_php_linux.py');
// Bytecode is read only from this fresh empty private tree, never from a
// __pycache__ in the action checkout (-B alone still reads planted .pyc files).
const runnerTemp = process.env.RUNNER_TEMP;
if (typeof runnerTemp !== 'string' || !path.isAbsolute(runnerTemp)) {
  throw new Error('Bound PHP setup requires the absolute runner temporary directory');
}
const pycache = fs.mkdtempSync(path.join(runnerTemp, 'dw-php-pycache-'));
process.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', '-S', '-B', '-X', `pycache_prefix=${pycache}`,
  program, 'reexec'], {
  ...process.env,
  DW_SETUP_NODE_BINARY: process.execPath,
  DW_SETUP_NODE_VERSION: process.version,
});
