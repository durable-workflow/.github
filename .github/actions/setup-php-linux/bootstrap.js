'use strict';

const path = require('node:path');

// execve replaces this trusted action process. A credential-bearing Node
// wrapper must not remain above the transitive installer process tree.
// https://nodejs.org/docs/latest-v24.x/api/process.html#processexecvefile-args-env
if (process.platform !== 'linux' || typeof process.execve !== 'function') {
  throw new Error('Bound PHP setup requires Linux and the runner Node execve API');
}
const program = path.resolve(__dirname, '../../../scripts/setup_php_linux.py');
process.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', '-S', '-B', program, 'reexec'], {
  ...process.env,
  DW_SETUP_NODE_BINARY: process.execPath,
  DW_SETUP_NODE_VERSION: process.version,
});
