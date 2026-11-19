"""Bound Linux PHP setup: the action's only Python import root.

The setup action runs `scripts/php_setup/setup_php_linux.py` with
`python3 -I -S -B -X pycache_prefix=<fresh private directory>`, registers this
directory as the `php_setup` package and adds no `sys.path` entry. Only the
modules here load. The reviewed setup-code digest covers every entry under this
directory exactly; any added file, directory, extension module or link changes
the digest. Keep nothing else here.
"""
