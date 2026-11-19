"""Alias of the reviewed setup module in scripts/php_setup (the action import root)."""
import sys

from scripts.php_setup import setup_php_linux as _module

sys.modules[__name__] = _module
