"""Read shell definitions without executing the interactive entry point."""
from pathlib import Path

SOURCE = (Path(__file__).resolve().parents[1] / 'gre4.sh').read_text()
assert SOURCE.splitlines()[-1] == 'main "$@"'
FUNCTIONS = SOURCE.rsplit('\nmain "$@"', 1)[0]
