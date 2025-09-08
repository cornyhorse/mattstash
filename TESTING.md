# Working test commands for mattstash

# Simple command (what you originally wanted, but corrected):
pip install -e . && pytest --cache-clear && pytest -q --cov=src/mattstash --cov-report=term-missing --cov-report=html tests/

# Alternative with verbose output:
pip install -e . && pytest --cache-clear && pytest -v --cov=src/mattstash --cov-report=term-missing --cov-report=html tests/

# Just run tests without coverage (fastest):
pip install -e . && pytest --cache-clear && pytest -v tests/

# Using the script:
./scripts/run-tests.sh
