#!/bin/bash
python -m pip install -e .
PYTHONPATH=./src pytest -v --cov=src --cov-report=term-missing tests/