#!/bin/bash
PYTHONPATH=./src pytest -v --cov=src --cov-report=term-missing tests/