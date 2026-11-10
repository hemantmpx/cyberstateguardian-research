#!/usr/bin/env bash
set -euo pipefail

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Replace placeholder secrets before lab use."
fi

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,probe]"

ruff check .
pytest
docker compose config >/dev/null

echo "Bootstrap complete. Start the stack with: docker compose up -d --build"
