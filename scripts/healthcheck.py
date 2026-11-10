from __future__ import annotations

import argparse
import json
import sys

import httpx


def check(url: str) -> dict[str, object]:
    response = httpx.get(url, timeout=5)
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") != "ok":
        raise RuntimeError(f"unexpected health payload: {payload}")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Check CyberStateGuardian API health")
    parser.add_argument("--url", default="http://localhost:8000/health")
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.url), indent=2))
    except Exception as exc:
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
