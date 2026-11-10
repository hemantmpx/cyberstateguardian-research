from __future__ import annotations

import argparse
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build_env_text(example_text: str) -> str:
    postgres_password = secrets.token_urlsafe(24)
    lab_token = secrets.token_urlsafe(32)
    return (
        example_text.replace("change-me-for-local-lab", postgres_password)
        .replace("replace-with-lab-token", lab_token)
        .replace(
            "postgresql+psycopg://csg:change-me-for-local-lab@postgres:5432/cyberstateguardian",
            f"postgresql+psycopg://csg:{postgres_password}@postgres:5432/cyberstateguardian",
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a local CyberStateGuardian lab .env")
    parser.add_argument("--force", action="store_true", help="overwrite an existing .env")
    parser.add_argument("--output", type=Path, default=ROOT / ".env")
    parser.add_argument("--example", type=Path, default=ROOT / ".env.example")
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        print(f"{args.output} already exists; use --force to replace it")
        return

    env_text = build_env_text(args.example.read_text(encoding="utf-8"))
    args.output.write_text(env_text, encoding="utf-8")
    print(f"Created {args.output}")
    print("Secrets were generated locally and not printed. Keep .env out of version control.")


if __name__ == "__main__":
    main()
