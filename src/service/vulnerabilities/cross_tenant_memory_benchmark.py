"""Command-line runner for the Cross-Tenant AI Memory Leakage benchmark.

Runs one scenario against several Ollama models and prints contamination and
disclosure rates per model as JSON:

    python -m src.service.vulnerabilities.cross_tenant_memory_benchmark \\
        --level 1 --models phi3:mini,llama3.1:8b --trials 10
"""

import argparse
import asyncio
import json

from ...ollama_client import OLLAMA_MODEL
from .cross_tenant_memory_lab import (
    DEFAULT_ATTACK_QUESTION,
    DEFAULT_TENANT_ID,
    LEVELS,
    TENANTS,
    run_benchmark,
)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark the Cross-Tenant AI Memory Leakage lab across models.")
    parser.add_argument("--level", type=int, default=1, choices=sorted(LEVELS))
    parser.add_argument("--models", default=OLLAMA_MODEL,
                        help="Comma-separated Ollama model names (default: OLLAMA_MODEL)")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--tenant", default=DEFAULT_TENANT_ID, choices=sorted(TENANTS))
    parser.add_argument("--question", default=DEFAULT_ATTACK_QUESTION)
    args = parser.parse_args(argv)
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    report = asyncio.run(run_benchmark(args.level, models, trials=args.trials,
                                       tenant_id=args.tenant, user_input=args.question))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
