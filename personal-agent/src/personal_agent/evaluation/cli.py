from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os

import httpx


async def _run(args: argparse.Namespace) -> None:
    token = args.admin_token or os.getenv("PERSONAL_AGENT_ADMIN_TOKEN")
    if not token:
        token = getpass.getpass("Admin token: ")
    payload = {"case_ids": args.case, "trials": args.trials}
    async with httpx.AsyncClient(timeout=args.timeout) as client:
        response = await client.post(
            f"{args.core_url.rstrip('/')}/api/benchmark/run",
            headers={"X-Admin-Token": token},
            json=payload,
        )
        response.raise_for_status()
    print(json.dumps(response.json(), ensure_ascii=False, indent=2))


def run() -> None:
    parser = argparse.ArgumentParser(
        description="Run the local Personal Agent benchmark in dry-run mode."
    )
    parser.add_argument("--core-url", default="http://127.0.0.1:8787")
    parser.add_argument("--admin-token", default="")
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--trials", type=int, choices=(1, 2, 3), default=3)
    parser.add_argument("--timeout", type=float, default=1800)
    asyncio.run(_run(parser.parse_args()))
