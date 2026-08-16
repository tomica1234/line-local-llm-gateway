#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import os
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import httpx

LINE_KEYS = (
    "PERSONAL_AGENT_LINE_CHANNEL_SECRET",
    "PERSONAL_AGENT_LINE_CHANNEL_ACCESS_TOKEN",
    "PERSONAL_AGENT_LINE_PRIMARY_USER_ID",
)


def read_env(path: Path) -> tuple[list[str], dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return lines, values


def prompt_values(existing: dict[str, str]) -> dict[str, str]:
    channel_secret = getpass.getpass(
        "Channel secret（入力は表示されません）: "
    ) or existing.get(LINE_KEYS[0], "")
    access_token = getpass.getpass(
        "Channel access token（入力は表示されません）: "
    ) or existing.get(LINE_KEYS[1], "")
    primary_user_id = input(
        "Basic settings の Your user ID（U + 32桁）: "
    ).strip() or existing.get(LINE_KEYS[2], "")
    if len(channel_secret) < 16:
        raise ValueError("Channel secretが短すぎます")
    if len(access_token) < 32:
        raise ValueError("Channel access tokenが短すぎます")
    if not re.fullmatch(r"U[0-9a-fA-F]{32}", primary_user_id):
        raise ValueError("Your user IDは U + 32桁の16進数で入力してください")
    for value in (channel_secret, access_token, primary_user_id):
        if "\n" in value or "\r" in value:
            raise ValueError("設定値に改行は使用できません")
    return dict(zip(LINE_KEYS, (channel_secret, access_token, primary_user_id), strict=True))


def update_env(path: Path, lines: list[str], values: dict[str, str]) -> None:
    replaced: set[str] = set()
    updated: list[str] = []
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in values:
            updated.append(f"{key}={values[key]}")
            replaced.add(key)
        else:
            updated.append(line)
    for key in LINE_KEYS:
        if key not in replaced:
            updated.append(f"{key}={values[key]}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".line-env-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(updated) + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def activate(values: dict[str, str], webhook_url: str) -> None:
    subprocess.run(
        ["systemctl", "--user", "restart", "personal-agent.service"], check=True
    )
    for _ in range(20):
        try:
            response = httpx.get("http://127.0.0.1:8789/api/health", timeout=2)
            if response.status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    else:
        raise RuntimeError("Personal Agentが再起動後に応答しません")

    token = values[LINE_KEYS[1]]
    user_id = values[LINE_KEYS[2]]
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=20, headers=headers) as client:
        client.get("https://api.line.me/v2/bot/info").raise_for_status()
        client.get(f"https://api.line.me/v2/bot/profile/{user_id}").raise_for_status()
        client.put(
            "https://api.line.me/v2/bot/channel/webhook/endpoint",
            headers={"Content-Type": "application/json"},
            json={"endpoint": webhook_url},
        ).raise_for_status()
        test = client.post("https://api.line.me/v2/bot/channel/webhook/test")
        test.raise_for_status()
        result = test.json()
        if result.get("success") is not True:
            raise RuntimeError(f"LINE webhook test failed: {result.get('reason') or 'unknown'}")
        client.post(
            "https://api.line.me/v2/bot/message/push",
            headers={
                "Content-Type": "application/json",
                "X-Line-Retry-Key": str(uuid.uuid4()),
            },
            json={
                "to": user_id,
                "messages": [
                    {"type": "text", "text": "Personal AgentのLINE連携が完了しました。"}
                ],
            },
        ).raise_for_status()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Configure Personal Agent's single-user LINE Messaging API connector."
    )
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--activate", action="store_true")
    parser.add_argument(
        "--webhook-url",
        default=os.getenv("PERSONAL_AGENT_LINE_WEBHOOK_URL", ""),
    )
    arguments = parser.parse_args()
    if arguments.activate and not arguments.webhook_url:
        parser.error("--activate requires --webhook-url or PERSONAL_AGENT_LINE_WEBHOOK_URL")
    lines, existing = read_env(arguments.env_file)
    values = prompt_values(existing)
    update_env(arguments.env_file, lines, values)
    print("LINE認証情報を.envへ保存しました（値は表示していません）。")
    if arguments.activate:
        activate(values, arguments.webhook_url)
        print("Webhook検証と本人宛てテスト通知が成功しました。")
    else:
        print("公開Webhook経路を用意した後、同じコマンドへ --activate を付けてください。")


if __name__ == "__main__":
    main()
