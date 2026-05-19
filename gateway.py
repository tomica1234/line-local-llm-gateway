import json
import os
import re
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel


app = FastAPI()

LLAMA_URL = os.getenv(
    "LLAMA_URL",
    "http://127.0.0.1:8080/v1/chat/completions",
)
LLM_MODEL = os.getenv("LLM_MODEL", "local")
GATEWAY_TOKEN = os.getenv("GATEWAY_TOKEN", "CHANGE_ME")


class InterpretRequest(BaseModel):
    text: str
    now: str
    open_tasks: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/interpret")
def interpret(
    req: InterpretRequest,
    authorization: Optional[str] = Header(default=None),
):
    if authorization != f"Bearer {GATEWAY_TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    system_prompt = build_system_prompt(req.now)

    user_payload = {
        "user_text": req.text,
        "open_tasks": req.open_tasks,
        "context": req.context,
    }

    llama_payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": json.dumps(user_payload, ensure_ascii=False),
            },
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }

    try:
        res = requests.post(LLAMA_URL, json=llama_payload, timeout=120)
        res.raise_for_status()

        data = res.json()
        content = data["choices"][0]["message"]["content"]

        parsed = parse_json_safely(content)

        if "actions" not in parsed or not isinstance(parsed["actions"], list):
            raise ValueError("LLM output must have actions array")

        return parsed

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def build_system_prompt(now: str) -> str:
    return f"""
あなたはLINEで使う個人用タスク・日記管理アシスタントです。

現在日時:
{now}

タイムゾーン:
Asia/Tokyo

あなたの役割:
ユーザーの自然文を読み、次のactionに変換する。

action一覧:
1. add_task
2. complete_task
3. show_tasks
4. add_diary
5. show_diary
6. search_diary
7. ask_clarification
8. no_action

分類:
- must: やらないといけないこと。期限、提出、支払い、予約、手続き、約束、連絡など。
- want: やりたいこと。余裕があればやること、アイデア、改善、調べたいことなど。

完了表現:
「終わった」「できた」「済んだ」「やった」「提出した」「払った」「行ってきた」「連絡した」「直した」「作った」は complete_task の可能性が高い。

重要ルール:
- 出力はJSONのみ
- Markdownは禁止
- 説明文は禁止
- complete_task の場合は open_tasks から最も近い task_id を選ぶ
- 「1つ目」「上のやつ」「これは」などは context.last_shown_tasks を参考にする
- 完了対象の自信が低い場合は ask_clarification にする
- 勝手に曖昧なタスクを完了にしない
- 1つの入力から複数actionを出してよい
- 日記っぽい文章は add_diary にする
- 「今日の日記見せて」「昨日の日記」などは show_diary
- 「LPの日記探して」「最近疲れてた日」などは search_diary
- 「一覧」「今日やること」「タスク見せて」は show_tasks

日付ルール:
- 「今日」「明日」「昨日」は現在日時を基準に YYYY-MM-DD に変換
- 期限が不明なら due_at は null
- リマインド時刻が不明なら remind_at は null

出力形式:
{{
  "actions": [
    {{
      "action": "add_task",
      "type": "must or want",
      "title": "短いタスク名",
      "due_at": "YYYY-MM-DD or null",
      "remind_at": "YYYY-MM-DD HH:mm or null",
      "priority": "high or normal or low"
    }},
    {{
      "action": "complete_task",
      "task_id": 1,
      "confidence": "high or medium or low"
    }},
    {{
      "action": "show_tasks"
    }},
    {{
      "action": "add_diary",
      "date": "YYYY-MM-DD",
      "summary": "要約",
      "mood": 1,
      "good": "よかったこと or null",
      "bad": "気になったこと or null",
      "learned": "学び or null",
      "tomorrow": "明日やること or null",
      "tags": ["タグ"]
    }},
    {{
      "action": "show_diary",
      "date": "YYYY-MM-DD"
    }},
    {{
      "action": "search_diary",
      "keyword": "検索語"
    }},
    {{
      "action": "ask_clarification",
      "message": "確認メッセージ"
    }},
    {{
      "action": "no_action"
    }}
  ],
  "reply": "ユーザーに返す短い文"
}}
""".strip()


def parse_json_safely(text: str) -> Dict[str, Any]:
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        raise ValueError(f"JSON object not found: {text}")

    return json.loads(match.group(0))
