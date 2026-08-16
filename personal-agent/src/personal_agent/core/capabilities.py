from __future__ import annotations

import re
from dataclasses import dataclass

from ..types import RiskLevel


@dataclass(frozen=True, slots=True)
class CapabilityStep:
    """A capability grant fixed from the trusted user request before tool output exists."""

    step_id: str
    purpose: str
    allowed_tools: frozenset[str]
    permissions: frozenset[str]
    risk: RiskLevel

    def as_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "purpose": self.purpose,
            "allowed_tools": sorted(self.allowed_tools),
            "permissions": sorted(self.permissions),
            "risk": self.risk.value,
        }


def build_capability_plan(goal: str) -> tuple[CapabilityStep, ...]:
    """Build an immutable, least-capability plan from the original user request.

    Tool results are deliberately not accepted by this function. In particular, browser,
    message, and file content cannot add a later capability grant.
    """

    steps: list[CapabilityStep] = []

    def add(
        purpose: str,
        tools: set[str],
        permissions: set[str],
        risk: RiskLevel,
    ) -> None:
        steps.append(
            CapabilityStep(
                step_id=f"step-{len(steps) + 1}",
                purpose=purpose,
                allowed_tools=frozenset(tools),
                permissions=frozenset(permissions),
                risk=risk,
            )
        )

    natural_diary_signal = _matches(
        goal,
        r"(今日は|昨日は|最近).*(した|だった|嬉しかった|疲れた|楽しかった|つらかった|学んだ|気づいた)",
    ) and not _matches(goal, r"調べて|探して|検索して")
    diary_signal = _matches(
        goal, r"日記|diary|今日やったこと|昨日やったこと"
    ) or natural_diary_signal
    todo_completion_signal = not diary_signal and _matches(
        goal,
        r"完了|終わった|済んだ|できた|提出した|払った|連絡した|直した|作った|complete",
    )
    todo_create_signal = not diary_signal and _matches(
        goal,
        r"todo|to-do|やること|個人タスク|タスク|しないと|やらなきゃ|期限|締切|提出.*必要",
    )
    todo_signal = todo_create_signal or todo_completion_signal

    if todo_signal:
        if _matches(
            goal, r"一覧|見せて|表示|確認|残って|未完了|show|list"
        ) or todo_completion_signal:
            add(
                "Personal Todoを参照する",
                {"todo.list"},
                {"todo.read"},
                RiskLevel.R0,
            )
        if todo_create_signal and _matches(
            goal, r"追加|登録|作って|覚えて|しないと|やらなきゃ|期限|締切|提出.*必要|add|create"
        ):
            add(
                "Personal Todoを構造化して追加する",
                {"todo.create"},
                {"todo.write"},
                RiskLevel.R1,
            )
        if todo_completion_signal:
            add(
                "指定されたPersonal Todoを完了にする",
                {"todo.complete"},
                {"todo.write"},
                RiskLevel.R1,
            )
        if _matches(goal, r"更新|変更|期限.*変|優先.*変|update"):
            add(
                "指定されたPersonal Todoを更新する",
                {"todo.update"},
                {"todo.write"},
                RiskLevel.R1,
            )

    if diary_signal:
        if _matches(goal, r"見せて|読む|表示|今日の日記|昨日の日記|show|read"):
            add(
                "business dateに基づいて日記を読む",
                {"diary.read"},
                {"diary.read"},
                RiskLevel.R0,
            )
        if _matches(goal, r"検索|探して|振り返|search"):
            add(
                "日記を検索する",
                {"diary.search"},
                {"diary.read"},
                RiskLevel.R0,
            )
        if (
            natural_diary_signal
            or _matches(goal, r"書いて|記録|追加|登録|日記[:：\s]|create|add")
        ) and not _matches(goal, r"見せて|読む|表示|検索|探して|show|read|search"):
            add(
                "日記を構造化して記録する",
                {"diary.create"},
                {"diary.write"},
                RiskLevel.R1,
            )

    browser_signal = _matches(
        goal,
        r"https?://|ブラウザ|サイト|ウェブ|\bweb\b|検索して|調べて|フォーム|ページ|比較して",
    ) and not diary_signal
    if browser_signal:
        add(
            "外部Webを読み取り、候補や根拠を集める",
            {
                "browser.open",
                "browser.snapshot",
                "browser.tabs",
                "browser.new_tab",
                "browser.close_tab",
                "browser.switch_tab",
                "browser.back",
                "browser.forward",
                "browser.reload",
                "browser.hover",
                "browser.scroll",
                "browser.wait",
                "browser.screenshot",
                "browser.get_url",
                "browser.get_downloads",
            },
            {"browser.read"},
            RiskLevel.R0,
        )
        if _matches(
            goal,
            r"クリック|入力|選択|チェック|アップロード|ダウンロード|フォーム|ログイン|操作して|click|type|select|upload|download",
        ):
            add(
                "Webページ上の明示された入力・操作を行う",
                {
                    "browser.click",
                    "browser.type",
                    "browser.select",
                    "browser.check",
                    "browser.upload",
                    "browser.download",
                    "browser.press",
                    "browser.click_point",
                },
                {"browser.interact"},
                RiskLevel.R2,
            )
        if _matches(goal, r"ログイン|サインイン|認証"):
            add(
                "登録済みcredentialを使って認証状態を確立する",
                {"auth.ensure_authenticated"},
                {"auth.use", "secret.use"},
                RiskLevel.R2,
            )
        if _matches(
            goal,
            r"送信ボタン|フォーム.*送信|submit|申し込|予約確定|注文確定|購入確定|確定して",
        ):
            add(
                "明示されたWebフォームをpostcondition付きで送信する",
                {"browser.submit"},
                {"browser.submit"},
                RiskLevel.R2,
            )

    communication_signal = _matches(
        goal, r"line|slack|メール|gmail|sms|メッセージ|返信|下書き|送信"
    )
    if communication_signal and _matches(
        goal, r"検索|探して|読んで|見せて|確認|履歴|スレッド|同期|search|read|thread"
    ):
        add(
            "メッセージを読み取る",
            {
                "communication.search",
                "communication.read",
                "communication.thread",
                "communication.sync",
            },
            {"messages.read"},
            RiskLevel.R1,
        )
    draft_signal = communication_signal and _matches(
        goal, r"下書き|返信|送信|送って|メールして|draft|reply|send"
    )
    draft_already_exists = _matches(goal, r"下書き済み|下書きを送信|existing draft")
    if draft_signal and not draft_already_exists:
        add(
            "宛先を固定した未送信メッセージを作る",
            {"communication.draft"},
            {"messages.draft"},
            RiskLevel.R1,
        )
    if communication_signal and _matches(
        goal, r"送信して|送って|メールして|返信して|実際に送|\bsend\b"
    ):
        add(
            "承認境界を通して既存の下書きを送信する",
            {"communication.send"},
            {"messages.write"},
            RiskLevel.R2,
        )

    calendar_signal = _matches(goal, r"予定|カレンダー|calendar|空き時間|free.?busy|スケジュール")
    if calendar_signal:
        add(
            "カレンダーの予定または空き時間を読む",
            {"calendar.search", "calendar.get_availability"},
            {"calendar.read"},
            RiskLevel.R0,
        )
        if _matches(goal, r"追加|登録|入れて|作成|変更|更新|取消|キャンセル|create|update|cancel"):
            add(
                "明示されたカレンダー変更を行う",
                {"calendar.create", "calendar.update", "calendar.cancel"},
                {"calendar.write"},
                RiskLevel.R2,
            )

    file_signal = _matches(goal, r"ファイル|\bfile\b|文書|document|pdf|画像|領収書")
    if file_signal:
        add(
            "許可されたroot内のファイルを検索・参照する",
            {"files.search", "files.read"},
            {"files.read"},
            RiskLevel.R0,
        )
        write_tools: set[str] = set()
        if _matches(goal, r"コピー|copy"):
            write_tools.add("files.copy")
        if _matches(goal, r"移動|move"):
            write_tools.add("files.move")
        if _matches(goal, r"名前.*変更|rename"):
            write_tools.add("files.rename")
        if _matches(goal, r"削除|delete"):
            write_tools.add("files.delete")
        if write_tools:
            add(
                "許可されたroot内のファイル変更を行う",
                write_tools,
                {"files.write"},
                RiskLevel.R2 if "files.delete" in write_tools else RiskLevel.R1,
            )

    economic_signal = _matches(
        goal, r"買|購入|予約|契約|サブスク|返金|返品|支払|送金|振込"
    )
    if economic_signal:
        add(
            "購入・予約・送金の内容と最終条件を準備する",
            {
                "economic.create_intent",
                "economic.set_final_quote",
                "money.create_transfer_intent",
                "money.reconcile",
            },
            {"economic.prepare", "economic.read"},
            RiskLevel.R1,
        )
        if _matches(goal, r"購入して|予約して|支払って|送金して|振り込んで|実行して"):
            add(
                "承認済みの経済操作をsandboxで実行する",
                {"economic.execute_sandbox", "money.execute_transfer_sandbox"},
                {"economic.execute"},
                RiskLevel.R3,
            )

    if _matches(goal, r"home assistant|家電|照明|ライト|エアコン|温度|シーン"):
        add(
            "Home Assistantの対象状態を読む",
            {"home.get_state"},
            {"home.read"},
            RiskLevel.R0,
        )
        if _matches(goal, r"つけて|消して|設定|実行|turn|set|run"):
            add(
                "明示されたHome Assistant操作を行う",
                {"home.turn_on", "home.turn_off", "home.set_temperature", "home.run_scene"},
                {"home.write"},
                RiskLevel.R2,
            )

    if _matches(goal, r"pc|パソコン|computer|os状態"):
        add(
            "ローカルPCの限定された状態を読む",
            {"computer.get_status"},
            {"computer.read"},
            RiskLevel.R0,
        )
    if _matches(goal, r"PC通知|パソコン.*通知|computer.*notify"):
        add(
            "ローカルPC通知を作る",
            {"computer.notify"},
            {"computer.write"},
            RiskLevel.R1,
        )
    if _matches(goal, r"PC.*ロック|パソコン.*ロック|lock.*computer"):
        add(
            "Windows workstationをロックする",
            {"computer.lock"},
            {"computer.lock"},
            RiskLevel.R2,
        )

    if _matches(goal, r"好み|嗜好|preference|いつも選ぶ|傾向"):
        add(
            "根拠付きのPreference候補を作る",
            {"learning.propose_preference"},
            {"learning.propose"},
            RiskLevel.R1,
        )

    return tuple(steps)


def _matches(text: str, pattern: str) -> bool:
    return re.search(pattern, text, flags=re.IGNORECASE) is not None
