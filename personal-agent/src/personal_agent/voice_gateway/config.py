from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class VoiceSettings:
    core_url: str = "http://127.0.0.1:8787"
    conversation_id: str = "cyborg-local"
    input_device: str | int | None = None
    sample_rate: int = 16_000
    frame_ms: int = 80
    wake_model_path: Path = Path("models/hey_jarvis_v0.1.onnx")
    wake_threshold: float = 0.5
    wake_vad_threshold: float = 0.5
    speech_rms_threshold: float = 0.018
    end_silence_ms: int = 850
    no_speech_timeout_seconds: float = 4.0
    max_utterance_seconds: float = 20.0
    conversation_window_seconds: float = 15.0
    whisper_cli: Path = Path("whisper-cli.exe")
    whisper_model: Path = Path("models/ggml-large-v3-turbo.bin")
    piper_python: Path = Path(sys.executable)
    piper_model: str = "ja_JP-test-medium"
    piper_data_dir: Path | None = None
    acknowledgement: str = "はい。"

    @classmethod
    def from_env(cls) -> VoiceSettings:
        device = os.getenv("PA_VOICE_INPUT_DEVICE")
        parsed_device: str | int | None = device
        if device and device.isdigit():
            parsed_device = int(device)
        return cls(
            core_url=os.getenv("PA_VOICE_CORE_URL", "http://127.0.0.1:8787").rstrip("/"),
            conversation_id=os.getenv("PA_VOICE_CONVERSATION_ID", "cyborg-local"),
            input_device=parsed_device,
            wake_model_path=Path(os.getenv("PA_VOICE_WAKE_MODEL", "models/hey_jarvis_v0.1.onnx")),
            wake_threshold=float(os.getenv("PA_VOICE_WAKE_THRESHOLD", "0.5")),
            wake_vad_threshold=float(os.getenv("PA_VOICE_WAKE_VAD_THRESHOLD", "0.5")),
            speech_rms_threshold=float(os.getenv("PA_VOICE_RMS_THRESHOLD", "0.018")),
            end_silence_ms=int(os.getenv("PA_VOICE_END_SILENCE_MS", "850")),
            no_speech_timeout_seconds=float(os.getenv("PA_VOICE_NO_SPEECH_TIMEOUT_SECONDS", "4")),
            max_utterance_seconds=float(os.getenv("PA_VOICE_MAX_UTTERANCE_SECONDS", "20")),
            conversation_window_seconds=float(
                os.getenv("PA_VOICE_CONVERSATION_WINDOW_SECONDS", "15")
            ),
            whisper_cli=Path(os.getenv("PA_VOICE_WHISPER_CLI", "whisper-cli.exe")),
            whisper_model=Path(
                os.getenv("PA_VOICE_WHISPER_MODEL", "models/ggml-large-v3-turbo.bin")
            ),
            piper_python=Path(os.getenv("PA_VOICE_PIPER_PYTHON", sys.executable)),
            piper_model=os.getenv("PA_VOICE_PIPER_MODEL", "ja_JP-test-medium"),
            piper_data_dir=(
                Path(value) if (value := os.getenv("PA_VOICE_PIPER_DATA_DIR")) else None
            ),
            acknowledgement=os.getenv("PA_VOICE_ACKNOWLEDGEMENT", "はい。"),
        )

    @property
    def frame_samples(self) -> int:
        return self.sample_rate * self.frame_ms // 1000

    def validate(self) -> None:
        parsed = urlparse(self.core_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("PA_VOICE_CORE_URL must be an HTTP(S) URL")
        if parsed.hostname != "localhost":
            try:
                address = ipaddress.ip_address(parsed.hostname)
            except ValueError as exc:
                raise ValueError(
                    "Voice Core URL must use localhost or an explicit private IP"
                ) from exc
            if not (address.is_loopback or address.is_private):
                raise ValueError("Voice Core URL cannot use a public IP")
        for label, path in {
            "wake model": self.wake_model_path,
            "whisper CLI": self.whisper_cli,
            "whisper model": self.whisper_model,
            "Piper Python": self.piper_python,
        }.items():
            if not path.exists():
                raise FileNotFoundError(f"{label} not found: {path}")
