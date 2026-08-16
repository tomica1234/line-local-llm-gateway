from __future__ import annotations

import json
import logging
import queue
import subprocess
import tempfile
import time
import wave
from pathlib import Path
from typing import Any

import httpx

from .config import VoiceSettings
from .vad import UtteranceCollector

LOGGER = logging.getLogger("personal_agent.voice")


class VoiceGateway:
    def __init__(self, settings: VoiceSettings):
        settings.validate()
        self.settings = settings
        self.audio_queue: queue.Queue[bytes] = queue.Queue(maxsize=256)
        self.collector = UtteranceCollector(
            frame_ms=settings.frame_ms,
            rms_threshold=settings.speech_rms_threshold,
            end_silence_ms=settings.end_silence_ms,
            max_utterance_seconds=settings.max_utterance_seconds,
        )
        self._load_audio_dependencies()
        self.wake_model = self._wake_model_type(
            wakeword_models=[str(settings.wake_model_path)],
            vad_threshold=settings.wake_vad_threshold,
        )

    def _load_audio_dependencies(self) -> None:
        try:
            import numpy as np
            import sounddevice as sd
            from openwakeword.model import Model
        except ImportError as exc:
            raise RuntimeError(
                "Voice dependencies are missing. Install with: pip install -e '.[voice]'"
            ) from exc
        self.np = np
        self.sd = sd
        self._wake_model_type = Model

    def run_forever(self) -> None:
        waiting_for_wake = True
        listen_deadline = 0.0
        notification_poll_at = 0.0
        LOGGER.info("Voice Gateway ready; waiting for wake word")
        with self.sd.RawInputStream(
            samplerate=self.settings.sample_rate,
            blocksize=self.settings.frame_samples,
            device=self.settings.input_device,
            channels=1,
            dtype="int16",
            callback=self._audio_callback,
        ):
            while True:
                frame = self.audio_queue.get()
                now = time.monotonic()
                if now >= notification_poll_at:
                    notification_poll_at = now + 2.0
                    notification = self._claim_notification_best_effort()
                    if notification:
                        self._deliver_notification(notification)
                        self._drain_audio_queue()
                        continue
                if waiting_for_wake:
                    scores = self.wake_model.predict(self.np.frombuffer(frame, dtype=self.np.int16))
                    if (
                        not scores
                        or max(float(score) for score in scores.values())
                        < self.settings.wake_threshold
                    ):
                        continue
                    waiting_for_wake = False
                    listen_deadline = now + self.settings.no_speech_timeout_seconds
                    self.collector.reset()
                    LOGGER.info("Wake word detected")
                    self._speak_best_effort(self.settings.acknowledgement)
                    self._drain_audio_queue()
                    continue

                utterance = self.collector.feed(frame)
                if not self.collector.speech_started and now >= listen_deadline:
                    waiting_for_wake = True
                    self.collector.reset()
                    LOGGER.info("No speech; returning to wake-word mode")
                    continue
                if utterance is None:
                    continue

                try:
                    text = self._transcribe(utterance)
                    if not text:
                        LOGGER.info("STT returned no text")
                    else:
                        LOGGER.info("User: %s", text)
                        reply = self._call_core(text)
                        LOGGER.info("Agent: %s", reply)
                        self._speak_best_effort(reply)
                except Exception:
                    LOGGER.exception("Voice turn failed")
                    self._speak_best_effort("処理に失敗しました。Web画面を確認してください。")
                finally:
                    self._drain_audio_queue()
                    self.collector.reset()
                    waiting_for_wake = False
                    listen_deadline = time.monotonic() + self.settings.conversation_window_seconds

    def _audio_callback(self, indata: bytes, _frames: int, _time: Any, status: Any) -> None:
        if status:
            LOGGER.warning("Audio input status: %s", status)
        try:
            self.audio_queue.put_nowait(bytes(indata))
        except queue.Full:
            LOGGER.warning("Audio queue full; dropping frame")

    def _transcribe(self, pcm: bytes) -> str:
        with tempfile.TemporaryDirectory(prefix="personal-agent-stt-") as temp_dir:
            wav_path = Path(temp_dir) / "utterance.wav"
            with wave.open(str(wav_path), "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(self.settings.sample_rate)
                wav_file.writeframes(pcm)
            completed = subprocess.run(
                [
                    str(self.settings.whisper_cli),
                    "-m",
                    str(self.settings.whisper_model),
                    "-f",
                    str(wav_path),
                    "-l",
                    "ja",
                    "-nt",
                    "-np",
                ],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
            )
            return completed.stdout.strip()

    def _call_core(self, text: str) -> str:
        with httpx.Client(timeout=180) as client:
            response = client.post(
                f"{self.settings.core_url}/api/channels/voice/input",
                json={
                    "text": text,
                    "source": "voice",
                    "conversation_id": self.settings.conversation_id,
                },
            )
            response.raise_for_status()
            payload = response.json()
        return str(payload["text"])

    def _claim_notification_best_effort(self) -> dict[str, Any] | None:
        try:
            with httpx.Client(timeout=3) as client:
                response = client.post(
                    f"{self.settings.core_url}/api/notifications/claim",
                    json={"source": "voice", "conversation_id": self.settings.conversation_id},
                )
                response.raise_for_status()
                return response.json()
        except Exception:
            LOGGER.debug("Notification poll failed", exc_info=True)
            return None

    def _deliver_notification(self, notification: dict[str, Any]) -> None:
        notification_id = str(notification["notification_id"])
        try:
            self._speak(str(notification["text"]))
            endpoint = "ack"
        except Exception:
            LOGGER.exception("Notification delivery failed")
            endpoint = "release"
        try:
            with httpx.Client(timeout=3) as client:
                response = client.post(
                    f"{self.settings.core_url}/api/notifications/{notification_id}/{endpoint}"
                )
                response.raise_for_status()
        except Exception:
            LOGGER.exception("Could not %s notification %s", endpoint, notification_id)

    def _speak_best_effort(self, text: str) -> None:
        try:
            self._speak(text)
        except Exception:
            LOGGER.exception("TTS failed; response text: %s", json.dumps(text, ensure_ascii=False))

    def _speak(self, text: str) -> None:
        with tempfile.TemporaryDirectory(prefix="personal-agent-tts-") as temp_dir:
            wav_path = Path(temp_dir) / "reply.wav"
            command = [
                str(self.settings.piper_python),
                "-m",
                "piper",
                "-m",
                self.settings.piper_model,
                "-f",
                str(wav_path),
            ]
            if self.settings.piper_data_dir:
                command.extend(["--data-dir", str(self.settings.piper_data_dir)])
            command.extend(["--", text])
            subprocess.run(command, check=True, capture_output=True, timeout=120)
            with wave.open(str(wav_path), "rb") as wav_file:
                if wav_file.getsampwidth() != 2:
                    raise RuntimeError("Piper output must be 16-bit PCM WAV")
                channels = wav_file.getnchannels()
                sample_rate = wav_file.getframerate()
                audio = self.np.frombuffer(
                    wav_file.readframes(wav_file.getnframes()), dtype="int16"
                )
                if channels > 1:
                    audio = audio.reshape((-1, channels))
            self.sd.play(audio, sample_rate, blocking=True)

    def _drain_audio_queue(self) -> None:
        while True:
            try:
                self.audio_queue.get_nowait()
            except queue.Empty:
                return


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    VoiceGateway(VoiceSettings.from_env()).run_forever()


if __name__ == "__main__":
    run()
