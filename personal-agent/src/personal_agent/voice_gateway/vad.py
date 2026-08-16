from __future__ import annotations

import math
import sys
from array import array
from collections import deque


def pcm16_rms(frame: bytes) -> float:
    samples = array("h")
    samples.frombytes(frame)
    if sys.byteorder != "little":
        samples.byteswap()
    if not samples:
        return 0.0
    mean_square = sum(sample * sample for sample in samples) / len(samples)
    return math.sqrt(mean_square) / 32768.0


class UtteranceCollector:
    """Energy VAD with pre-roll, end-of-speech, and hard duration limits."""

    def __init__(
        self,
        *,
        frame_ms: int,
        rms_threshold: float,
        end_silence_ms: int,
        max_utterance_seconds: float,
        pre_roll_ms: int = 240,
    ) -> None:
        self.rms_threshold = rms_threshold
        self.end_silence_frames = max(1, end_silence_ms // frame_ms)
        self.max_frames = max(1, int(max_utterance_seconds * 1000 // frame_ms))
        self.pre_roll: deque[bytes] = deque(maxlen=max(1, pre_roll_ms // frame_ms))
        self.frames: list[bytes] = []
        self.silence_frames = 0
        self.speech_started = False

    def reset(self) -> None:
        self.pre_roll.clear()
        self.frames.clear()
        self.silence_frames = 0
        self.speech_started = False

    def feed(self, frame: bytes) -> bytes | None:
        is_speech = pcm16_rms(frame) >= self.rms_threshold
        if not self.speech_started:
            if not is_speech:
                self.pre_roll.append(frame)
                return None
            self.speech_started = True
            self.frames.extend(self.pre_roll)
            self.frames.append(frame)
            self.pre_roll.clear()
            return None

        self.frames.append(frame)
        self.silence_frames = 0 if is_speech else self.silence_frames + 1
        if self.silence_frames >= self.end_silence_frames or len(self.frames) >= self.max_frames:
            completed = b"".join(self.frames)
            self.reset()
            return completed
        return None
