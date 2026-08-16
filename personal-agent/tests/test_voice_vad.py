from __future__ import annotations

from array import array

from personal_agent.voice_gateway.vad import UtteranceCollector, pcm16_rms


def pcm(value: int, samples: int = 1280) -> bytes:
    return array("h", [value] * samples).tobytes()


def test_pcm_rms() -> None:
    assert pcm16_rms(pcm(0)) == 0
    assert 0.49 < pcm16_rms(pcm(16384)) < 0.51


def test_utterance_collector_uses_vad_and_end_silence() -> None:
    collector = UtteranceCollector(
        frame_ms=80,
        rms_threshold=0.02,
        end_silence_ms=160,
        max_utterance_seconds=2,
        pre_roll_ms=80,
    )
    assert collector.feed(pcm(0)) is None
    assert collector.feed(pcm(4000)) is None
    assert collector.speech_started
    assert collector.feed(pcm(4000)) is None
    assert collector.feed(pcm(0)) is None
    complete = collector.feed(pcm(0))
    assert complete is not None
    assert len(complete) == 5 * 1280 * 2
    assert not collector.speech_started
