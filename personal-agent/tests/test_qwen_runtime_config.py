from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_qwen_launcher_fixes_requested_unsloth_quant_and_cpu_moe_layers() -> None:
    launcher = (PROJECT_ROOT / "scripts" / "start-qwen.sh").read_text()
    downloader = (PROJECT_ROOT / "scripts" / "download-qwen.sh").read_text()
    environment = (PROJECT_ROOT / ".env.example").read_text()

    assert "Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf" in launcher
    assert "--n-cpu-moe 40" in launcher
    assert "--n-gpu-layers all" in launcher
    assert "--parallel 1" in launcher
    assert "--host 127.0.0.1" in launcher
    assert "--no-webui" in launcher
    assert "707a55a8a4397ecde44de0c499d3e68c1ad1d240d1da65826b4949d1043f4450" in environment
    assert "unsloth/Qwen3.6-35B-A3B-GGUF/resolve/main" in downloader
    assert "Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf" in downloader
    assert "--continue-at -" in downloader
    assert "707a55a8a4397ecde44de0c499d3e68c1ad1d240d1da65826b4949d1043f4450" in downloader
