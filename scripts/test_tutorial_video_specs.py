from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
STEMS = (
    "wanyutong-line-bot-tutorial-20260914",
    "wanyutong-secretary-tutorial-20260914",
    "wanyutong-activation-flow-20260914",
)

REQUIRED_CAPTION_TERMS = {
    "wanyutong-line-bot-tutorial-20260914": (
        "支援語言",
        "持續多語最多可以同時設定八種",
        "自動關閉多語",
        "黃色營運事件",
        "不等同遭到駭客入侵",
    ),
    "wanyutong-secretary-tutorial-20260914": (
        "祕書與小老鼠秘書兩種寫法都可以",
        "最近三百筆",
        "自動回覆預設關閉",
        "黃色營運事件",
        "不等同遭到駭客入侵",
    ),
    "wanyutong-activation-flow-20260914": (
        "月費版九十九元",
        "半年版四百九十九元",
        "一年版七百九十九元",
        "尊爵版兩千五百元",
        "不要再次付款",
        "黃色營運事件",
    ),
}


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, capture_output=True, text=True)


def probe(path: Path) -> dict:
    result = run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_streams",
            "-show_format",
            "-of",
            "json",
            str(path),
        ]
    )
    return json.loads(result.stdout)


def loudness(path: Path) -> tuple[float, float]:
    result = run(
        [
            "ffmpeg",
            "-hide_banner",
            "-nostats",
            "-i",
            str(path),
            "-vn",
            "-af",
            "loudnorm=I=-16:TP=-1.5:LRA=8:print_format=json",
            "-f",
            "null",
            "-",
        ]
    )
    reports = re.findall(r"\{\s*\"input_i\"[\s\S]*?\}", result.stderr)
    if not reports:
        raise AssertionError(f"{path.name}: loudness report missing")
    report = json.loads(reports[-1])
    return float(report["input_i"]), float(report["input_tp"])


def one_stream(data: dict, kind: str) -> dict:
    streams = [stream for stream in data["streams"] if stream["codec_type"] == kind]
    if len(streams) != 1:
        raise AssertionError(f"expected one {kind} stream, got {len(streams)}")
    return streams[0]


def main() -> None:
    builder = (ROOT / "scripts" / "build_tutorial_videos.py").read_text(encoding="utf-8")
    assert "@語言設定 A B" not in builder, "tutorial visual must use a copyable command"
    assert "@語言設定 繁體中文 英文" in builder, "tutorial visual needs a valid bilingual example"

    for stem in STEMS:
        video_path = ASSETS / f"{stem}.mp4"
        poster_path = ASSETS / f"{stem}-poster.jpg"
        captions_path = ASSETS / f"{stem}.vtt"

        for path in (video_path, poster_path, captions_path):
            assert path.is_file() and path.stat().st_size > 0, f"missing: {path}"

        data = probe(video_path)
        video = one_stream(data, "video")
        audio = one_stream(data, "audio")
        duration = float(data["format"]["duration"])
        size = video_path.stat().st_size

        assert video["codec_name"] == "h264", f"{stem}: video codec"
        assert (video["width"], video["height"]) == (1920, 1080), f"{stem}: resolution"
        assert video["r_frame_rate"] == "30/1", f"{stem}: frame rate"
        assert video["pix_fmt"] == "yuv420p", f"{stem}: pixel format"
        assert video.get("color_range") == "tv", f"{stem}: color range"
        assert video.get("color_space") == "bt709", f"{stem}: color space"
        assert video.get("color_primaries") == "bt709", f"{stem}: color primaries"
        assert video.get("color_transfer") == "bt709", f"{stem}: color transfer"
        assert audio["codec_name"] == "aac", f"{stem}: audio codec"
        assert audio["sample_rate"] == "48000", f"{stem}: sample rate"
        assert 45 <= duration <= 150, f"{stem}: unexpected duration {duration:.2f}s"
        assert size <= 10 * 1024 * 1024, f"{stem}: exceeds 10 MiB"

        raw = video_path.read_bytes()
        moov, mdat = raw.find(b"moov"), raw.find(b"mdat")
        assert moov >= 0 and mdat >= 0 and moov < mdat, f"{stem}: faststart missing"
        assert b"C:\\Users\\" not in raw, f"{stem}: local path metadata leaked"

        captions = captions_path.read_text(encoding="utf-8")
        assert captions.startswith("WEBVTT\n"), f"{stem}: invalid WebVTT header"
        for required in REQUIRED_CAPTION_TERMS[stem]:
            assert required in captions, f"{stem}: missing caption fact {required}"
        for stale in ("@群組多語", "NT$899", "365 天"):
            assert stale not in captions, f"{stem}: stale caption {stale}"

        poster = one_stream(probe(poster_path), "video")
        assert (poster["width"], poster["height"]) == (1920, 1080), f"{stem}: poster size"

        integrated, true_peak = loudness(video_path)
        assert -17.0 <= integrated <= -15.0, f"{stem}: {integrated:.1f} LUFS"
        assert true_peak <= -1.0, f"{stem}: {true_peak:.1f} dBTP"
        print(
            f"PASS {stem}: {duration:.2f}s, {size / 1024 / 1024:.2f} MiB, "
            f"{integrated:.1f} LUFS, {true_peak:.1f} dBTP"
        )


if __name__ == "__main__":
    main()
