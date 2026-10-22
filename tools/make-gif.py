#!/usr/bin/env python3
"""Render the output of demo/record.ts into assets/demo.gif.

No screen recorder, no ffmpeg, no manual steps: the animation is drawn from the
same text a human sees when running `node demo/record.ts`.

    python tools/make-gif.py            # writes assets/demo.gif
    python tools/make-gif.py --png      # also writes assets/demo.png (still frame)
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT_GIF = ROOT / "assets" / "demo.gif"
OUT_PNG = ROOT / "assets" / "demo.png"

FONT_SIZE = 17
LINE_H = 25
CHROME_H = 42
PAD = 30
TOP = CHROME_H + 18
BOTTOM = 26

BG = "#0B0E14"
BAR = "#161B22"
BORDER = "#21262D"
TEXT = "#C9D1D9"
BRIGHT = "#F0F6FC"
DIM = "#7D8590"
BLUE = "#58A6FF"
RED = "#F85149"
AMBER = "#D29922"
GREEN = "#3FB950"

BADGE_COLOR = {"DENY": RED, "ASK": AMBER, "ALLOW": GREEN, "REDACT": AMBER}


def pick_font(bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        "C:/Windows/Fonts/CascadiaMono.ttf",
        "C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/consola.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            return ImageFont.truetype(path, FONT_SIZE)
    raise SystemExit("no monospace font found")


def find_node() -> str:
    node = os.environ.get("GUARD_NODE") or shutil.which("node")
    if node:
        return node
    patterns = [
        os.path.expandvars(r"%USERPROFILE%\.workbuddy\binaries\node\versions\*\node.exe"),
        r"C:\Program Files\nodejs\node.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\nodejs\node.exe"),
    ]
    for pattern in patterns:
        for match in sorted(glob.glob(pattern), reverse=True):
            return match
    raise SystemExit("node not found; set GUARD_NODE to the executable")


def capture() -> list[str]:
    node = find_node()
    result = subprocess.run(
        [node, str(ROOT / "demo" / "record.ts")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(ROOT),
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr or "record.ts failed\n")
        raise SystemExit(1)
    return result.stdout.rstrip("\n").split("\n")


def segments(line: str, index: int) -> list[tuple[str, str | None, bool]]:
    stripped = line.strip()
    if stripped and set(stripped) == {"-"}:
        return [(line, DIM, False)]

    match = re.match(r"^(  )(DENY|ASK|ALLOW|REDACT)(\s+)(G\d{3})(\s+)(.*)$", line)
    if match:
        badge = match.group(2)
        return [
            (match.group(1) + badge, BADGE_COLOR[badge], True),
            (match.group(3) + match.group(4), BLUE, False),
            (match.group(5) + match.group(6), TEXT, False),
        ]

    if line.startswith("$ "):
        return [("$ ", DIM, False), (line[2:], BRIGHT, False)]

    if line.startswith("        ") and stripped:
        return [(line[:8], None, False), (line[8:], DIM, False)]

    if index == 0:
        return [(line, BRIGHT, True)]
    if index == 1:
        return [(line, DIM, False)]
    return [(line, TEXT, False)]


def chrome(draw: ImageDraw.ImageDraw, width: int, title_font: ImageFont.FreeTypeFont) -> None:
    draw.rectangle([0, 0, width, CHROME_H], fill=BAR)
    draw.line([0, CHROME_H, width, CHROME_H], fill=BORDER)
    for i, color in enumerate(["#FF5F56", "#FFBD2E", "#27C93F"]):
        x = 20 + i * 20
        draw.ellipse([x, CHROME_H / 2 - 5, x + 10, CHROME_H / 2 + 5], fill=color)
    draw.text((84, CHROME_H / 2), "opencode-guard  ·  demo", font=title_font, fill=DIM, anchor="lm")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--png", action="store_true", help="also write a still frame")
    args = parser.parse_args()

    lines = capture()
    font = pick_font()
    font_bold = pick_font(bold=True)
    title_font = ImageFont.truetype(font.path, 12)

    probe = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    cw = probe.textlength("M" * 20, font=font) / 20
    width = int(max(len(line) for line in lines) * cw + PAD * 2)
    height = TOP + len(lines) * LINE_H + BOTTOM

    frames: list[Image.Image] = []
    durations: list[int] = []

    for visible in range(len(lines) + 1):
        img = Image.new("RGB", (width, height), BG)
        draw = ImageDraw.Draw(img)
        chrome(draw, width, title_font)

        for index, line in enumerate(lines[:visible]):
            x = PAD
            y = TOP + index * LINE_H
            for text, color, bold in segments(line, index):
                if color is None:
                    x += len(text) * cw
                    continue
                draw.text((x, y), text, font=font_bold if bold else font, fill=color)
                x += len(text) * cw

        draw.rectangle([0, 0, width - 1, height - 1], outline=BORDER)
        frames.append(img.convert("P", palette=Image.ADAPTIVE, colors=48))
        durations.append(700 if visible == 0 else 65)

    durations[-1] = 2600

    OUT_GIF.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        OUT_GIF,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )

    if args.png:
        still = Image.open(OUT_GIF)
        still.seek(still.n_frames - 1)
        still.convert("RGB").save(OUT_PNG, optimize=True)

    size_kb = OUT_GIF.stat().st_size / 1024
    print(f"{OUT_GIF.relative_to(ROOT)}  {width}x{height}  {len(frames)} frames  {size_kb:.0f} KB")


if __name__ == "__main__":
    main()
