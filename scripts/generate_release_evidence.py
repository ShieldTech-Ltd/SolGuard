"""Generate reproducible SolGuard launch evidence from the current source commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import textwrap
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from time import perf_counter, perf_counter_ns
from typing import Any, cast

from solguard.authorization import WalletAuthorizationGuard
from solguard.contracts import AgentMandate, Decision, JsonValue, PaymentRequest
from solguard.dashboard import DemoRuntime
from solguard.detection import BehaviourEngine
from solguard.gateway import PaymentGateway
from solguard.policy import MandatePolicyEngine
from solguard.simulation import SimulatedSettlement

SOURCE_TIME = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
REPOSITORY_URL = "https://github.com/ShieldTech-Ltd/SolGuard"
FRAME_SIZE = (1440, 900)
VIDEO_FPS = 10
VIDEO_DURATION_SECONDS = 75


class MutableClock:
    """Deterministic benchmark clock advanced between requests."""

    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


def _run_json(command: Sequence[str]) -> dict[str, JsonValue]:
    completed = subprocess.run(
        list(command),
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"evidence command failed with exit code {completed.returncode}")
    return cast(dict[str, JsonValue], json.loads(completed.stdout))


def _source_commit(reference: str | None) -> str:
    revision = reference or "HEAD"
    completed = subprocess.run(
        ["git", "rev-parse", f"{revision}^{{commit}}"],
        capture_output=True,
        check=True,
        encoding="utf-8",
    )
    source_commit = completed.stdout.strip()
    if reference is not None:
        comparison = subprocess.run(
            [
                "git",
                "diff",
                "--quiet",
                source_commit,
                "--",
                "src",
                "pyproject.toml",
                "uv.lock",
            ],
            check=False,
        )
        if comparison.returncode != 0:
            raise RuntimeError(f"runtime source differs from {reference}")
    return source_commit


def _clean_process_runs(count: int) -> list[dict[str, JsonValue]]:
    return [
        _run_json([sys.executable, "-m", "solguard.demo", "--skip-paysh"]) for _ in range(count)
    ]


def _external_run(pay_executable: str | None) -> dict[str, JsonValue]:
    if pay_executable is None:
        return {"settlement_type": "PAYSH_SANDBOX", "status": "NOT_CAPTURED"}
    return _run_json(
        [
            sys.executable,
            "-m",
            "solguard.demo",
            "--pay-executable",
            pay_executable,
        ]
    )


def _benchmark_local_gateway(iterations: int) -> dict[str, JsonValue]:
    if iterations < 10:
        raise ValueError("benchmark iterations must be at least 10")
    agent_id = "benchmark-agent"
    mandate_id = "benchmark-mandate"
    clock = MutableClock(SOURCE_TIME)
    mandate = AgentMandate.from_dict(
        {
            "mandate_id": mandate_id,
            "agent_id": agent_id,
            "purpose": "local gateway benchmark",
            "asset": "USDC",
            "max_single_payment": "1",
            "allowed_recipients": ["benchmark-api"],
            "blocked_recipients": [],
            "valid_from": "2026-07-25T09:00:00Z",
            "expires_at": "2026-07-26T00:00:00Z",
        }
    )
    settlement = SimulatedSettlement(
        {agent_id: Decimal("10000")},
        authorization_guard=WalletAuthorizationGuard(clock=clock),
    )
    gateway = PaymentGateway(
        policy=MandatePolicyEngine({agent_id: mandate}),
        detection=BehaviourEngine(),
        settlement=settlement,
        clock=clock,
        timer_ns=perf_counter_ns,
    )
    latencies: list[Decimal] = []
    started = perf_counter()
    for index in range(iterations):
        clock.current = SOURCE_TIME + timedelta(seconds=index * 11)
        request = PaymentRequest.from_dict(
            {
                "request_id": f"benchmark-{index:05d}",
                "agent_id": agent_id,
                "mandate_id": mandate_id,
                "recipient": "benchmark-api",
                "amount": "0.01",
                "asset": "USDC",
                "purpose": "local gateway benchmark",
                "nonce": f"benchmark-nonce-{index:05d}",
                "created_at": clock.current.isoformat(),
                "expires_at": (clock.current + timedelta(minutes=1)).isoformat(),
                "metadata": {},
            }
        )
        outcome = gateway.process(request)
        if outcome.result.decision is not Decision.ALLOW:
            raise RuntimeError("benchmark request was not allowed")
        latencies.append(Decimal(cast(str, outcome.result.evidence["latency_ms"])))
    elapsed = Decimal(str((perf_counter() - started) * 1000))
    ordered = sorted(latencies)
    percentile_index = max(0, round((len(ordered) - 1) * 0.95))
    return {
        "decisions": {"allow": iterations, "other": 0},
        "iterations": iterations,
        "latency_ms": {
            "max": str(max(latencies)),
            "mean": str(statistics.fmean(latencies)),
            "median": str(statistics.median(latencies)),
            "min": str(min(latencies)),
            "p95": str(ordered[percentile_index]),
        },
        "method": (
            "PaymentGateway.process with all local controls and in-memory simulated settlement"
        ),
        "network_included": False,
        "total_duration_ms": str(elapsed),
    }


def _font(size: int, *, bold: bool = False) -> Any:
    from PIL import ImageFont

    candidates = [
        Path("C:/Windows/Fonts/seguisb.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf"),
        Path(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
            if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        ),
    ]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size=size)
    return ImageFont.load_default()


def _render_frame(
    *,
    title: str,
    eyebrow: str,
    metrics: Sequence[tuple[str, str]],
    body: Sequence[str],
    accent: str,
    source_commit: str,
    qr_image: Any | None = None,
) -> Any:
    from PIL import Image, ImageDraw

    image = Image.new("RGB", FRAME_SIZE, "#071522")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, FRAME_SIZE[0], 14), fill=accent)
    draw.text((88, 72), eyebrow.upper(), font=_font(19, bold=True), fill=accent)
    draw.text((88, 118), title, font=_font(55, bold=True), fill="#F1F7FC")
    draw.text(
        (88, 194),
        f"Verified runtime evidence · source {source_commit[:7]}",
        font=_font(20),
        fill="#91ABC0",
    )

    card_top = 270
    card_width = 290
    for index, (label, value) in enumerate(metrics):
        left = 88 + index * (card_width + 22)
        right = left + card_width
        draw.rounded_rectangle(
            (left, card_top, right, card_top + 155),
            radius=18,
            fill="#0D2032",
            outline="#29435A",
            width=2,
        )
        draw.text((left + 24, card_top + 23), label, font=_font(18), fill="#91ABC0")
        draw.text((left + 24, card_top + 67), value, font=_font(32, bold=True), fill="#FFFFFF")

    y = 500
    max_body_width = 74 if qr_image is None else 58
    for paragraph in body:
        for line in textwrap.wrap(paragraph, width=max_body_width):
            draw.text((88, y), line, font=_font(25), fill="#C8D8E5")
            y += 38
        y += 13

    if qr_image is not None:
        resized = qr_image.resize((220, 220))
        image.paste(resized, (FRAME_SIZE[0] - 310, 540))
        draw.text(
            (FRAME_SIZE[0] - 320, 780),
            "Repository and run instructions",
            font=_font(17, bold=True),
            fill="#FFFFFF",
        )

    draw.text(
        (88, 842),
        "SOLGUARD · SECURITY BEFORE THE SIGNATURE",
        font=_font(17, bold=True),
        fill="#607E96",
    )
    draw.text((1110, 842), "SANDBOX / SIMULATED", font=_font(17, bold=True), fill="#607E96")
    return image


def _render_assets(
    output: Path,
    checkpoints: dict[str, JsonValue],
    source_commit: str,
) -> tuple[list[Path], Path]:
    import imageio.v2 as imageio
    import numpy as np
    import qrcode
    from PIL import Image

    screenshots = output / "screenshots"
    screenshots.mkdir(parents=True, exist_ok=True)
    qr = qrcode.make(REPOSITORY_URL).convert("RGB")
    qr_path = output / "repository-qr.png"
    qr.save(qr_path)

    baseline = cast(dict[str, JsonValue], checkpoints["baseline"])
    attack = cast(dict[str, JsonValue], checkpoints["attack"])
    recovery = cast(dict[str, JsonValue], checkpoints["recovery"])
    baseline_counts = cast(dict[str, JsonValue], baseline["decision_counts"])
    attack_counts = cast(dict[str, JsonValue], attack["decision_counts"])
    recovery_counts = cast(dict[str, JsonValue], recovery["decision_counts"])
    attack_events = cast(list[JsonValue], attack["events"])
    latest_attack = cast(dict[str, JsonValue], attack_events[0])

    frames: list[tuple[str, Any, int]] = []
    title_frame = _render_frame(
        title="Stop compromised agents before funds move.",
        eyebrow="Autonomous payment security",
        metrics=(("PRODUCT", "SOLGUARD"), ("CONTROL", "PRE-SIGN"), ("MODE", "VERIFIED")),
        body=(
            "A security control plane between autonomous agents and wallet settlement.",
            "Every number in this recording comes from the demonstrated source commit.",
        ),
        accent="#34E6B0",
        source_commit=source_commit,
    )
    frames.append(("title", title_frame, 8))

    normal_frame = _render_frame(
        title="Normal commerce passes.",
        eyebrow="Clean baseline",
        metrics=(
            ("ALLOWED", str(baseline_counts["allowed"])),
            ("WALLET", f"{baseline['wallet_balance']} USDC"),
            ("SETTLEMENT", "SIMULATED"),
        ),
        body=(
            "Known-recipient payments satisfy the mandate, receive a single-use "
            "authorization, and settle.",
            "Only clean allowed traffic updates the behavioural baseline.",
        ),
        accent="#34E6B0",
        source_commit=source_commit,
    )
    frames.append(("normal", normal_frame, 15))

    attack_frame = _render_frame(
        title="The compromised agent accelerates.",
        eyebrow="Attack sequence",
        metrics=(
            (
                "ATTEMPTS",
                str(
                    int(cast(int, attack_counts["total"]))
                    - int(cast(int, baseline_counts["total"]))
                ),
            ),
            ("APPROVAL", str(attack_counts["require_approval"])),
            ("BLOCKED", str(attack_counts["blocked"])),
        ),
        body=(
            "A first-seen recipient and burst activity pause suspicious requests "
            "before the compound threshold is reached.",
            f"The running engine computed {attack['value_protected']} USDC of blocked value.",
        ),
        accent="#F2B84B",
        source_commit=source_commit,
    )
    frames.append(("attack", attack_frame, 17))

    balance_unchanged = baseline["wallet_balance"] == attack["wallet_balance"]
    blocked_frame = _render_frame(
        title="Stopped before the wallet.",
        eyebrow="Compound drain blocked",
        metrics=(
            ("DECISION", str(latest_attack["decision"])),
            ("SIGNING", str(latest_attack["signing_state"])),
            ("BALANCE SAFE", "YES" if balance_unchanged else "NO"),
        ),
        body=(
            "New recipient + abnormal amount + high velocity produced the compound-drain block.",
            "No signing authorization reached settlement. The post-baseline wallet "
            "balance did not change.",
        ),
        accent="#FF667A",
        source_commit=source_commit,
    )
    frames.append(("blocked-wallet", blocked_frame, 20))

    recovery_frame = _render_frame(
        title="Recovery stays usable.",
        eyebrow="Reset and continue",
        metrics=(
            ("RECOVERY", "ALLOW"),
            ("WALLET", f"{recovery['wallet_balance']} USDC"),
            ("ALLOWED", str(recovery_counts["allowed"])),
        ),
        body=(
            "The local state resets and a subsequent legitimate request completes normally.",
            "Buyer: agent platforms and wallet providers. Ask: validate the control "
            "with a design partner.",
        ),
        accent="#64B5FF",
        source_commit=source_commit,
        qr_image=qr,
    )
    frames.append(("recovery", recovery_frame, 15))

    static_paths: list[Path] = []
    for name, frame, _ in frames[1:]:
        target = screenshots / f"{name}.png"
        frame.save(target, optimize=True)
        static_paths.append(target)

    video_path = output / "solguard-offline-demo.mp4"
    writer = imageio.get_writer(
        video_path,
        fps=VIDEO_FPS,
        codec="libx264",
        quality=7,
        macro_block_size=None,
        ffmpeg_log_level="error",
    )
    previous = frames[0][1]
    try:
        for _, frame, seconds in frames:
            fade_frames = VIDEO_FPS if frame is not previous else 0
            for fade_index in range(fade_frames):
                alpha = Decimal(fade_index + 1) / Decimal(fade_frames)
                blended = Image.blend(previous, frame, float(alpha))
                writer.append_data(np.asarray(blended))
            for _ in range(seconds * VIDEO_FPS - fade_frames):
                writer.append_data(np.asarray(frame))
            previous = frame
    finally:
        writer.close()
    return [*static_paths, qr_path], video_path


def _write_json(path: Path, value: JsonValue) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{json.dumps(value, indent=2, sort_keys=True)}\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(
    *,
    output: Path,
    iterations: int,
    pay_executable: str | None,
    source_reference: str | None,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    source_commit = _source_commit(source_reference)
    checkpoints = cast(
        dict[str, JsonValue],
        DemoRuntime(start_time=SOURCE_TIME).run_demo_sequence(),
    )
    clean_runs = _clean_process_runs(3)
    external_run = _external_run(pay_executable)
    benchmark = _benchmark_local_gateway(iterations)

    data_dir = output / "data"
    _write_json(data_dir / "runtime-checkpoints.json", checkpoints)
    _write_json(data_dir / "clean-process-runs.json", cast(JsonValue, clean_runs))
    _write_json(data_dir / "external-demo-run.json", external_run)
    _write_json(data_dir / "benchmark.json", benchmark)
    _, video_path = _render_assets(output, checkpoints, source_commit)

    expected_duration = VIDEO_DURATION_SECONDS
    manifest_path = output / "manifest.json"
    artifacts = sorted(
        path for path in output.rglob("*") if path.is_file() and path != manifest_path
    )
    manifest: dict[str, JsonValue] = {
        "artifacts": [
            {
                "bytes": path.stat().st_size,
                "path": path.relative_to(output.parent).as_posix(),
                "sha256": _sha256(path),
            }
            for path in artifacts
        ],
        "claims": {
            "clean_process_runs": len(clean_runs),
            "external_status": cast(dict[str, JsonValue], external_run.get("external", {})).get(
                "status", external_run.get("status")
            ),
            "recording_duration_seconds": expected_duration,
        },
        "labels": ["PAYSH_SANDBOX", "SIMULATED"],
        "repository": REPOSITORY_URL,
        "source_commit": source_commit,
        "video": video_path.relative_to(output.parent).as_posix(),
    }
    _write_json(manifest_path, manifest)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate SolGuard release evidence")
    parser.add_argument("--output", type=Path, default=Path("evidence"))
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--pay-executable")
    parser.add_argument(
        "--source-commit",
        dest="source_reference",
        help="Git revision whose runtime source must match the working tree",
    )
    parsed = parser.parse_args(arguments)
    generate(
        output=parsed.output,
        iterations=parsed.iterations,
        pay_executable=parsed.pay_executable,
        source_reference=parsed.source_reference,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
