"""Container-flavored submission runner.

The Python-entrypoint flavor (`contract.load_submission_module`) imports
the submission as a module and calls `predict()` in-process. That's
convenient for development but doesn't enforce network isolation, and
it lets a submission peek at any in-process state (random seed, the
truth dict via reflection, etc.). It also asks the host machine to
have whatever Python deps the submission needs.

The container flavor isolates the submission completely:

    features written to <tmp>/in/eval_features.jsonl →
        docker run --network none --read-only --memory <N>g --cpus <N>
                   --tmpfs /tmp -v <tmp>/in:/in:ro -v <tmp>/out:/out
                   <submission_image>
    submission writes <tmp>/out/scores.jsonl →
    runner reads scores.jsonl and returns the parsed rows.

The runner is a drop-in replacement for `_run_submission` in
`benchmark.evaluate`: same `list[dict]` input, same `list[dict]`
output, same `validate_submission_output` hook runs unchanged.
Resource accounting (`wall_time_s`, `peak_mem_mb`, `exit_status`) is
captured side-channel and returned alongside the rows.

Network isolation is enforced by `--network none`. Read-only rootfs is
enforced by `--read-only` + `--tmpfs /tmp:rw,size=512m`. Capability
drop + no-new-privileges close the obvious escape hatches. Memory +
CPU caps default to 4G / 2 cpus per the contract.

A `run_subprocess(...)` sibling implements the same I/O contract for a
host subprocess. It's what the smoke uses when docker isn't reachable,
and it's also a viable isolation story for sites that already have
firejail / nsjail / chroot tooling and don't want to run a docker
daemon just for this benchmark.

Both paths thread the same two env vars to the submission:

    CERNIS_IN   directory containing eval_features.jsonl (read-only)
    CERNIS_OUT  directory the submission writes scores.jsonl into

Inside docker the bind mounts go to `/in` and `/out` and the template
Dockerfile bakes the env vars to those paths so the submission code
doesn't have to know it's in a container.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import subprocess
import tempfile
import threading
import time
from typing import Optional


@dataclasses.dataclass
class ContainerResult:
    """What a container/subprocess run produced.

    `rows` is the parsed scores.jsonl content (may be empty if the
    submission crashed). `wall_time_s` is monotonic-clock end-to-end.
    `peak_mem_mb` is best-effort — populated from `docker stats`
    polling for the container path, left None for the subprocess
    path. `exit_status` is the container/process exit code; 124
    indicates a timeout.
    """
    rows: list[dict]
    wall_time_s: float
    peak_mem_mb: Optional[float]
    exit_status: int


class DockerUnavailable(RuntimeError):
    """Raised when the docker daemon can't be reached. Callers may
    catch this to fall back to the Python-entrypoint flavor or to
    surface a clear "start colima / Docker Desktop" message."""


def docker_available() -> bool:
    """True iff `docker info` exits 0 within a short timeout.

    Cheap; safe to call from a smoke or a CLI startup banner.
    """
    try:
        cp = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=5,
        )
        return cp.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def write_features(features: list[dict], path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for row in features:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def read_scores(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


_MEM_UNITS = {
    "B":   1.0 / (1024 * 1024),
    "KiB": 1.0 / 1024,
    "MiB": 1.0,
    "GiB": 1024.0,
    "TiB": 1024.0 * 1024.0,
}


def _parse_mem_usage(line: str) -> Optional[float]:
    """`docker stats --format {{.MemUsage}}` → MB float, or None.

    Format examples: "12.34MiB / 4GiB", "950.2KiB / 4GiB".
    """
    if not line or "/" not in line:
        return None
    lhs = line.split("/", 1)[0].strip()
    for unit, factor in _MEM_UNITS.items():
        if lhs.endswith(unit):
            try:
                return float(lhs[:-len(unit)]) * factor
            except ValueError:
                return None
    return None


class _MemPoller(threading.Thread):
    """Background poller of `docker stats --no-stream` on a container,
    tracking peak memory in MB. Stops when `.stop_event` is set."""

    def __init__(self, cidfile: pathlib.Path, interval_s: float = 0.5) -> None:
        super().__init__(daemon=True)
        self.cidfile = cidfile
        self.interval_s = interval_s
        self.stop_event = threading.Event()
        self.peak_mb: Optional[float] = None

    def _read_cid(self) -> Optional[str]:
        if not self.cidfile.exists():
            return None
        cid = self.cidfile.read_text().strip()
        return cid or None

    def run(self) -> None:
        while not self.stop_event.is_set():
            cid = self._read_cid()
            if cid is None:
                if self.stop_event.wait(self.interval_s):
                    return
                continue
            try:
                cp = subprocess.run(
                    ["docker", "stats", "--no-stream",
                     "--format", "{{.MemUsage}}", cid],
                    capture_output=True, text=True, timeout=3,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                if self.stop_event.wait(self.interval_s):
                    return
                continue
            if cp.returncode == 0 and cp.stdout.strip():
                mb = _parse_mem_usage(cp.stdout.strip().splitlines()[0])
                if mb is not None and (self.peak_mb is None or mb > self.peak_mb):
                    self.peak_mb = mb
            if self.stop_event.wait(self.interval_s):
                return


def run_container(
    image: str,
    features: list[dict],
    *,
    train_features: Optional[list[dict]] = None,
    dev_features: Optional[list[dict]] = None,
    memory: str = "4g",
    cpus: str = "2",
    network: str = "none",
    timeout_s: float = 600.0,
) -> ContainerResult:
    """Run `image` against `features` in an isolated container.

    Optional `train_features` / `dev_features` are written to /in so the
    container's runner.py can call `submission.train(...)` before
    `predict(...)`. Matches the Python-entrypoint flavor's train→predict
    order.

    Raises `DockerUnavailable` if the docker daemon can't be reached.
    Otherwise always returns a `ContainerResult`; `exit_status != 0`
    means the container failed (caller inspects `rows` may be empty).
    """
    if not docker_available():
        raise DockerUnavailable(
            "docker daemon not reachable. Start colima / Docker Desktop, "
            "then retry."
        )

    with tempfile.TemporaryDirectory(prefix="cernis_runner_") as td:
        td_path = pathlib.Path(td)
        in_dir = td_path / "in"
        out_dir = td_path / "out"
        in_dir.mkdir()
        out_dir.mkdir()
        # bind mounts are uid-sensitive on Linux; world-writable on
        # the host keeps the container's writes unrestricted regardless
        # of which uid the image's ENTRYPOINT runs as.
        out_dir.chmod(0o777)
        write_features(features, in_dir / "eval_features.jsonl")
        if train_features is not None:
            write_features(train_features, in_dir / "train_features.jsonl")
        if dev_features is not None:
            write_features(dev_features, in_dir / "dev_features.jsonl")

        cidfile = td_path / "cid"
        cmd = [
            "docker", "run", "--rm", f"--network={network}",
            "--read-only", "--tmpfs", "/tmp:rw,size=512m",
            f"--memory={memory}", f"--cpus={cpus}",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--cidfile", str(cidfile),
            "-v", f"{in_dir}:/in:ro",
            "-v", f"{out_dir}:/out:rw",
            image,
        ]

        poller = _MemPoller(cidfile)
        poller.start()
        t0 = time.monotonic()
        try:
            cp = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_s,
            )
            exit_status = cp.returncode
        except subprocess.TimeoutExpired:
            exit_status = 124
        wall = time.monotonic() - t0
        poller.stop_event.set()
        poller.join(timeout=2)

        rows = read_scores(out_dir / "scores.jsonl")
        return ContainerResult(
            rows=rows,
            wall_time_s=wall,
            peak_mem_mb=poller.peak_mb,
            exit_status=exit_status,
        )


def run_subprocess(
    cmd: list[str],
    features: list[dict],
    *,
    train_features: Optional[list[dict]] = None,
    dev_features: Optional[list[dict]] = None,
    cwd: Optional[pathlib.Path] = None,
    env: Optional[dict] = None,
    timeout_s: float = 600.0,
) -> ContainerResult:
    """Same I/O contract as `run_container` but for a host subprocess.

    Threads `CERNIS_IN` and `CERNIS_OUT` env vars to the child process
    pointing at the temp dirs the runner manages. Used by the smoke when
    docker isn't available, and viable as a non-docker isolation story
    when paired with firejail / nsjail / chroot.

    Resource accounting is wall-time + exit-status only; `peak_mem_mb`
    is left None because measuring host-process peak RSS reliably on
    macOS requires `/usr/bin/time -l` parsing, which is fragile across
    macOS versions and not worth the complexity in this phase.
    """
    with tempfile.TemporaryDirectory(prefix="cernis_runner_") as td:
        td_path = pathlib.Path(td)
        in_dir = td_path / "in"
        out_dir = td_path / "out"
        in_dir.mkdir()
        out_dir.mkdir()
        write_features(features, in_dir / "eval_features.jsonl")
        if train_features is not None:
            write_features(train_features, in_dir / "train_features.jsonl")
        if dev_features is not None:
            write_features(dev_features, in_dir / "dev_features.jsonl")
        full_env = dict(env) if env else {}
        full_env.setdefault("CERNIS_IN", str(in_dir))
        full_env.setdefault("CERNIS_OUT", str(out_dir))
        full_env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")

        t0 = time.monotonic()
        try:
            cp = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_s,
                cwd=str(cwd) if cwd else None, env=full_env,
            )
            exit_status = cp.returncode
        except subprocess.TimeoutExpired:
            exit_status = 124
        wall = time.monotonic() - t0
        rows = read_scores(out_dir / "scores.jsonl")
        return ContainerResult(
            rows=rows, wall_time_s=wall,
            peak_mem_mb=None, exit_status=exit_status,
        )
