"""
TRACE-X shared utilities: hashing, safe-path handling, logging setup.
"""
import hashlib
import logging
import os
import re
import time
import unicodedata
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s: %(message)s",
)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str) -> str:
    """Strip path components and unsafe characters from a filename.
    Never trust filenames pulled from email content or attachments."""
    if not name:
        return "unnamed"
    name = unicodedata.normalize("NFKC", name)
    name = Path(name).name  # strips any directory / traversal components
    name = _SAFE_NAME_RE.sub("_", name)
    name = name.strip("._")
    return name[:200] if name else "unnamed"


def safe_join(base_dir: str, filename: str) -> str:
    """Join a filename to base_dir, guaranteeing the result stays inside base_dir."""
    base = Path(base_dir).resolve()
    candidate = (base / sanitize_filename(filename)).resolve()
    if base not in candidate.parents and candidate != base:
        raise ValueError(f"Unsafe path detected: {filename}")
    return str(candidate)


def severity_rank(sev: str) -> int:
    from core.config import SEVERITY_ORDER
    return SEVERITY_ORDER.get((sev or "INFO").upper(), 0)


def new_investigation_id(counter: int) -> str:
    return f"TX-{counter:06d}"


def _acquire_file_lock(lock_path: str, timeout: float = 5.0) -> None:
    """Cross-platform (Windows/Linux) exclusive-create lock, no external deps.
    Breaks a stale lock after `timeout` seconds so a crashed prior run can
    never permanently deadlock this single-user prototype tool."""
    start = time.time()
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return
        except FileExistsError:
            if time.time() - start > timeout:
                try:
                    os.remove(lock_path)
                except OSError:
                    pass
                continue
            time.sleep(0.01)


def _release_file_lock(lock_path: str) -> None:
    try:
        os.remove(lock_path)
    except OSError:
        pass


def next_investigation_id(state_dir: str = "output") -> str:
    """
    Generate a unique, sequential TX-XXXXXX investigation ID that persists
    ACROSS process invocations (not just within one Python process).

    Rationale: the CLI is a fresh process per invocation, so an in-memory
    module-level counter resets to 0 every time and produces the same ID
    (TX-000001) for every separate `python cli.py analyze ...` call. This
    persists the counter to a small state file next to the output
    directory, guarded by a simple cross-platform exclusive-create lock
    file, so IDs remain unique across separate CLI runs without requiring
    a database or any new dependency.
    """
    os.makedirs(state_dir, exist_ok=True)
    state_path = os.path.join(state_dir, ".tx_investigation_counter")
    lock_path = state_path + ".lock"

    _acquire_file_lock(lock_path)
    try:
        n = 0
        if os.path.exists(state_path):
            try:
                with open(state_path, "r", encoding="utf-8") as f:
                    n = int(f.read().strip() or "0")
            except (ValueError, OSError):
                n = 0
        # Never reuse an ID if the counter was deleted or corrupted.
        try:
            existing = [int(m.group(1)) for name in os.listdir(state_dir)
                        if (m := re.fullmatch(r"TX-(\d{6})\.json", name))]
            n = max([n] + existing)
        except OSError:
            pass
        n += 1
        tmp_path = state_path + f".{os.getpid()}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(str(n))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, state_path)
    finally:
        _release_file_lock(lock_path)

    return new_investigation_id(n)



def canonical_json_bytes(value) -> bytes:
    """Stable UTF-8 JSON used for IDs, graph hashes and manifests."""
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode("utf-8")


def stable_object_id(prefix: str, value, length: int = 16) -> str:
    return f"{prefix}-{sha256_bytes(canonical_json_bytes(value))[:length].upper()}"


def _fsync_directory(path: str) -> None:
    """Best-effort directory durability; unavailable on some Windows/filesystems."""
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def private_makedirs(path: str, mode: int = 0o700) -> None:
    os.makedirs(path, mode=mode, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def atomic_write_new(path: str, data: bytes, mode: int = 0o600) -> str:
    """Publish one new file without overwrite or exposing a partial final file."""
    import tempfile
    parent = os.path.dirname(os.path.abspath(path))
    private_makedirs(parent)
    fd, temp_path = tempfile.mkstemp(prefix=".trace-x-", suffix=".tmp", dir=parent)
    try:
        try:
            os.fchmod(fd, mode)
        except OSError:
            pass
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link is an exclusive, non-overwriting publish on supported filesystems.
        try:
            os.link(temp_path, path)
            os.unlink(temp_path)
        except (AttributeError, OSError) as exc:
            if os.path.exists(path):
                raise FileExistsError(path) from exc
            # Fallback for filesystems without hard links. Opening final exclusively
            # preserves non-overwrite, though pair atomicity is provided by save_case.
            out_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            try:
                with os.fdopen(out_fd, "wb") as out:
                    out.write(data)
                    out.flush()
                    os.fsync(out.fileno())
            finally:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
        try:
            os.chmod(path, mode)
        except OSError:
            pass
        _fsync_directory(parent)
        return path
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise
