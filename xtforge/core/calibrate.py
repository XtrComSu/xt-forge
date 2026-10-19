"""Boot-time recalibration: mem WAL checkpoint + expiry, flash compact, caps reprobe.

Problem fixed: previously nothing invalidated caches on reboot. caps.json was
trusted for 3600s even across a reboot, SQLite WAL (mem.db-wal/-shm) was never
checkpointed, flash TTLs were only filtered on read (never purged), and
`xtforge sync` installed no boot hook. After an Android reboot / Termux restart
memory stayed stale until a manual command touched it.

`calibrate()` is idempotent and safe to run on every boot and from `doctor`.
It records the kernel boot_id so the next boot is detected as a reboot.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from ..version import cache_dir, db_path, xt_home

BOOT_FILE = "boot.json"


def current_boot_id() -> str:
    """Stable id that changes on every reboot. Never raises."""
    for cand in (Path("/proc/sys/kernel/random/boot_id"),):
        try:
            txt = cand.read_text().strip()
            if txt:
                return txt
        except OSError:
            pass
    # Fallback: btime + uptime. Changes across reboot, stable within a boot.
    try:
        btime = ""
        uptime = ""
        try:
            for line in Path("/proc/stat").read_text().splitlines():
                if line.startswith("btime "):
                    btime = line.split()[1]
                    break
        except OSError:
            pass
        try:
            uptime = Path("/proc/uptime").read_text().split()[0]
        except (OSError, IndexError):
            pass
        if btime:
            return f"btime-{btime}"
        if uptime:
            # uptime alone drifts, so bucket it coarsely; btime preferred.
            return f"uptime-{uptime}"
    except Exception:
        pass
    try:
        import subprocess

        r = subprocess.run(["uptime", "-s"], capture_output=True, text=True, timeout=3)
        out = r.stdout.strip()
        if out:
            return f"uptime-s-{out}"
    except Exception:
        pass
    return "unknown-boot"


def boot_path() -> Path:
    return cache_dir() / BOOT_FILE


def read_boot() -> dict[str, Any] | None:
    p = boot_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, dict) else None
    except (ValueError, OSError):
        return None


def write_boot(rec: dict[str, Any]) -> None:
    from ..atomicio import atomic_write_json

    atomic_write_json(boot_path(), rec)


def needs_calibration() -> dict[str, Any]:
    """Cheap check: reboot detected, stale caps, WAL leftovers, or never calibrated."""
    boot_id = current_boot_id()
    prev = read_boot()
    reboot = not prev or prev.get("boot_id") != boot_id

    # caps staleness (age or boot mismatch)
    caps_stale = True
    try:
        from .route import caps as capmod

        cached = capmod.read_caps()
        if cached and cached.get("stamp"):
            age = time.time() - float(cached["stamp"])
            same_boot = cached.get("boot_id") in (None, boot_id)
            # None = pre-calibration cache, treat boot as same but age rules apply
            caps_stale = (age >= 3600) or (not same_boot)
        else:
            caps_stale = True
    except Exception:
        caps_stale = True

    # WAL leftovers from unclean shutdown / reboot
    wal = False
    try:
        home = xt_home()
        wal = (home / "mem.db-wal").exists() or (home / "mem.db-shm").exists()
    except Exception:
        pass

    need = bool(reboot or caps_stale or wal or not prev)
    return {
        "boot_id": boot_id,
        "prev_boot_id": (prev or {}).get("boot_id"),
        "reboot": reboot,
        "caps_stale": caps_stale,
        "wal_present": wal,
        "needs": need,
    }


def _sqlite_maintenance(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"integrity": None, "checkpoint": None, "purged": 0, "fts": None}
    if not path.exists():
        out["integrity"] = "no-db"
        return out
    conn = sqlite3.connect(str(path), timeout=15.0)
    try:
        try:
            row = conn.execute("PRAGMA integrity_check").fetchone()
            out["integrity"] = str(row[0]) if row else "unknown"
        except sqlite3.Error as exc:
            out["integrity"] = f"error: {exc}"
        try:
            # TRUNCATE reclaims the -wal file left behind by a reboot.
            chk = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            out["checkpoint"] = list(chk) if chk else None
        except sqlite3.Error as exc:
            out["checkpoint"] = f"error: {exc}"
        conn.commit()
    finally:
        conn.close()
    # Purge + FTS health go through Store so triggers stay consistent.
    try:
        from .mem.store import Store

        st = Store(path)
        try:
            try:
                out["purged"] = st.purge_expired()
            except Exception as exc:
                out["purged"] = f"error: {exc}"
            try:
                if st.fts:
                    n_mem = st.conn.execute("SELECT COUNT(*) FROM mem").fetchone()[0]
                    try:
                        n_fts = st.conn.execute(
                            "SELECT COUNT(*) FROM mem_fts"
                        ).fetchone()[0]
                    except sqlite3.Error:
                        n_fts = -1
                    out["fts"] = {"mem": n_mem, "fts": n_fts, "match": n_mem == n_fts}
                    if n_mem != n_fts:
                        st._rebuild_fts()
                        st.conn.commit()
                        out["fts"]["rebuilt"] = True
                else:
                    out["fts"] = "like_trigram"
            except Exception as exc:
                out["fts"] = f"error: {exc}"
        finally:
            st.close()
    except Exception as exc:
        out["store_error"] = str(exc)
    # Final checkpoint so the WAL file is actually truncated post-purge.
    try:
        conn2 = sqlite3.connect(str(path), timeout=15.0)
        try:
            conn2.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn2.commit()
        finally:
            conn2.close()
    except Exception:
        pass
    return out


def _flash_maintenance() -> dict[str, Any]:
    from .mem.flash import Flash

    f = Flash()
    scopes = f.scopes()
    if not scopes:
        scopes = ["global"]
    per_scope: dict[str, Any] = {}
    totals = {"scopes": 0, "expired": 0, "dupes_merged": 0, "evicted": 0}
    for scope in sorted(set(scopes)):
        try:
            res = f.compact(scope)
            stats = f.stats(scope)
            per_scope[scope] = {**res, "stats": stats}
            totals["scopes"] += 1
            totals["expired"] += int(res.get("expired", 0))
            totals["dupes_merged"] += int(res.get("dupes_merged", 0))
            totals["evicted"] += int(res.get("evicted", 0))
        except Exception as exc:
            per_scope[scope] = {"error": str(exc)}
    return {"totals": totals, "scopes": per_scope}


def calibrate(force: bool = False) -> dict[str, Any]:
    """Run full recalibration. Idempotent; safe on every boot."""
    t0 = time.time()
    boot_id = current_boot_id()
    prev = read_boot()
    reboot = not prev or prev.get("boot_id") != boot_id
    pre = needs_calibration()
    skipped = (not force) and (not pre["needs"])
    result: dict[str, Any] = {
        "ok": True,
        "boot_id": boot_id,
        "prev_boot_id": (prev or {}).get("boot_id"),
        "reboot": reboot,
        "forced": force,
        "skipped": skipped,
        "ts": time.time(),
    }
    if skipped:
        result["reason"] = "fresh; no reboot, caps fresh, no WAL"
        result["ms"] = int((time.time() - t0) * 1000)
        return result

    # 1. sqlite (WAL checkpoint + integrity + expiry + FTS)
    try:
        result["sqlite"] = _sqlite_maintenance(db_path())
    except Exception as exc:
        result["sqlite"] = {"error": str(exc)}

    # 2. flash (compact every scope)
    try:
        result["flash"] = _flash_maintenance()
    except Exception as exc:
        result["flash"] = {"error": str(exc)}

    # 3. caps reprobe (bypass 1h cache; records current boot_id)
    try:
        from .route import caps as capmod

        caps = capmod.probe(use_cache=False)
        result["caps"] = {"tools": caps.get("tools"), "boot_id": boot_id}
    except Exception as exc:
        result["caps"] = {"error": str(exc)}

    # 4. sync drift check (dry-run only: report, never write here)
    try:
        from ..adapters.sync import build_actions

        drift = build_actions(dry_run=True)
        result["sync_drift"] = {
            "would_write": drift.get("would_write", 0),
            "unchanged": drift.get("unchanged", 0),
        }
    except Exception as exc:
        result["sync_drift"] = {"error": str(exc)}

    result["ms"] = int((time.time() - t0) * 1000)
    try:
        write_boot(
            {
                "boot_id": boot_id,
                "last_calibrated": time.time(),
                "last_ms": result["ms"],
                "reboot": reboot,
            }
        )
    except Exception as exc:
        result["boot_write_error"] = str(exc)
    return result


def status() -> dict[str, Any]:
    """Cheap status for `doctor` and `--json` without doing work."""
    pre = needs_calibration()
    prev = read_boot()
    return {
        **pre,
        "last_calibrated": (prev or {}).get("last_calibrated"),
        "boot_file": str(boot_path()),
        "db": str(db_path()),
    }
