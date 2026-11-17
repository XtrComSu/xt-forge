#!/usr/bin/env python3
"""Tests for `xtforge artifact` — provenance and verification sidecars.

What is under test
------------------
A sidecar records an artifact's identity (sha256 of its bytes), where it came
from, and which checks examined it. The important property is that **status is
derived from the current bytes**, not from a stored flag:

    no sidecar            -> unverified
    sidecar, no checks    -> unverified
    pass on current bytes -> verified
    fail on current bytes -> failed
    bytes changed         -> stale (and a passing check on old bytes cannot
                             upgrade it)

Run: python3 test_artifact.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

XT = "xtforge"
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail else ""))
    if not cond:
        fails.append(name)


def run(*args, cwd, timeout=60):
    return subprocess.run([XT, *args], capture_output=True, text=True,
                          cwd=cwd, timeout=timeout,
                          env=dict(os.environ, XT_INVOKE_CWD=cwd))


def status(cwd, name):
    r = run("artifact", "verify", name, cwd=cwd)
    return r.stdout.strip().split(":")[0], r.returncode


tmp = tempfile.mkdtemp(prefix="xt-art-")
try:
    art = "out.csv"
    p = os.path.join(tmp, art)

    # --- unverified: no sidecar ------------------------------------------
    with open(p, "w") as fh:
        fh.write("metric,42\n")
    st, rc = status(tmp, art)
    check("fresh file with no sidecar is unverified", st == "unverified", st)
    check("unverified is a non-zero exit (gates callers)", rc != 0, f"rc={rc}")

    # --- record, still unverified ---------------------------------------
    run("artifact", "record", art, "--media-type", "text/csv",
        "--producer", "test", cwd=tmp)
    check("record writes a sidecar", os.path.exists(p + ".xt-artifact.json"))
    st, rc = status(tmp, art)
    check("recorded-but-unchecked stays unverified", st == "unverified", st)

    # sidecar carries identity + producer
    sc = json.load(open(p + ".xt-artifact.json"))
    check("sidecar declares the schema", sc.get("schema") == "xt.artifact/1")
    check("sidecar stores a sha256 id", len(str(sc.get("id"))) == 64)
    check("sidecar stores the producer", sc.get("producer") == "test")
    check("sidecar stores the media type", sc.get("mediaType") == "text/csv")

    # --- passing check -> verified --------------------------------------
    # An executed pass alone is NOT completion: no requirement was declared.
    run("artifact", "check", art, "--check", "csv-parses", "--result", "pass",
        "--detail", "1 row", "--checker", "csv@1", "--exit-status", "0", cwd=tmp)
    st, rc = status(tmp, art)
    check("executed pass without a requirement is partially_verified",
          st == "partially_verified", st)
    check("partial is a non-zero exit", rc != 0, f"rc={rc}")

    # Declaring the requirement converts it into a completion statement.
    run("artifact", "require", art, "--requires", "csv-parses", cwd=tmp)
    st, rc = status(tmp, art)
    check("requirement satisfied by an executed pass is verified", st == "verified", st)
    check("verified is exit 0", rc == 0, f"rc={rc}")

    # A declared pass can never substitute for an executed one.
    run("artifact", "check", art, "--check", "looks-right", "--result", "pass",
        "--declared", cwd=tmp)
    st, _ = status(tmp, art)
    check("a declared pass does not disturb a verified artifact", st == "verified", st)

    # --- editing the file -> stale --------------------------------------
    with open(p, "w") as fh:
        fh.write("metric,99\n")
    st, rc = status(tmp, art)
    check("edited bytes flip status to stale", st == "stale", st)

    # --- a pass on the OLD bytes must not upgrade -----------------------
    run("artifact", "check", art, "--check", "csv-parses", "--result", "pass",
        "--detail", "stale re-run", "--checker", "csv@1", "--exit-status", "0", cwd=tmp)
    st, _ = status(tmp, art)
    check("a check appended to a stale sidecar stays stale", st == "stale", st)

    # --- re-record adopts bytes, failing check -> failed -----------------
    run("artifact", "record", art, "--media-type", "text/csv", cwd=tmp)
    run("artifact", "check", art, "--check", "value-correct", "--result", "fail",
        "--detail", "expected 42, got 99", "--checker", "assert@1",
        "--exit-status", "1", cwd=tmp)
    st, rc = status(tmp, art)
    check("failing check on current bytes is failed", st == "failed", st)
    check("failed is a non-zero exit", rc != 0, f"rc={rc}")

    # --- recover to verified --------------------------------------------
    run("artifact", "check", art, "--check", "value-correct", "--result", "pass",
        "--detail", "fixed", "--checker", "assert@1", "--exit-status", "0", cwd=tmp)
    run("artifact", "require", art, "--requires", "value-correct", cwd=tmp)
    st, rc = status(tmp, art)
    check("a later executed pass on the same check recovers to verified",
          st == "verified", st)

    # --- check replacement, not accumulation ----------------------------
    sc = json.load(open(p + ".xt-artifact.json"))
    ids = [c["id"] for c in sc["checks"]]
    check("re-running a check replaces rather than appends",
          ids.count("value-correct") == 1, str(ids))
    check("history still records each run",
          sum(1 for h in sc["history"] if h.get("change", "").startswith("check:value-correct")) >= 2,
          str(len(sc["history"])))

    # --- deleting the artifact -> stale ---------------------------------
    os.remove(p)
    st, rc = status(tmp, art)
    check("deleted artifact reports stale", st == "stale", st)
    check("deleted artifact is non-zero exit", rc != 0, f"rc={rc}")

    # --- declared vs executed verdicts --------------------------------
    d = "declared.csv"
    dp = os.path.join(tmp, d)
    with open(dp, "w") as fh:
        fh.write("x,1\n")
    run("artifact", "record", d, cwd=tmp)
    run("artifact", "check", d, "--check", "i-believe-it", "--result", "pass",
        "--declared", cwd=tmp)
    st, rc = status(tmp, d)
    check("a declared pass alone is attested_unsupported",
          st == "attested_unsupported", st)
    check("attested is a non-zero exit", rc != 0, f"rc={rc}")

    # a pass with no checker and no exit status is treated as declared
    run("artifact", "check", d, "--check", "bare-claim", "--result", "pass", cwd=tmp)
    sc = json.load(open(dp + ".xt-artifact.json"))
    bare = next(c for c in sc["checks"] if c["id"] == "bare-claim")
    check("a pass with no checker/exit status is marked declared",
          bare["declared"] is True, str(bare))

    # declared and executed are mutually exclusive
    r = run("artifact", "check", d, "--check", "both", "--result", "pass",
            "--declared", "--checker", "x@1", cwd=tmp)
    check("declared+executed is refused", r.returncode != 0, f"rc={r.returncode}")

    # an executed pass records its executor and exit status
    run("artifact", "check", d, "--check", "real-run", "--result", "pass",
        "--checker", "checker@2.1", "--exit-status", "0",
        "--evidence", "out.log", cwd=tmp)
    sc = json.load(open(dp + ".xt-artifact.json"))
    real = next(c for c in sc["checks"] if c["id"] == "real-run")
    check("executed check records checker identity", real["checker"] == "checker@2.1")
    check("executed check records version", real["version"] == "1")
    check("executed check records exit status", real["exitStatus"] == 0)
    check("executed check records evidence", real["evidence"] == "out.log")
    check("executed check is not marked declared", real["declared"] is False)

    # --- unrelated passing checks must not imply completion -----------
    u = "unrelated.csv"
    with open(os.path.join(tmp, u), "w") as fh:
        fh.write("y,2\n")
    run("artifact", "record", u, cwd=tmp)
    run("artifact", "check", u, "--check", "file-exists", "--result", "pass",
        "--checker", "ls@1", "--exit-status", "0", cwd=tmp)
    st, _ = status(tmp, u)
    check("one passing smoke check is partial, not complete",
          st == "partially_verified", st)
    run("artifact", "require", u, "--requires", "file-exists",
        "--requires", "values-correct", cwd=tmp)
    st, _ = status(tmp, u)
    check("a missing required check blocks completion", st == "unverified", st)
    run("artifact", "check", u, "--check", "values-correct", "--result", "pass",
        "--declared", cwd=tmp)
    st, _ = status(tmp, u)
    check("a declared pass cannot satisfy a requirement",
          st == "unverified", st)
    run("artifact", "check", u, "--check", "values-correct", "--result", "pass",
        "--checker", "assert@1", "--exit-status", "0", cwd=tmp)
    st, _ = status(tmp, u)
    check("all required executed passes yield verified", st == "verified", st)

    # a requirement naming an unknown check is surfaced, not silently accepted
    r = run("artifact", "require", u, "--requires", "no-such-check", cwd=tmp)
    sc = json.load(open(os.path.join(tmp, u + ".xt-artifact.json")))
    check("unknown required check is reported",
          "no-such-check" in (r.stdout or ""), r.stdout.strip()[:120])

    # --- relative path resolves against the caller, not the tool root ---
    with open(p, "w") as fh:
        fh.write("metric,7\n")
    run("artifact", "record", art, cwd=tmp)
    check("sidecar written next to the caller's file",
          os.path.exists(os.path.join(tmp, art + ".xt-artifact.json")))
    check("nothing written into the tool root",
          not os.path.exists("" + art + ".xt-artifact.json"))

    # --- missing file is a clean caller error ---------------------------
    r = run("artifact", "record", "does-not-exist.bin", cwd=tmp)
    check("recording a missing file fails cleanly",
          r.returncode != 0 and "no such artifact" in (r.stdout + r.stderr),
          f"rc={r.returncode}")

    # --- bad result value rejected --------------------------------------
    r = run("artifact", "check", art, "--check", "x", "--result", "maybe", cwd=tmp)
    check("an invalid --result is refused", r.returncode != 0, f"rc={r.returncode}")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print()
if fails:
    print(f"{len(fails)} failure(s): {fails}")
    sys.exit(1)
print("all artifact checks passed")
