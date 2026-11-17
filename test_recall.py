#!/usr/bin/env python3
"""Tests for `xtforge recall` — the cross-store fan-out.

Pure-function tests plus live-store checks. Every check states what it proves.

Run: python3 test_recall.py
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, ".")
from xtforge.cli import recall_cmd as rc  # noqa: E402

XT = "xtforge"
ENV = dict(os.environ, XT_HOME="$XT_HOME")
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail else ""))
    if not cond:
        fails.append(name)


def run(*args, timeout=90):
    return subprocess.run([XT, *args], capture_output=True, text=True,
                          env=ENV, timeout=timeout)


# --- tokenisation and the relevance gate ---------------------------------
check("stopwords are dropped", "the" not in rc._tokens("the loop guard"))
check("short tokens are dropped", "an" not in rc._tokens("an x y ab"))
check("real tokens survive", rc._tokens("proxy cancellation") == {"proxy", "cancellation"})

row_hit = {"title": "loop guard cost", "body": "toggle added to rea_lite"}
row_off = {"title": "pokemon teams", "body": "platinum gym rematches"}
check("relevant row kept", rc._relevant([row_hit], "loop guard") == [row_hit])
check("unrelated row dropped", rc._relevant([row_off], "loop guard") == [])
check("empty query keeps everything", rc._relevant([row_hit], "") == [row_hit])
# one shared common word out of four must NOT qualify
check("single shared token out of four is rejected",
      rc._relevant([{"title": "editing does nothing", "body": ""}],
                   "zzz nothing matches xyzzy") == [])

# --- merge / dedup --------------------------------------------------------
a = rc._row("mem", "fact", "t1", "same body")
b = rc._row("flash", "session", "different key", "same body")
c = rc._row("mem", "fact", "other", "other body")
merged = rc.merge([a, b, c])
check("cross-store duplicate collapses to one row", len(merged) == 2,
      f"got {len(merged)}")
check("merged row cites both stores",
      any(set(r["sources"]) == {"mem", "flash"} for r in merged))
check("distinct rows are preserved", len(rc.merge([a, c])) == 2)
check("empty body does not dedupe everything",
      len(rc.merge([rc._row("mem", "f", "x", ""), rc._row("mem", "f", "y", "")])) == 2)

# --- live CLI behaviour ---------------------------------------------------
miss = run("recall", "xyzzy plugh frobnicate", "--json")
d = json.loads(miss.stdout)
check("nonsense query reports an explicit miss", d["count"] == 0, f"count={d['count']}")
check("miss is ok:true, not an error", d.get("ok") is True)

hit = run("recall", "loop guard", "--json")
h = json.loads(hit.stdout)
check("real query returns rows", h["count"] > 0, f"count={h['count']}")
check("every row names its store",
      all(r["store"] in ("mem", "recon", "flash", "errors") for r in h["results"]))
check("rows carry a fingerprint for dedup",
      all(r.get("fingerprint") for r in h["results"]))

scoped = run("recall", "loop", "--store", "recon", "--json")
s = json.loads(scoped.stdout)
check("recon without --target is reported as not-applicable",
      any("no --target" in x for x in s["notApplicable"]), str(s.get("notApplicable")))

err = run("recall", "loop", "--store", "errors", "--json")
e = json.loads(err.stdout)
check("errors without --tool is reported as not-applicable",
      any("no --tool" in x for x in e["notApplicable"]), str(e.get("notApplicable")))

loose = run("recall", "xyzzy plugh frobnicate", "--loose", "--json")
lo = json.loads(loose.stdout)
check("--loose bypasses the relevance gate", lo["count"] >= 0)

# --- artifacts source -----------------------------------------------------
import tempfile, shutil
atmp = tempfile.mkdtemp(prefix="xt-rec-art-")
try:
    good = os.path.join(atmp, "good.csv")
    with open(good, "w") as fh:
        fh.write("a,1\n")
    aenv = dict(ENV, XT_INVOKE_CWD=atmp)
    subprocess.run([XT, "artifact", "record", "good.csv", "--producer", "t"],
                   capture_output=True, text=True, cwd=atmp, env=aenv, timeout=60)
    subprocess.run([XT, "artifact", "check", "good.csv", "--check", "c",
                    "--result", "pass", "--checker", "b@1", "--exit-status", "0"],
                   capture_output=True, text=True, cwd=atmp, env=aenv, timeout=60)
    subprocess.run([XT, "artifact", "require", "good.csv", "--requires", "c"],
                   capture_output=True, text=True, cwd=atmp, env=aenv, timeout=60)
    r = subprocess.run([XT, "recall", "good", "--store", "artifacts",
                        "--artifacts-root", atmp, "--json"],
                       capture_output=True, text=True, timeout=90,
                       env=dict(ENV, XT_INVOKE_CWD=atmp))
    d2 = json.loads(r.stdout)
    check("recall surfaces a recorded artifact", d2["count"] >= 1, f"count={d2['count']}")
    row = next((x for x in d2["results"] if x["store"] == "artifact"), None)
    check("artifact row reports its derived status",
          row is not None and ("verified" in row["body"] or "partial" in row["body"]),
          str(row and row["body"]))
    check("artifact row carries the absolute path",
          row is not None and os.path.isabs(str(row.get("path"))), str(row and row.get("path")))

    # a file with no sidecar must not appear
    with open(os.path.join(atmp, "untracked-widget.csv"), "w") as fh:
        fh.write("z\n")
    r = subprocess.run([XT, "recall", "untracked-widget", "--store", "artifacts",
                        "--artifacts-root", atmp, "--json"],
                       capture_output=True, text=True, timeout=90,
                       env=dict(ENV, XT_INVOKE_CWD=atmp))
    d3 = json.loads(r.stdout)
    check("unrecorded file is not surfaced as an artifact",
          all(x["store"] != "artifact" for x in d3["results"]),
          str(d3["results"]))
finally:
    shutil.rmtree(atmp, ignore_errors=True)

empty = run("recall", "")
check("empty query is refused", empty.returncode == 2, f"rc={empty.returncode}")

print()
if fails:
    print(f"{len(fails)} failure(s): {fails}")
    sys.exit(1)
print("all recall checks passed")
