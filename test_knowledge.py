#!/usr/bin/env python3
"""Tests for agent-contributed knowledge: status, verification, history.

The rules under test
--------------------
  - an agent may assert `observed` or `proposed`, never `verified`;
  - `verified` is reachable only through a verification that names a method and
    supplies an executed check (checker or exit status);
  - an assertion-only pass does not promote, and says why in the record;
  - a failed recovery moves status to `contradicted` AND lowers confidence;
  - revisions and deprecations keep history;
  - obsolete/superseded records are separated from current knowledge;
  - scope (project/target) filters retrieval.

Run: python3 test_knowledge.py
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


tmp = tempfile.mkdtemp(prefix="xt-know-")
env = dict(os.environ, XT_INVOKE_CWD=tmp)
db = os.path.join(tmp, "mem.db")


def run(*args, timeout=90):
    return subprocess.run([XT, *args, "--db", db], capture_output=True,
                          text=True, cwd=tmp, env=env, timeout=timeout)


def jrun(*args):
    r = run("--json", *args) if False else run(*args, "--json")
    return json.loads(r.stdout)


def put(**kw):
    args = ["knowledge", "put", "--title", kw.pop("title"), "--body",
            kw.pop("body", "body text")]
    for key, flag in (("kind", "--kind"), ("project", "--project"),
                      ("target", "--target"), ("author", "--author")):
        if key in kw:
            args += [flag, kw.pop(key)]
    if "status" in kw:
        args += ["--status", kw.pop("status")]
    out = run(*args, "--json")
    if out.returncode != 0:
        return {"error": out.stdout.strip() or out.stderr.strip()}
    return json.loads(out.stdout)


try:
    # --- agent cannot self-promote -------------------------------------
    r = put(title="unverified claim", kind="fact", status="verified")
    check("an agent cannot assert 'verified'", "error" in r, str(r)[:120])
    check("the refusal explains how to verify",
          "error" in r and "verify" in r["error"].lower(), str(r.get("error"))[:120])

    # --- default status is proposed ------------------------------------
    a = put(title="cache may be stale", kind="fact", project="p1")
    check("a new record is 'proposed' by default", a.get("status") == "proposed", str(a))
    check("put returns an id", bool(a.get("id")))

    # --- assertion-only verification does not promote -------------------
    v = jrun("knowledge", "verify", a["id"], "--method", "someone said so",
             "--result", "pass")
    check("an assertion-only pass does not promote", v.get("promoted") is False, str(v))
    rec = jrun("knowledge", "get", a["id"])
    body = json.loads(rec["body"]) if isinstance(rec.get("body"), str) else {}
    check("the record explains why it was not promoted",
          "verificationCaveat" in body, str(list(body))[:120])
    check("status stays proposed after an assertion-only pass",
          rec.get("status") == "proposed", str(rec.get("status")))

    # --- executed verification promotes --------------------------------
    v = jrun("knowledge", "verify", a["id"], "--method", "reran the query",
             "--result", "pass", "--checker", "q@1", "--exit-status", "0")
    check("an executed pass promotes to verified", v.get("promoted") is True, str(v))
    check("verified status is reported", v.get("status") == "verified", str(v))
    rec = jrun("knowledge", "get", a["id"])
    check("the record status is verified", rec.get("status") == "verified")
    ver = rec.get("verification")
    if isinstance(ver, str):
        ver = json.loads(ver)
    check("verification records the checker", ver.get("checker") == "q@1", str(ver)[:120])
    check("verification records the exit status", ver.get("exitStatus") == 0)
    check("verification records that it was executed", ver.get("executed") is True)

    # --- failed recovery contradicts and lowers confidence -------------
    b = put(title="delete node_modules", kind="recovery", project="p1")
    before = jrun("knowledge", "get", b["id"]).get("confidence")
    v = jrun("knowledge", "verify", b["id"], "--method", "tried it, same error",
             "--result", "fail", "--contradict")
    check("a failed recovery is 'contradicted'", v.get("status") == "contradicted", str(v))
    after = jrun("knowledge", "get", b["id"]).get("confidence")
    check("a failed recovery lowers confidence", after < before, f"{before} -> {after}")
    check("contradicted confidence is low", after <= 0.2, str(after))

    # --- verification requires a method --------------------------------
    r = run("knowledge", "verify", b["id"], "--result", "pass", "--checker", "x")
    check("verification without a method is refused", r.returncode != 0, f"rc={r.returncode}")

    # --- revise keeps history ------------------------------------------
    r = jrun("knowledge", "revise", a["id"], "--title", "cache is definitely stale")
    check("revise reports a revision count", r.get("revisions", 0) >= 1, str(r))
    rec = jrun("knowledge", "get", a["id"])
    check("revise updates the title", rec.get("title") == "cache is definitely stale")
    body = json.loads(rec["body"]) if isinstance(rec.get("body"), str) else {}
    check("the previous revision is preserved",
          any("previous" in rev for rev in (body.get("revisions") or [])),
          str(body.get("revisions"))[:120])
    r = run("knowledge", "revise", a["id"], "--status", "verified")
    check("a revision cannot promote to verified", r.returncode != 0, f"rc={r.returncode}")

    # --- deprecate keeps the reason ------------------------------------
    d = jrun("knowledge", "deprecate", b["id"], "--reason", "made things worse")
    check("deprecate sets obsolete", d.get("status") == "obsolete", str(d))
    rec = jrun("knowledge", "get", b["id"])
    body = json.loads(rec["body"]) if isinstance(rec.get("body"), str) else {}
    check("the deprecation reason is preserved",
          any("made things worse" in (x.get("reason") or "")
              for x in (body.get("deprecations") or [])), str(body.get("deprecations"))[:120])
    r = run("knowledge", "deprecate", b["id"], "--reason", "")
    check("deprecation without a reason is refused", r.returncode != 0, f"rc={r.returncode}")

    # --- obsolete is separated from current ----------------------------
    put(title="cache is stale because of X", kind="fact", project="p1")
    s = jrun("knowledge", "search", "cache stale", "--project", "p1")
    ids_current = {x["id"] for x in s["current"]}
    ids_hist = {x["id"] for x in s["historical"]}
    check("obsolete records are not in 'current'", b["id"] not in ids_current, str(ids_current))
    check("obsolete records are still retrievable as history",
          b["id"] in ids_hist, str(ids_hist))

    # --- scope filtering -----------------------------------------------
    put(title="scoped only to p2", kind="fact", project="p2")
    s1 = jrun("knowledge", "search", "scoped only to p2", "--project", "p1")
    check("a p2 record is not returned for p1",
          all(x.get("project") != "p2" for x in s1["current"]), str(s1["current"])[:120])
    s2 = jrun("knowledge", "search", "scoped only to p2", "--project", "p2")
    check("a p2 record is returned for p2", len(s2["current"]) >= 1, str(s2["counts"]))

    # --- link --------------------------------------------------------
    c = put(title="root cause: stale symlink", kind="problem", project="p1")
    lk = jrun("knowledge", "link", "--id", c["id"], a["id"], "--relation", "caused_by")
    check("link records a relation", lk.get("relation") in ("caused_by", "relates_to"),
          str(lk))
    r = run("knowledge", "link", "--id", c["id"], a["id"], "--relation", "nonsense")
    check("an invalid relation is refused", r.returncode != 0, f"rc={r.returncode}")

    # --- unknown kind -------------------------------------------------
    r = run("knowledge", "put", "--title", "x", "--body", "y", "--kind", "nonsense")
    check("an unknown kind is refused", r.returncode != 0, f"rc={r.returncode}")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print()
if fails:
    print(f"{len(fails)} failure(s): {fails}")
    sys.exit(1)
print("all knowledge checks passed")
