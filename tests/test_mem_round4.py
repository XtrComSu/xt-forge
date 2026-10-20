"""Contract tests for round 4: typed links, review queue, hybrid retrieval.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.mem import search as memsearch  # noqa: E402
from xtforge.core.mem.embed import (Embedder, VectorIndex, cosine,  # noqa: E402
                                    features, hash_embed, stem)
from xtforge.core.mem.store import Store  # noqa: E402


def fresh_store(name: str = "mem") -> Store:
    tmp = tempfile.mkdtemp(prefix="memround4-")
    return Store(Path(tmp) / f"{name}.db")


class TestTypedLinks(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()
        self.a = self.store.put(scope="global", kind="fact", body="alpha note",
                                id="aaa")["id"]
        self.b = self.store.put(scope="global", kind="fact", body="beta note",
                                id="bbb")["id"]

    def tearDown(self):
        self.store.close()

    def test_link_and_read_back(self):
        res = self.store.link(self.a, self.b, "caused_by")
        self.assertEqual(res["action"], "linked")
        self.assertEqual(res["rel"], "caused_by")
        graph = self.store.links(self.a)
        self.assertEqual(graph["count"], 1)
        self.assertEqual(graph["out"][0]["other"], self.b)
        self.assertEqual(graph["out"][0]["direction"], "out")
        incoming = self.store.links(self.b)
        self.assertEqual(incoming["in"][0]["other"], self.a)
        self.assertEqual(incoming["in"][0]["direction"], "in")

    def test_link_is_deduped(self):
        self.store.link(self.a, self.b, "see_also")
        again = self.store.link(self.a, self.b, "see_also")
        self.assertEqual(again["action"], "unchanged")
        self.assertEqual(self.store.links(self.a)["count"], 1)

    def test_bad_relation_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.store.link(self.a, self.b, "buddy_buddy")
        self.assertIn("invalid relation", str(ctx.exception))

    def test_self_link_rejected(self):
        with self.assertRaises(ValueError):
            self.store.link(self.a, self.a, "relates_to")

    def test_unknown_record_rejected(self):
        with self.assertRaises(ValueError):
            self.store.link(self.a, "nope", "relates_to")

    def test_unlink_removes_edges(self):
        self.store.link(self.a, self.b, "fixes")
        self.assertEqual(self.store.unlink(self.a, self.b), 1)
        self.assertEqual(self.store.links(self.a)["count"], 0)

    def test_forget_cascades_links(self):
        self.store.link(self.a, self.b, "part_of")
        self.store.forget(self.a)
        self.assertEqual(self.store.links(self.b)["count"], 0)

    def test_neighbors_walks_both_directions(self):
        c = self.store.put(scope="global", kind="fact", body="gamma", id="ccc")["id"]
        self.store.link(self.a, self.b, "relates_to")
        self.store.link(self.b, c, "relates_to")
        self.assertEqual(self.store.neighbors(self.a, depth=1), ["bbb"])
        self.assertEqual(self.store.neighbors(self.a, depth=2), ["bbb", "ccc"])
        self.assertEqual(self.store.neighbors(c, depth=1), ["bbb"])


class TestReviewQueue(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()

    def tearDown(self):
        self.store.close()

    def test_pending_is_not_promoted(self):
        res = self.store.put(scope="global", kind="decision", body="stage me",
                             pending=True, id="p1")
        self.assertEqual(res["action"], "inserted")
        self.assertEqual(len(self.store.pending()), 1)
        self.assertFalse(self.store.list(pending=False))

    def test_promote_clears_pending(self):
        self.store.put(scope="global", kind="decision", body="stage me",
                       pending=True, confidence=0.4, id="p1")
        res = self.store.review("promote", "p1")
        self.assertEqual(res["changed"], 1)
        rec = self.store.get("p1")
        self.assertEqual(rec["pending"], 0)
        self.assertEqual(rec["confidence"], 0.9)

    def test_drop_removes_candidate(self):
        self.store.put(scope="global", kind="decision", body="stage me",
                       pending=True, id="p1")
        self.store.review("drop", "p1")
        self.assertEqual(self.store.pending(), [])

    def test_pending_candidate_never_rewrites_promoted(self):
        self.store.put(scope="global", kind="procedure",
                       body="Serialize GPU work: run evals after the tune ends",
                       id="promoted")
        res = self.store.put(scope="global", kind="procedure",
                             body="Serialize GPU work: run evals after the fine tune ends",
                             pending=True, id="candidate")
        self.assertEqual(res["action"], "dup_of_promoted")
        self.assertIn("promoted", res["id"])
        self.assertEqual(self.store.pending(), [])
        self.assertIn("tune ends", self.store.get("promoted")["body"])

    def test_review_action_requires_record(self):
        self.assertEqual(self.store.review("promote", "missing")["changed"], 0)
        with self.assertRaises(ValueError):
            self.store.review("nonsense", "p1")


class TestEmbeddings(unittest.TestCase):
    def test_stem_folds_inflections(self):
        self.assertEqual(stem("indexing"), stem("indexed"))

    def test_hash_embed_is_deterministic_and_normalized(self):
        a = hash_embed("serialize the gpu workload")
        b = hash_embed("serialize the gpu workload")
        self.assertEqual(a, b)
        self.assertAlmostEqual(sum(v * v for v in a), 1.0, places=6)

    def test_similarity_prefers_morphological_neighbors(self):
        """Stems and word-shape are this backend's job; synonyms are not."""
        query = hash_embed("which tokens does the indexer produce")
        near = hash_embed("the tokeniser split identifiers during indexing")
        far = hash_embed("commit messages stay one line and imperative")
        self.assertGreater(cosine(query, near), cosine(query, far))

    def test_zero_overlap_stays_unrelated(self):
        """Honest limit: a pure synonym gap is not closed by shape matching."""
        query = hash_embed("allocation failure on the graphics card")
        other = hash_embed("commit messages stay one line and imperative")
        self.assertLessEqual(cosine(query, other), 0.25)

    def test_cmd_backend_used_when_configured(self):
        with mock.patch.dict(os.environ, {"XT_EMBED_CMD": "echo [3, 4]"}):
            emb = Embedder()
            self.assertEqual(emb.backend, "cmd")
            vec = emb.embed("anything")
        self.assertAlmostEqual(vec[0], 0.6, places=6)

    def test_cmd_failure_falls_back_to_hash(self):
        with mock.patch.dict(os.environ, {"XT_EMBED_CMD": "exit 1"}):
            emb = Embedder()
            vec = emb.embed("anything")
        self.assertEqual(emb.fallbacks, 1)
        self.assertEqual(vec, hash_embed("anything"))

    def test_off_mode_is_unavailable(self):
        emb = Embedder(mode="off")
        self.assertFalse(emb.available)
        self.assertIsNone(emb.embed("anything"))


class TestHybridSearch(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()
        self.records = [
            ("r1", "error_pattern", "GPU out of memory during eval",
             "CUDA OOM when evals run while the fine-tune is resident on the card"),
            ("r2", "procedure", "Serialize GPU work",
             "Run evaluation only after the fine-tune job releases the device"),
            ("r3", "preference", "Terse commits",
             "Commit messages stay one line and imperative, no trailing punctuation"),
            ("r4", "error_pattern", "Tokeniser mismatch",
             "Queries failed because the tokeniser split identifiers differently"),
        ]
        for rec_id, kind, title, body in self.records:
            self.store.put(scope="global", kind=kind, title=title, body=body,
                           id=rec_id)

    def tearDown(self):
        self.store.close()

    def test_lexical_path_is_unchanged(self):
        """hybrid=False must reproduce the original formula exactly."""
        out = memsearch.search(self.store, "gpu memory", k=5, hybrid=False,
                               embedder=Embedder(mode="off"), explain=True)
        self.assertFalse(out["hybrid"])
        self.assertEqual(out["embed_mode"], "off")
        for item in out["results"]:
            exp = item["record"]["_explain"]
            boosts = exp["pin"] + exp["recency"] + exp["uses"] + 0.5 * exp["scope"]
            self.assertAlmostEqual(exp["total"],
                                   memsearch.W_TEXT * exp["text"] + boosts,
                                   places=6)

    def test_hybrid_off_matches_disabled_embedder(self):
        off = memsearch.search(self.store, "gpu memory", k=5, hybrid=True,
                               embedder=Embedder(mode="off"))
        lex = memsearch.search(self.store, "gpu memory", k=5, hybrid=False,
                               embedder=Embedder(mode="off"))
        self.assertEqual([r["record"]["id"] for r in off["results"]],
                         [r["record"]["id"] for r in lex["results"]])

    def test_hybrid_is_deterministic(self):
        a = memsearch.search(self.store, "evaluation on the graphics card", k=3,
                             embedder=Embedder())
        b = memsearch.search(self.store, "evaluation on the graphics card", k=3,
                             embedder=Embedder())
        self.assertEqual([r["record"]["id"] for r in a["results"]],
                         [r["record"]["id"] for r in b["results"]])

    def test_hybrid_adds_morphologically_linked_candidates(self):
        """Semantic pass reaches a record the lexical pass cannot.

        The query shares no exact token with the record — only stems and word
        shape — which is the gap the embedding pass is there to close.
        """
        query = "tokenizer breaks name fields apart"
        lex = memsearch.search(self.store, query, k=5, hybrid=False,
                               embedder=Embedder(mode="off"))
        hyb = memsearch.search(self.store, query, k=5, hybrid=True,
                               embedder=Embedder())
        lex_ids = [r["record"]["id"] for r in lex["results"]]
        hyb_ids = [r["record"]["id"] for r in hyb["results"]]
        self.assertTrue(hyb["hybrid"])
        self.assertNotIn("r4", lex_ids)
        self.assertIn("r4", hyb_ids)
        self.assertEqual(hyb_ids[0], "r4")

    def test_vector_index_query_shape(self):
        index = VectorIndex(Embedder())
        index.add("a", "gpu memory exhaustion")
        index.add("b", "commit message style")
        hits = index.query("graphics card ran out of memory", k=2)
        self.assertTrue(hits)
        self.assertEqual(hits[0][0], "a")

    def test_features_carry_word_and_shape_signals(self):
        feats = features("indexing")
        self.assertIn("w:index", feats)
        self.assertIn("p:index", feats)
        self.assertTrue(any(f.startswith("c:") for f in feats))


class TestRecallFixture(unittest.TestCase):
    def test_hybrid_recall_not_worse_than_lexical(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench_mem_recall.py"),
             "--json", "--no-gate"],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertGreaterEqual(payload["queries"], 50)
        self.assertGreaterEqual(payload["hybrid"]["recall"],
                                payload["lexical"]["recall"])
        self.assertGreater(payload["delta"], 0)


class TestCliRound4(unittest.TestCase):
    def run_cli(self, db: str, *args, expect_ok: bool = True):
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "--db", db, "mem", *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60)
        if expect_ok:
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return proc

    def test_link_links_unlink_over_cli(self):
        with tempfile.TemporaryDirectory(prefix="memcli-") as tmp:
            db = str(Path(tmp) / "m.db")
            a = json.loads(self.run_cli(db, "put", "--body", "one",
                                        "--json").stdout)["id"]
            b = json.loads(self.run_cli(db, "put", "--body", "two",
                                        "--json").stdout)["id"]
            self.run_cli(db, "link", a, b, "--rel", "caused_by", "--json")
            graph = json.loads(self.run_cli(db, "links", a, "--json").stdout)
            self.assertEqual(graph["out"][0]["other"], b)
            out = self.run_cli(db, "unlink", a, b, "--json")
            self.assertEqual(json.loads(out.stdout)["removed"], 1)

    def test_review_action_over_cli(self):
        with tempfile.TemporaryDirectory(prefix="memcli-") as tmp:
            db = str(Path(tmp) / "m.db")
            self.run_cli(db, "put", "--body", "stage this candidate",
                         "--kind", "decision", "--pending", "--json")
            pending = json.loads(self.run_cli(db, "review", "--json").stdout)
            rec_id = pending["pending"][0]["id"]
            self.run_cli(db, "review", "--action", "promote", "--id", rec_id,
                         "--json")
            rec = json.loads(self.run_cli(db, "get", "--id", rec_id,
                                          "--json").stdout)
            self.assertEqual(rec["pending"], 0)

    def test_capture_stages_candidates(self):
        with tempfile.TemporaryDirectory(prefix="memcli-") as tmp:
            db = str(Path(tmp) / "m.db")
            log = "AssertionError: 3 failed in 1.20s\nwe decided to keep the WAL on boot\n"
            out = self.run_cli(db, "capture", "--body", log, "--json")
            staged = json.loads(out.stdout)
            self.assertGreaterEqual(staged["count"], 2)
            self.assertEqual(len(json.loads(
                self.run_cli(db, "review", "--json").stdout)["pending"]),
                staged["count"])


if __name__ == "__main__":
    unittest.main()
