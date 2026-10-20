"""Regression guards for invariants that no other test pins down.

These came out of mutation testing: deliberately breaking the source and
checking that the suite notices. Three mutations survived the existing 340
tests, which meant the suite was green while the behaviour was wrong.

Each test below kills a mutant that used to survive:

  * `ENFORCED_MIN_EVIDENCE` lowered from 3 to 1 — the old test only ever
    moved confidence and evidence together, so the evidence count was never
    pinned on its own. A learning can reach high confidence on two strong
    signals; it must still not be `enforced`.
  * `ENFORCED_MIN_CONFIDENCE` lowered from 0.85 to 0.0 — same mirror image:
    three weak signals are three pieces of evidence, but not enough
    confidence, so the row stays `hint`.
  * base64url padding left on the encoder — round-tripping still worked
    (the decoder re-pads), but a padded segment is not a JWT segment, so
    `inspect` silently stopped recognising JWTs.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import codec as codecmod  # noqa: E402
from xtforge.core.taste import learn as learnmod  # noqa: E402
from xtforge.core.taste.schema import Signal  # noqa: E402


def signal(weight: float, polarity: int = 1) -> Signal:
    """A signal with an explicit weight, so evidence count and confidence
    can be moved independently of one another."""
    return Signal(kind="explicit", polarity=polarity, category="cli",
                  key="semicolons", statement="Omit semicolons.",
                  weight=weight)


class TestEnforcedThresholds(unittest.TestCase):
    """`enforced` needs high confidence **and** three pieces of evidence.

    The two thresholds are independent gates. A suite that only exercises
    them together cannot tell which one is broken.
    """

    def test_high_confidence_on_two_signals_is_not_enforced(self):
        """Two strong signals: confidence 0.90, but only two pieces of
        evidence. The evidence count is the binding gate here."""
        learning = learnmod.new_learning(signal(2.0), "global", 100)
        learnmod.absorb(learning, signal(2.0), 100)
        learnmod.absorb(learning, signal(2.0), 100)

        self.assertGreaterEqual(learning.confidence, 0.85,
                                "precondition: confidence must be high")
        self.assertLess(learning.evidence, 3,
                        "precondition: evidence must be below the gate")
        self.assertEqual(learning.status, "hint",
                         "two pieces of evidence must not enforce a rule")

    def test_three_weak_signals_are_not_enforced(self):
        """Three pieces of evidence, but confidence only 0.80. The
        confidence gate is the binding one here."""
        learning = learnmod.new_learning(signal(0.5), "global", 100)
        for _ in range(3):
            learnmod.absorb(learning, signal(0.5), 100)

        self.assertGreaterEqual(learning.evidence, 3,
                                "precondition: evidence must reach the gate")
        self.assertLess(learning.confidence, 0.85,
                        "precondition: confidence must be below the gate")
        self.assertEqual(learning.status, "hint",
                         "low confidence must not enforce a rule")

    def test_both_gates_satisfied_does_enforce(self):
        """The other corner: three strong signals clear both gates."""
        learning = learnmod.new_learning(signal(1.0), "global", 100)
        for _ in range(3):
            learnmod.absorb(learning, signal(1.0), 100)

        self.assertGreaterEqual(learning.confidence, 0.85)
        self.assertGreaterEqual(learning.evidence, 3)
        self.assertEqual(learning.status, "enforced")


class TestBase64UrlPadding(unittest.TestCase):
    """base64url output must be unpadded.

    Padding is not cosmetic: a JWT segment may not contain `=`, and the
    JWT shape matcher keys on the unpadded alphabet. Padding that survives
    the encoder makes `inspect` stop recognising JWTs while every
    round-trip test still passes, because the decoder re-pads on the way in.
    """

    def test_encoder_strips_padding(self):
        encoded = codecmod._b64_encode(b"x" * 56, url=True)
        self.assertNotIn("=", encoded,
                         "base64url output must be unpadded")
        # 56 bytes -> 76 base64 characters, 1 of which is padding.
        self.assertEqual(len(encoded), 75)

    def test_inspect_recognises_a_jwt_whose_payload_needs_padding(self):
        payload = b'{"sub":"1234567890","name":"John Doe","iat":1516239022}'
        self.assertEqual(len(payload) % 3, 1,
                         "precondition: payload must require padding")

        segment = codecmod._b64_encode(payload, url=True)
        self.assertNotIn("=", segment)
        token = f"eyJhbGciOiJIUzI1NiJ9.{segment}.c2ln"

        found = codecmod.inspect(token)
        kinds = [item.get("type") for item in found.get("findings", [])]
        self.assertIn("jwt", kinds,
                      "a JWT with a padding-requiring payload must be found")
        payload_part = next(item for item in found["findings"]
                            if item["type"] == "jwt")["detail"][1]
        self.assertEqual(payload_part["payload"]["sub"], "1234567890")


class TestRot13IsActuallyARotation(unittest.TestCase):
    """rot13 must rotate by 13, not stand still.

    rot13 is an involution, so `decode(encode(x)) == x` holds for the
    identity function too. A round-trip test alone cannot tell a working
    rot13 from a no-op, so the output value itself has to be pinned.
    """

    def test_rot13_shifts_letters_by_thirteen(self):
        self.assertEqual(codecmod._rot13("Uryyb, Jbeyq!"), "Hello, World!")

    def test_rot13_leaves_non_letters_alone(self):
        self.assertEqual(codecmod._rot13("Abc XYZ 123"), "Nop KLM 123")

    def test_rot13_is_an_involution(self):
        once = codecmod._rot13("The quick brown fox")
        self.assertEqual(codecmod._rot13(once), "The quick brown fox")
        self.assertNotEqual(once, "The quick brown fox")


if __name__ == "__main__":
    unittest.main()
