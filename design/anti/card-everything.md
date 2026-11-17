---
id: card-everything
name: Card-everything layout
severity: high
provenance: authored for XT-Forge, 2026-11-03
license: MIT
---

# Anti-pattern: every element in a card

## Symptom
Every row, stat and message sits in a rounded card with a shadow. The page reads
as a wall of identical boxes; the eye has no entry point and scanning is slower.

## Why it happens
Cards are the default component in most kits, so applying one is easier than
deciding what deserves emphasis.

## Correction
1. Choose **one** emphasis mechanism per screen — weight, colour, or size.
2. Reserve cards for items that are genuinely discrete and comparable.
3. Use plain rows + spacing for lists; grouping is carried by proximity.
4. Verify by blurring the page: the primary action should still be findable.
