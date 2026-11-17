# Design library

Curated, *usable* assets for agents building interfaces. Not screenshots: every
entry has code, documented dependencies, a licence and a provenance line.

Layout:

    index.json        machine-readable catalogue (what `xtforge design` reads)
    patterns/         layout recipes, each with state coverage
    anti/             anti-patterns with a concrete correction
    data/             clearly-labelled demonstration datasets
    templates/        starter sets per stack

Demonstration data lives only under `data/` and every file there carries a
`"_demo": true` marker. Nothing in `patterns/` reads from it at runtime.
