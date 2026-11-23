# LZFSE decoder

These are the Go sources of `github.com/aixiansheng/lzfse` v0.2.4, unmodified
apart from dropping the upstream test file (it references test fixtures that are
not checked in). XT-Forge-SYS uses it in process to decompress LZFSE blocks
inside UDIF disk images, so DMG analysis needs no external `hdiutil` or
`lzfse` binary.

The upstream LICENSE is checked in beside this file. It is a public-domain
dedication (the Unlicense), so there is no attribution requirement, but the
provenance is recorded here anyway.
