# Reverse-engineering report

## Scope and provenance

Record the artifact name, version, source, SHA-256, format, architecture, and analysis tool versions. State what the analysis covers and what still needs a check.

## DEMO-001

**Observation**  
`demo_transform` returns 7 when its input is zero. Otherwise it returns the input XOR 21.

**Evidence**  
The [fixture source](../fixtures/demo.c) states the expected behavior. The structured result from XT-Forge-SYS identifies the conditional and both return expressions on supported builds.

**Reproduction**  
Follow the [README commands](../README.md#reproduce-the-demo). For a new finding, record the exact command, image or archive member, and function name or address. Link the relevant output or excerpt. Record whether the address is a virtual address, RVA, or file offset.

**Cross-check**  
Compare the recovered expressions with the fixture. For example, input 0 produces 7 and input 4 produces 17. Running the fixture executable checks those two cases and returns exit status zero when both pass.

## Open questions

Track hypotheses here until the relevant artifact, command, and output support them.
