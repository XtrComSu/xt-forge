<h1>{{PROJECT_NAME}}</h1>

Describe the artifact, version, and question this repository investigates.

![XT-Forge-SYS inspecting the included demo fixture](docs/assets/showcase.gif)

## Findings

| ID | Observation | Evidence |
| --- | --- | --- |
| DEMO-001 | The demo returns a fixed value for zero and applies XOR to other inputs. | [Reproduction and evidence](docs/REPORT.md#demo-001) |

## Reproduce the demo

With XT-Forge's native hub and a C compiler available, run the following from the repository root.

```sh
cc -O0 -o demo-binary.exe fixtures/demo.c
xtforge re overview ./demo-binary.exe --json
xtforge re decompile-native ./demo-binary.exe --target demo_transform --json
```

Use `gcc` or `clang` in place of `cc` if needed. On Mach-O, use `--target _demo_transform` for the leading underscore in the symbol name. The [demo source](fixtures/demo.c) supplies the expected behavior. Replace the sample findings and showcase GIF with evidence from your own project as it develops.

## Commit activity

![Daily commit counts from local Git history](docs/assets/activity.svg)

Run `python scripts/update_activity.py` after committing research updates. The chart shows 52 weeks of UTC author dates in the history reachable from your current commit. Use a full clone of the branch you want to report on. Commit the generated SVG to display it in the README.

See the [contribution guide](CONTRIBUTING.md) for reporting observations and attaching evidence.
