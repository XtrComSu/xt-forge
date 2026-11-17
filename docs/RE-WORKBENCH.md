# Reverse Engineering Workbench (`re`)

Reversing software cleanly with an agent usually hits two walls: massive decompiler outputs flood the prompt, and every time the binary gets re-analyzed in a new chat, the analyst's symbol renames and comments vanish.

XT-Forge 0.4.0 keeps everything deterministic, content-addressed, and gentle on context tokens.

![Reverse Engineering Overlay and Container Workflow](assets/re-workbench.gif)

## 1. Stateful Annotation Overlays (`re annotate`)

Instead of mutating original executables on disk or locking notes inside a proprietary database format, `re annotate` hashes the binary (`sha256`) and stores renames, inline comments, and C type declarations inside `$XT_HOME/re_overlay.db`.

```sh
# Rename an unnamed subroutine at RVA 0x1200
./bin/xtforge re annotate rename ./sample.bin --rva 0x1200 --orig sub_1200 --name decrypt_cfg

# Attach an analyst note and C signature
./bin/xtforge re annotate comment ./sample.bin --rva 0x1200 --comment "RC4 key schedule loop"
./bin/xtforge re annotate type ./sample.bin --rva 0x1200 --type-decl "int decrypt_cfg(uint8_t *buf, size_t len)"

# List saved overlays for this binary
./bin/xtforge re annotate list ./sample.bin --json

# Export portable scripts for external disassemblers
./bin/xtforge re annotate export ./sample.bin --format r2
./bin/xtforge re annotate export ./sample.bin --format ghidra
```

Whenever you run `xtforge re cfg` or `xtforge re xrefs` against the same binary, XT-Forge checks `re_overlay.db` and merges your saved renames and comments directly into the output blocks and call references.

## 2. Fast Byte-Level Triage in Rust

For packed samples, malware triage, or Mach-O/ELF/PE executables, heavy parsing runs directly in native Rust:

* **Per-block Shannon entropy:** Spot encrypted sections (`>= 7.2` bits/byte) before opening a disassembler:
  ```sh
  ./bin/xtforge re entropy ./sample.bin --block 4096 --count 32 --json
  ```
* **Single-byte XOR string recovery:** Scans all 255 non-zero keys and sorts candidate decoded strings by length so real URLs and C2 tokens rise above short false positives:
  ```sh
  ./bin/xtforge re strings ./sample.bin --xor --min-len 6 --json
  ```
* **Mach-O header parsing:** Identifies 32/64-bit endianness, CPU architecture (`x86_64`, `arm64`), and load command count natively in Rust alongside existing ELF and PE parsers:
  ```sh
  ./bin/xtforge re info ./macos_tool --json
  ```

## 3. Electron `.asar`, Network Captures, and Android `.apk`

Real reverse engineering engagements rarely consist of a single stripped C binary. Go's `xtforge-hub` (with pure-Python stdlib parity) unpacks modern application containers directly:

### Electron ASAR Archives

```sh
./bin/xtforge re asar ./app.asar --limit 100 --json
```

Reads Chromium's Pickle header cleanly, flags embedded source maps, and lists bundled files without running `npm` or Electron.

### HAR and Fiddler SAZ Network Captures

```sh
./bin/xtforge re netcap ./session.har --limit 50 --json
```

Summarizes HTTP methods, status codes, and API endpoints while **masking sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`) by default**. Pass `--reveal` only when you explicitly need unmasked values.

### Android APKs

```sh
./bin/xtforge re apk ./target.apk --json
```

Extracts `classes*.dex` inventories, native `lib/<abi>/*.so` libraries, and declared `android.permission.*` strings from the package without needing a heavy JVM startup. If `jadx` or `apktool` is present, you get full decompilation compatibility too.

## 4. Headless Decompilation and Confirm-Gated Tracing

When you have `rizin`, `r2`, or `objdump` available locally:

```sh
./bin/xtforge re decompile ./sample.bin --symbol decrypt_cfg
```

Dynamic instrumentation (`frida-trace` or `gdb`) stays locked by default and requires both an active permission mode outside `explore` and a single-use confirm token:

```sh
./bin/xtforge re trace ./sample.bin --preset api_trace --dry-run
```
