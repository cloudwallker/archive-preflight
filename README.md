# ArchivePreflight

### Inspect ZIP names before extracting

English · [简体中文](README_ZH.md)

[Try the workflow](#try-the-workflow) · [Policies](#policies-and-host-coverage) · [Development](#development-and-distributions)

ArchivePreflight reviews ZIP filenames before extraction. It preserves original filename bytes and encoding candidates, explains Windows/macOS/Linux policy collisions, and produces an editable offline report. An explicit, revalidated plan enables bounded extraction into a new native-owned directory.

![Editable offline ZIP name report, using synthetic demo data](docs/images/report-desktop.png)

Synthetic demo: review original byte evidence and edit a naming draft.

**中文简介：审阅 ZIP 原始名称与编码候选，解释跨平台碰撞，验证改名计划并进行受限提取。**

## Try the workflow

Python 3.12 or newer, standard-library runtime, no runtime package dependencies:

```sh
python -m pip install .
archive-preflight demo --output demo-output
```

Open `demo-output/report.html`. Search entries, inspect byte and candidate evidence, choose keep/rename/skip, and export a naming draft. The demo includes case collisions, reserved names, trailing dots, NFC/NFD names, a long path, traversal, a Unix link, and a highly compressible file. Its four policy JSON reports explain configuration differences. Exit 1 is expected for findings.

For your own ZIP:

```sh
mkdir .archive-preflight-local
archive-preflight inspect sample.zip --target windows --target-root X:/delivery --html .archive-preflight-local/report.html --report-json .archive-preflight-local/report.json --plan .archive-preflight-local/draft.json
archive-preflight validate-plan sample.zip --mapping .archive-preflight-local/reviewed-draft.json --output .archive-preflight-local/validated.json
archive-preflight extract sample.zip --plan .archive-preflight-local/validated.json --accept-plan PLAN_ID_FROM_VALIDATED_JSON --output .archive-preflight-local/new-output --result-json .archive-preflight-local/result.json
```

Open `.archive-preflight-local/report.html` and save the exported draft as `.archive-preflight-local/reviewed-draft.json`. The root is hypothetical: only its length is retained. Replace the plan ID placeholder with the current `planId`. Review unresolved length/encoding findings before validation. HTML exports a **draft**; it runs no platform rules or extraction. Changing names or encoding requires `validate-plan` again. `extract --seconds 0.5` lowers the whole extraction request budget; the default is 60 seconds, and only finite values greater than zero and at most 60 are accepted.

Reports and output directories must be new. Extraction reports are written outside the output tree. `--json` writes strict JSON to stdout and diagnostics to stderr. Exit codes: 0 complete/verified, 1 findings, 2 invalid input, 3 incomplete/unsupported/limits/stale, 4 extraction failure. A verified extraction lists any skipped entries.

## Policies and host coverage

| Policy | Meaning |
| --- | --- |
| `windows-win32-conservative-v1` / `windows` | Conservative Win32 names and UTF-16 budgets; casefold is an approximation |
| `macos-apfs-ci-advisory-v1` / `macos` | Case-insensitive delivery policy, normalization and casefold approximations |
| `macos-apfs-cs-advisory-v1` | Case-sensitive delivery policy, normalization approximation |
| `linux-posix-bytes-v1` / `linux` | Exact UTF-8 byte policy; normalization/casefold are advisories |

Policies are versioned comparison rules, with runtime Python/Unicode/zlib versions in each report. Native NTFS/APFS comparison tables and mount-specific Linux casefold behavior require host testing.

| Host | Current local evidence |
| --- | --- |
| Windows local NTFS | Source CLI and native handle ownership tests; standalone build and delivery checks described in [support matrix](docs/SUPPORT.md) |
| Linux/macOS | Policy analysis runs on Windows; native POSIX extraction awaits an actual host/CI run |
| UNC/network/reparse ancestors | Extraction fails closed |

## Offline evidence and extraction scope

Preflight reads the bounded central directory and necessary EOCD/ZIP64 search windows. It reads no member streams, inflates no data and computes no body hash. A short ZIP's tail search window can physically overlap compressed bytes. `archiveId` binds metadata, while extraction verifies local headers, complete STORED/raw DEFLATE streams, actual sizes, CRC and output SHA-256.

The single HTML file has inline assets, a restrictive CSP, no network/server/telemetry and visible escapes for controls/Bidi. JSON preserves exact original byte evidence; reports can contain sensitive archive names and should be reviewed before sharing. Absolute local roots, ZIP comments and body contents are excluded from reports.

Extraction supports ordinary files/directories, methods 0 and 8, into a nonexistent output directory with no overwrite, links, permissions or metadata copying. Limits are 10,000 files/directories, 256 MiB per file, 1 GiB total and 60 seconds; preflight limits include 8 GiB archive, 16 MiB directory and 50,000 entries. Existing safety and ownership checks determine host eligibility. Controlled failure cleans only verified owned objects. Forced termination leaves ownership unknown, preserves the tree and reports unavailable actual counts as null. Inspect the named directory locally before manual removal.

The threat model covers untrusted ZIP content and automatic escape/overwrite/resource expansion. Administrator or hostile same-account modification of trusted parents/source, malware detection and authentication of archive origin require separate controls.

## Development and distributions

```sh
python -m unittest discover -v
python fixtures/build_fixtures.py --output fixtures/generated
python -m pip install --require-hashes -r requirements-build.txt
python scripts/build_windows.py
```

The 18 synthetic ZIP fixtures are generated locally by the command above; their builder and independent acceptance facts are included in the source repository.

Windows x64 builds use PyInstaller 6.22.3 and the exact hashed development lock. `dist/archive-preflight.exe` bundles its Python runtime and assets. Source wheels keep zero runtime dependencies. Git ignores `build/`, `dist/`, `demo-output/` and the private workflow directory `.archive-preflight-local/`, along with `.env`/`.env.*` except the shareable `.env.example` template. Reports saved elsewhere require review before staging. Browser checks use Playwright 1.58.2: `npm ci`, `npx playwright install firefox`, then `node tests/report.browser.cjs REPORT_HTML EVIDENCE_DIRECTORY INJECTION_HTML`. CI recipes are future runs until their jobs actually execute.

Original code: MIT, copyright cloudwallker. The executable also includes third-party components under their respective licenses; see [third-party notices](THIRD_PARTY_NOTICES.md). [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md).

Adoption interviews and cross-platform extractor comparisons are research work; actual local observations are separated from untested platforms in the support matrix.
