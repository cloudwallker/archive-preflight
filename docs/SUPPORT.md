# Support and evidence / 支持与证据

| Capability | Local evidence | Unverified boundary |
| --- | --- | --- |
| ZIP/ZIP64 metadata, encodings and four delivery policies | Windows Python 3.12.14 / Unicode 15.0.0 / zlib 1.3.2, strict schemas and synthetic rule matrix | Native target comparison tables, arbitrary Linux mount options |
| Windows extraction | Local F: NTFS source CLI, real native ownership/links/CRC/deadline checks | UNC/reparse rejected; sandbox can deny ancestor handles, which fails closed |
| Linux/macOS extraction | POSIX backend source and CI recipe | No local POSIX native run yet |
| Offline report | Firefox 146.0.1 offline file: 20 checks of search/filter/candidate/editor/download, transformation evidence, confirmation state, keyboard and 390px layout | Other browser/assistive technology combinations |
| Windows x64 standalone | PyInstaller 6.22.3 / CPython 3.12.14 exe, system-only PATH: demo, inspect, validate, verified extraction, CRC cleanup, startup and observed-after-write deadlines; no remaining worker processes | Actual per-build hashes and commands belong to the build evidence, not a promise for future builds |
| Source wheel | Actual clean venv installation from wheel, zero Requires-Dist, installed CLI demo/inspect/validate/extract with verified size/CRC/SHA and unchanged source/sentinel | Python 3.9 is outside the declared >=3.12 runtime |

Policy analysis is distinct from native extraction. macOS CI/CS delivery profiles differ in configuration case comparison; NFC/casefold approximations remain explicitly labeled. Linux exact bytes retain separate case/normalization names, with advisory comparisons.

Current ZIP fixtures are original synthetic data. The tool does not scan malware or authenticate origin. Cross-platform 7-Zip/system extractor observations are limited to versions and cases actually run. Five-person interviews and adoption thresholds remain unexecuted research, separate from engineering acceptance.

The workflow configuration proposes future Windows/Linux/macOS runs. It counts as host evidence only after execution. A frozen startup timeout provides no proof of written output; an observed nonzero output prefix separately establishes that extraction had started. Both produce unknown final actual counts when there is no trustworthy final worker report.

Local extractor observation: Windows inbox bsdtar/libarchive 3.8.8 accepted and extracted the shared safe fixture. It listed the eight-risk ZIP (listing is not content validation). Extracting just the original demo's Report.txt/report.txt pair into a fresh controlled directory exited 0 and left a single report.txt with the second entry's bytes. No renaming was observed. Source ZIPs and the outside sentinel stayed unchanged. 7-Zip was unavailable; other extractor versions and hosts were not run. These cases do not assess competitors' broader workflows.
