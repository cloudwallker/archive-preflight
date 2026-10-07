# Third-party notices / 第三方许可

Original ArchivePreflight source is MIT, copyright 2026 cloudwallker. The source wheel has no third-party runtime package dependency.

The Windows standalone executable includes the project's MIT `LICENSE`, CPython 3.12.14, native libraries and the PyInstaller bootloader. Each component keeps its own terms. `licenses/CPython/LICENSE.txt` covers CPython and its included historical/Microsoft notices; separate native library licenses are listed below.

| Frozen component | Version/source | License file |
| --- | --- | --- |
| libcrypto-3-x64.dll / libssl-3-x64.dll; _hashlib / _ssl | OpenSSL 3.5.8 | `licenses/OpenSSL/LICENSE.txt` (Apache-2.0, original OpenSSL tag text) |
| libffi-8.dll; _ctypes | libffi 3.4.2, CPython Windows fork commit `16fad4855b3d8c03b5910e405ff3a04395b39a98` | `licenses/libffi/LICENSE.txt` (MIT, exact fork text) |
| _bz2 | bzip2 | `licenses/bzip2/LICENSE.txt` |
| _lzma | liblzma | `licenses/liblzma/LICENSE.txt` (0BSD) |
| _decimal | libmpdec | `licenses/mpdecimal/LICENSE.txt` |
| pyexpat | Expat | `licenses/expat/LICENSE.txt` (MIT) |
| Built-in zlib | zlib | `licenses/zlib/LICENSE.txt` |

The reference runtime is Astral python-build-standalone's [20260825 Windows x64 CPython 3.12.14 release](https://github.com/astral-sh/python-build-standalone/releases/tag/20260825). The official full archive supplies metadata and supplemental license texts; the stripped archive supplies reference DLL images. Runtime DLLs carry an OpenAI Authenticode signature. Provenance checks retain their complete hashes and compare PE images after excluding only checksum/certificate-directory/certificate bytes; signed files are not claimed to have the unsigned archive's whole-file hash. Exact component hashes, sources and license hashes are recorded in `licenses/NATIVE_COMPONENTS.json`. The Windows build's fixed libffi fork is distinct from the build download table's Unix libffi version. Other native extension code remains under the CPython terms; Microsoft runtime/UCRT binaries retain the Microsoft terms in the bundled CPython notice.

Build tools are pinned and their distribution license files are preserved verbatim under `licenses/`: PyInstaller 6.22.3 (GPL-2.0 with bootloader exception, plus specified Apache-2.0 files), pyinstaller-hooks-contrib 2026.8, altgraph 0.17.5, packaging 26.3, pefile 2024.8.26, pywin32-ctypes 0.2.3, setuptools 84.0.0 and wheel 0.45.1. See each exact copied license for terms and component coverage. Unmodified PyInstaller's bootloader exception permits distribution of generated bundles under the application's license subject to dependency licenses: [official explanation](https://pyinstaller.org/en/v6.22.3/license.html).

The `licenses/` directory and this notice are embedded in the executable and included in the source distribution. Tooling licenses identify their original authors; those public legal attributions remain intact.
