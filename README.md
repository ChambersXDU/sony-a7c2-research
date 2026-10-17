# Sony A7C II (ILCE-7CM2) Firmware Reverse Engineering

**Sony Alpha 7C II / A7C2 firmware research** for the **BIONZ XR (CXD90057)** platform. This repository documents validated **ILCE-7CM2 firmware 2.01** extraction, **WBI2 warm-boot memory snapshot** recovery, **LiME memory forensics with Volatility 3**, **AArch64 Linux kernel symbol recovery**, and initial `appFw.so` application analysis.

It extends [ma1co/fwtool.py](https://github.com/ma1co/fwtool.py) using [David Buchanan's CXD90057 work](https://github.com/ma1co/fwtool.py/pull/52). Sony firmware decryption and the underlying `fwtool.py` are upstream work; the A7C II validation, WBI2 analysis tools, forensic exports, and related tests are documented here. **This is offline research, not a camera jailbreak, firmware patch, or feature-unlock tool.**

## Verified A7C II 2.01 findings

| Area | Evidence and result |
| --- | --- |
| Firmware unpacking | Official `BODYDATA.DAT` (version 2.01) validated with checksums; device ID `0x20030014`, CXD90057 `k8` |
| WBI2 snapshot extraction | **1,181 memory sections** totaling **292,888,576 captured bytes**, including 50 explicit zero sections |
| LiME export | Preserves physical addresses and leaves **1,140 uncaptured gaps unmapped** rather than treating them as captured zero memory |
| Volatility 3 forensics | Kernel banner confirmed; **573 kernel log records** (672 output lines) and **286 reachable tasks** recovered using existing parsers with a scoped ARM64 adapter |
| ARM64 kernel research | **41,265 kallsyms** recovered; Snapshot Boot resume vector correlated with `cxd90057_resume_ssboot` |
| Application analysis | Static `appFw.so` initialization entry and callback chain identified |

The snapshot is a **partial memory image from Sony's firmware preparation process**, **not** a live memory dump from a user's camera. Volatility's banner plugin runs unmodified; kernel log/task analysis uses an explicit ARM64 mapping and partial source-derived profiles, **not general Linux plugin/automagic support**. The documentation reports **55 local tests passed with the official firmware and source/tool dependencies**; CI runs the available automated tests without redistributing Sony firmware.

## Research documentation

- **[A7C II 2.01 firmware extraction and validation](docs/ilce-7cm2-2.01.md)** — official source, checksums, device metadata, and regression tests.
- **[WBI2 memory snapshot format and recovery](docs/wbi2.md)** — sector/section structures, memory map, verification, supported flags, and limitations.
- **[LiME and Volatility 3 memory forensics](docs/memory-forensics.md)** — real kernel logs, task traversal, addresses, exact tool versions, and reproduction commands.
- **[ARM64 Linux kernel symbol recovery](docs/kernel-symbols.md)** — `kallsyms`, symbolized analysis ELF, resume path, and code comparison.
- **[Sony appFw.so application initialization](docs/application-entry.md)** — static analysis of application entry points and callbacks.

## Quick start: offline firmware research

Use a legally obtained **official Sony A7C II (ILCE-7CM2) 2.01 `BODYDATA.DAT`** file; do not commit firmware binaries or extracted memory.

```bash
git clone https://github.com/ChambersXDU/sony-a7c2-research.git
cd sony-a7c2-research
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python fwtool.py unpack -f /path/to/BODYDATA.DAT -o /path/to/unpacked
```

After extracting `nflasha5`, create a physical-addressed LiME image:

```bash
.venv/bin/python tools/wbi2_lime.py -f /path/to/nflasha5 -o /path/to/a7c2-lime
```

For full reproducible Volatility analysis, including the additional `volatility3`, `dwarf2json`, and Sony GPL kernel-source requirements, follow [memory-forensics.md](docs/memory-forensics.md). The full firmware end-to-end test is opt-in; tests without the official local binary skip that case.

## Upstream fwtool.py compatibility

This repository retains the wider Sony firmware unpacking functionality of the original `fwtool.py` project, including older camera generations. The upstream [fwtool.py releases](https://github.com/ma1co/fwtool.py/releases/latest) are **not** releases of these additional A7C II research scripts.

### Supported firmware families
The following firmware types can be extracted:

* **"FDAT" firmware updates**
  * **CXD90057**: ILCE-7M4, ILCE-7CM2
  * **CXD90045**: ILCE-7M3, ILCE-6600, …
  * **CXD90014**: ILCE-7, ILCE-6000, ...
  * **CXD4132**: DSC-RX100, NEX-6, …
  * **CXD4120**
  * **CXD4115**: DSC-HX5V, NEX-3, SLT-A33, ...
  * **CXD4105 / MB8AC102**

* **"Msfirm" firmware updates**
  * **CXD4108**: DSC-T100, DSC-G3
  * **CXD4105**: HDR-SR1, HDR-UX1, DSC-G1

* **DSLR firmware updates**
  * DSLR-A230, DSLR-A700, ...

* **"ASH" firmware updates**
  * DSC-V1, DSC-F828, DSC-H2, ...

### General firmware unpacking
Run `python fwtool.py --help` for additional options.

### Unpack a firmware image ###
    fwtool unpack -f Update_ILCE_V100.exe -o outDir

The following files are accepted as input (*-f* flag):
* A Windows firmware updater executable (.exe file)
* The *FirmwareData.dat* file extracted from an updater
* A *BODYDATA.DAT* memory-card update (ILCE-7CM2 Ver. 2.01 verified)
* A firmware dump created by running `dd if=/dev/nflasha of=dump.dat` on the camera

See [ILCE-7CM2 Ver. 2.01 validation](docs/ilce-7cm2-2.01.md) for the official
download provenance, checksums, extraction results, limitations and tests.

### Extract a WBI2 memory snapshot ###
Uncompressed 64-bit WBI2 images are extracted into address-named section files
and `memory.yaml`, including zero-filled sections. They are also recognized
inside firmware archives. See [WBI2 validation](docs/wbi2.md) for supported
flags and the distinction between captured memory and uncaptured gaps.

    python fwtool.py unpack -f nflasha5 -o /tmp/wbi2-sections
    python tools/wbi2_memory.py -f nflasha5 -o /tmp/wbi2-memory

The second command creates a sparse `memory.img` and an address map in a new
directory. Extracted firmware and memory images must remain outside Git.

For memory forensics, export LiME instead: captured physical ranges remain
readable and absent ranges stay unmapped in Volatility 3.

    python tools/wbi2_lime.py -f nflasha5 -o /tmp/wbi2-lime

See [actual memory analysis](docs/memory-forensics.md) for the verified kernel
banner, structured kernel log and reachable task-list results, source-derived
partial DWARF profiles, optional dependencies and reproducible firmware tests.

### Recover kernel symbols for static analysis ###
The verified ILCE-7CM2 2.01 kernel Image retains 41,265 kallsyms entries.
The source-only tool exports a symbolized analysis ELF and can compare its
kernel text against the WBI2 snapshot, validating the physical-address mapping.
See [kernel symbol recovery](docs/kernel-symbols.md) for reproduction, the
identified Snapshot Boot entry, captured code differences and format limits.

    python tools/kernel_symbols.py -f vmlinux.bin -o /tmp/kernel-analysis

The output is a derived analysis container. Keep it and the full symbol map
outside Git; it is not a flashable image or a reconstruction of build debug data.

The [application entry observations](docs/application-entry.md) identify the
`appFw.so` initialization callback, thread wrapper and resource paths from
static instructions and ELF relocations in the same verified firmware.
