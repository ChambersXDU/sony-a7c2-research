# ILCE-7CM2 2.01 kernel symbols and captured-text comparison

This work follows WBI2 commit `b8cadd63a31bc12ae90c13f6af53a13c17a99830`.
It recovers **41,265 symbols** from the actual `nflasha3` kernel Image and
exports an ELF for static analysis, with no firmware execution or hardware use.

## Inputs and format evidence

The official update and source-package provenance are recorded in
[the firmware validation](ilce-7cm2-2.01.md) and [WBI2 validation](wbi2.md).
`nflasha3_unpacked/vmlinux.bin` is **6,610,952 bytes**, SHA-256
`620a6a3c2b4f09a3696f2fbf06bab98b49be5eaad6bdb366a1f33319fcb6e9d2`.
Its header identifies a little-endian AArch64 Linux Image; its banner reports
Linux `4.9.337-scel+`, built on 2025-10-11. It is not an ELF file.

Sony's [official 2.01 kernel source distribution](https://oss.sony.net/Products/Linux/DI/ILCE-7CM2_Ver201.html)
supplies `scripts/kallsyms.c`, `kernel/kallsyms.c`, and the ARM64 linker script.
These define the compressed names, token dictionary, marker offsets and
base-relative addresses. The tool independently describes this binary format;
no kernel source or firmware data is included in the repository.

The observed profile uses unsigned 32-bit offsets, a 64-bit relative base and
256-byte table alignment. All compressed names, 162 markers, token boundaries,
address ordering and boundary/banner anchors were checked. Recovered layout:

| Table | Image offset |
| --- | --- |
| Address offsets | `0x482500` |
| Relative base | `0x4aaa00` |
| Symbol count | `0x4aab00` |
| Compressed names | `0x4aac00` |
| Markers | `0x521d00` |
| Token table | `0x522300` |
| Token index | `0x522700` |

## Address and resume-path observations

The linked `_text` address is **`0xffffff8008080000`**. Six independent
64-byte anchors in the kernel Image agree with captured WBI2 bytes at physical
base **`0x400080000`**. For this kernel mapping only:

```text
physical address = 0x400080000 + (linked address - 0xffffff8008080000)
```

WBI2's resume vector `0x4004a67f0` maps exactly to
`cxd90057_resume_ssboot`, linked address `0xffffff80084a67f0`, Image offset
`0x4267f0`. Apple LLVM 17 disassembled the derived ELF with the recovered names.
The raw instructions and Sony's `drivers/udif/mach-cxd900xx/resume.S` agree:

- `cxd90057_resume_profile` selects state 1.
- `cxd90057_resume_optimize` selects state 2.
- `cxd90057_resume_ssboot_pre` selects state 3.
- `cxd90057_resume_ssboot` selects state 4.

Each enters a shared path that calls `cxd900xx_init`, stores the state into
`cxd90057_ssboot_stat` (alias `cxd90057_suspend2`), then continues through
`v8_boot`, `cxd900xx_smp_init` and `cpu_resume`. The state values match
`include/linux/ssboot_stat.h`. This is static source/binary correspondence,
not observation of a camera executing the path.

Comparing the complete **4,390,912-byte** `.text` range with captured memory
found 1,004 identical and 68 different 4-KiB pages, with no uncaptured pages.
There are **147 changed instruction words**: 131 are verified jump/NOP
transitions at static-key table sites (including branch-target validation),
and 16 fall within alternatives patch sites. The original Image contains
361 jump-table and 2,244 alternatives records. Alternatives-site correlation
does not establish replacement semantics or prove how/when the code changed.

## Reproduction and outputs

Use the existing Python environment and previously unpacked official firmware:

```sh
.venv/bin/python tools/kernel_symbols.py \
  -f /tmp/sony-fw/unpacked/firmware.tar_unpacked/0700_part_image/dev/nflasha3_unpacked/vmlinux.bin \
  --snapshot /tmp/sony-fw/unpacked/firmware.tar_unpacked/0700_part_image/dev/nflasha5 \
  --physical-base 0x400080000 -o /tmp/sony-fw/new-kernel-analysis
.venv/bin/python -m unittest discover -s tests -v
SONY_A7C2_FW=/tmp/sony-fw/BODYDATA.DAT .venv/bin/python -m unittest discover -s tests -v
```

The snapshot arguments are optional but must be supplied together. The tool
verifies the proposed physical base using byte anchors before comparing text.
It refuses existing output directories and stages files before publishing.
Outputs are `kernel.elf`, `System.map`, `symbols.json`, `analysis.json`, and
optionally `snapshot-comparison.json`. Keep them outside Git.

The ELF preserves every original Image byte and all recovered names/addresses.
Its SHA-256 is
`996fae4ce434445e28e2d7d8ca8775f3d40d871c2c6a48fc754b822082b29e6b`.
It is a **derived analysis container**, not the original build ELF: original
debug information, relocations, symbol sizes and detailed sections were not
recovered. Region boundaries come from symbols; permissions are annotations,
and `.init` groups mixed init text/data. `.bss` describes the linked uninitialized
region, not captured RAM. ELF physical-address fields do not establish a
physical mapping; use the separately validated snapshot comparison.

## Coverage and limits

Ten synthetic tests cover multiple markers, alias/local/weak symbols, ELF
structure and byte preservation, malformed tables/headers, signed-offset
rejection, output protection, snapshot anchors and patch classification.
The real-firmware test also recovers all 41,265 symbols after a fresh unpack,
checks the ELF bytes, verifies the resume symbol and compares captured text.
Locally all 42 tests passed with the firmware supplied. Without it, 41 passed
and one real-firmware test skipped. No new project dependency is needed.

This reader supports the observed Linux 4.9 little-endian AArch64,
unsigned-base-relative, 256-byte-aligned profile. Absolute-address tables,
signed absolute-per-CPU encoding, newer long-name layouts, other alignments and
other firmwares remain unverified. Structural validation is not authentication;
plausible altered symbols or bytes can remain structurally valid. The ELF
contains original boot-image code; the report describes captured differences.
