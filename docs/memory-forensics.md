# A7C2 2.01 memory forensics

WBI2 is a partial preparation-camera snapshot distributed in the firmware,
not a capture of the user's camera. This implements the offline analysis
suggested in [fwtool PR #52](https://github.com/ma1co/fwtool.py/pull/52#issuecomment-5998130923).
Input provenance and hashes are in [WBI2](wbi2.md) and [kernel symbols](kernel-symbols.md).

## Format choice

| Format | Physical addresses and absent ranges | Decision |
| --- | --- | --- |
| Flat/padded raw | Requires an external map; file holes read as zeros | Keep the existing export, avoid it for automatic forensics |
| LiME v1 | Each captured range has 64-bit start/end addresses; gaps have no payload | Selected; Volatility loads it without a custom format plugin |
| ELF64 core | PT_LOAD can describe captured physical ranges; require filesz=memsz, omit gaps | Viable, but adds ELF machinery without improving this analysis |
| AVML | Volatility also has an AVML layer | Unnecessary alternative; not generated or tested here |

References: [LiME format](https://github.com/jtsylve/LiME#usage),
[Volatility LiME layer](https://volatility3.readthedocs.io/en/latest/volatility3.framework.layers.lime.html),
[ELF layer](https://volatility3.readthedocs.io/en/latest/volatility3.framework.layers.elf.html).
The inspected ELF loader accepts PT_LOAD only when filesz equals memsz.
No ELF core or CPU register notes are fabricated by this change.

The deterministic `memory.lime` is **292,926,368 bytes**, SHA-256
`3d5292bd82685355ff5538e1b8349dd6408d6196880741132138158a9efabb14`.
It preserves all **1,181** sections and **292,888,576 captured bytes**.
Volatility rejects reads in all **1,140 gaps** within the captured span
(`0x400001000`–`0x422000000`, end exclusive; 277,532,672 absent bytes).
These gaps, and addresses outside the span, are unknown. They do not define
the complete RAM extent. The 50 explicit WBI2 zero sections remain readable
zero data; `memory.yaml` preserves their origin and the WBI2 virtual addresses.

## Actual analysis results

Tested with Python 3.9.6, Volatility **2.28.0**, dwarf2json **0.9.0**,
Clang **21.1.2**, GNU make **3.81**, on macOS ARM64:

- The **unmodified native CLI** `banners.Banners` finds Linux
  `4.9.337-scel+` at physical **`0x4004b0090`**, matching `linux_banner`.
- Volatility's existing **`ABCKmsg.run_all`** decodes **573 records / 672
  output lines**. The static buffer is at `0xffffff80086e7538`, length
  131,072; first/next indices are 0 / 37,212, sequences 0 / 573.
- Captured log messages include four activated processors and
  `WBI: sections real:1181, estimate:2220`. The last record is
  `WBI: count_sections_p2:1181, 71506, 11764a00(11764a00)`.
  71,506 × 4,096 equals the independently restored byte count.
- Volatility's existing **`PsList.list_tasks`** returns **286 reachable
  tasks**, including PID 1 `init2` and PID 2 `kthreadd`. An independent raw
  walk verifies closure at `init_task`, every reciprocal next/prev link,
  unique PIDs, and every returned PID/TGID/comm. Checked `task_struct`
  offsets: tasks 648, pid 904, tgid 908, comm 1336; candidate size 2,944.

The last two results use the framework API through `tools/volatility_wbi2.py`,
with explicit address layers and partial ISFs. They are **not successful
native Linux CLI automagic/plugin runs**: this Volatility version's Linux
stacker and Kmsg/PsList module requirements target Intel32/Intel64.
The native `linux.kmsg.Kmsg` command was attempted and reported unsatisfied
kernel layer/symbol requirements. No Intel architecture is impersonated,
and no upstream parsing algorithm is replaced.

The adapter exposes captured kernel-image and ARM64 direct-map aliases only.
Six original Image byte anchors validate physical base `0x400080000`;
captured `memstart_addr=0x400000000` and `kimage_voffset=0xffffff7c08000000`
agree with Sony's `arch/arm64/include/asm/memory.h`. Reads never request padding.
Ring lengths, sequence counts and wrap bounds are checked before native parsing.

## Reproduce

Use the previously unpacked official firmware. Keep generated data outside Git.
`KERNEL_SOURCE` is the official 2.01 `linux-kernel.tar.gz` linked from
[Sony's source page](https://oss.sony.net/Products/Linux/DI/ILCE-7CM2_Ver201.html).
The profile builder enforces the documented source and Image hashes.

```sh
.venv/bin/python -m pip install -r requirements-forensics.txt
git clone --depth 1 --branch v0.9.0 https://github.com/volatilityfoundation/dwarf2json.git /tmp/dwarf2json
(cd /tmp/dwarf2json && go build)
PART=/tmp/sony-fw/unpacked/firmware.tar_unpacked/0700_part_image/dev
KERNEL_SOURCE=/tmp/sony-fw/oss/linux-kernel.tar.gz
CLANG=/opt/homebrew/opt/llvm/bin/clang  # or a Clang with AArch64 ELF support

.venv/bin/python tools/wbi2_lime.py -f "$PART/nflasha5" -o /tmp/a7c2-lime
.venv/bin/vol -q --offline -f /tmp/a7c2-lime/memory.lime -r json banners.Banners
.venv/bin/python tools/kernel_printk_profile.py --source "$KERNEL_SOURCE" \
  --kernel "$PART/nflasha3_unpacked/vmlinux.bin" --clang "$CLANG" \
  --dwarf2json /tmp/dwarf2json/dwarf2json --tasks -o /tmp/a7c2-profile
.venv/bin/python tools/volatility_wbi2.py -f /tmp/a7c2-lime/memory.lime \
  --kernel "$PART/nflasha3_unpacked/vmlinux.bin" --profile /tmp/a7c2-profile \
  -o /tmp/a7c2-analysis

SONY_A7C2_FW=/tmp/sony-fw/BODYDATA.DAT SONY_A7C2_SOURCE="$KERNEL_SOURCE" \
  SONY_A7C2_CLANG="$CLANG" SONY_DWARF2JSON=/tmp/dwarf2json/dwarf2json \
  .venv/bin/python -m unittest discover -s tests -v
```

All exporters require new directories. Omitting `--tasks` builds only the
small printk profile and avoids full source-tree/header preparation.
Outputs include `analysis.json`, `kmsg.json`, optional `tasks.json`, and
profile provenance/build logs. The test unpacks BODYDATA.DAT afresh, compares
every LiME payload against the raw WBI2 table, tests every gap through
Volatility, runs the native banner CLI, and regenerates both DWARF profiles.
The full **55-test suite passed** with the real firmware and source/tool
variables above; it includes all existing WBI1, WBI2 and symbol regressions.
Without firmware the end-to-end test skips; without optional Volatility
the framework tests skip. Core fwtool dependencies and raw/WBI1 behavior remain.

## Type recovery and limits

The printk builder extracts the actual `printk_log` declaration and scalar
declarations from Sony `kernel/printk/printk.c`, compiles AArch64 DWARF4, and
uses dwarf2json plus recovered addresses. There are two `log_buf` names in
kallsyms: the initialized `d` symbol is selected explicitly; the unrelated
`b` symbol must not overwrite it. This is newly generated partial DWARF,
not recovered original debug information.

The task profile uses official `sched.h`/`nsproxy.h` with generated headers
from `cxd90057_set_defconfig` and `make prepare0`; no replacement kernel is
executed. The original shipping `.config` is unavailable and IKCONFIG is
absent. A full `make prepare` attempt failed in old VDSO `gettimeofday.S`
(`too many positional arguments`) with current Clang; `prepare0` avoids that
unneeded assembler step. Sony's original GCC 6.4 toolchain is not installed.
The candidate configuration yields consistent used task fields, but this
does not validate every generated type, credential, timestamp or memory map.

No ARM64 page-table walker, process address-space translation, hidden-task
scan, open-file analysis, network analysis, or device execution is claimed.
Logs describe the distributed snapshot's recorded preparation history.
Neither structural consistency nor metadata checks authenticate that history.
