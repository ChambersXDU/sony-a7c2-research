# Uncompressed 64-bit WBI2 snapshots

This contribution follows the ILCE-7CM2 2.01 validation in commit
`0bf0915dce843e398b23d11e2f3d2e97086093e0`. The initial patch is preserved
on `feat/ilce-7cm2-support`; WBI2 work is on `feat/wbi2-unpack`.

## Evidence and format

Sony's [ILCE-7CM2 Ver.2.01 source distribution](https://oss.sony.net/Products/Linux/DI/ILCE-7CM2_Ver201.html)
links to the kernel package used to cross-check the binary structure:
`https://prodgpl.blob.core.windows.net/download/DI/20251111_ILCE-7CM2_Ver.2.01/linux-kernel.tar.gz`.
The complete package was downloaded and its SHA-256 is
`99a6f717659a87a60fd92475edcfe734f73617874650c6aa1d28ca71e2140d3d`.

References in that package are `include/linux/warmboot.h` (header and section
layout/flags), `kernel/power/wbi_raw.c` (raw sections and metadata placement),
`include/linux/wbi.h` (checksum seed), and `kernel/power/warm.c`
(checksum algorithm and original/stored sizes). No kernel source or firmware
binary is bundled with this patch; the Python reader independently describes
the binary format.

For this AArch64 layout, the header is 88 bytes, padded to a 512-byte sector;
section descriptors are 64 bytes. The section table starts at
`sectorSize + dataSize`, rather than at the end of the input. A zero section
stores no payload but has an original length that must be restored.
Metadata checksums XOR the first six little-endian 64-bit words with seed
`0x0f0f0f0f`. The reader checks every descriptor and both length totals
before returning sections. Zero output is generated in bounded chunks.

## Real ILCE-7CM2 2.01 results

Input `nflasha5` is 267,171,648 bytes; SHA-256:
`db3730c8dbb2de71cfb7a66c343ba8e752e0f374a3a4104196ceac1e9d1b08dc`.
It came from the official BODYDATA.DAT documented in the preceding validation.

- Header flags: 0; data version: `0x20060224`; sector size: 512.
- Sections: **1,181**, comprising 1,131 raw and 50 zero-filled sections.
- Stored section bytes: **266,833,920**; restored bytes: **292,888,576**.
- Explicit zero-filled bytes: **26,054,656**.
- All 1,181 metadata checksums passed; there are no overlapping saved ranges.
- Section table offset: `0xfe79200`; table end: `0xfe8b940`.
  An additional 261,632 input bytes are outside the declared image and are
  ignored. Their purpose has not been established.

The sparse image starts at physical address `0x400001000`, ends at
`0x422000000` (exclusive), and has logical size **570,421,248 bytes**.
SHA-256: `00899f2277c52a09fe138c4b28140d2556680fb837aa682e97171e15f9516687`.
The address map also records the resume vector, `0x4004a67f0`.
An independent script read the original section table using `struct.unpack`,
then compared every saved range with the exported image; all ranges matched.

## Use and tests

Install the existing dependencies, then run:

```sh
python fwtool.py unpack -f /tmp/sony-fw/BODYDATA.DAT -o /tmp/sony-fw/new-output
python fwtool.py unpack -f /tmp/sony-fw/unpacked/firmware.tar_unpacked/0700_part_image/dev/nflasha5 -o /tmp/sony-fw/wbi2-sections
python tools/wbi2_memory.py -f /tmp/sony-fw/unpacked/firmware.tar_unpacked/0700_part_image/dev/nflasha5 -o /tmp/sony-fw/wbi2-memory
python -m unittest discover -s tests -v
SONY_A7C2_FW=/tmp/sony-fw/BODYDATA.DAT python -m unittest tests.test_a7c2_e2e -v
```

The snapshot exporter requires a new output directory and refuses overwrite.
It checks available disk space, rejects overlapping ranges, and stages output
in a temporary directory before publishing it. The raw CLI extraction checks
space and duplicate output addresses. Each section filename retains its full
64-bit physical address; `memory.yaml` records physical and virtual addresses.
For the flat image, physical address equals `baseAddress + file offset`.

Locally the 32-test suite passed with the real firmware supplied. Without it,
31 tests passed and the one real-firmware test skipped. WBI2 tests use small
synthetic images to cover 64-bit addresses, stored/zero sections, zero first
sectors, trailing bytes, metadata corruption, truncation, unsupported flags,
invalid sizes, WBI1 regression, encrypted DAT/tar/WBI2 recursion, sparse gaps
and overwrite/overlap rejection.
The firmware test additionally compares all restored sections with the original
raw table, independently of the WBI2 reader, and runs the sparse exporter to
check the full image digest and every address-map entry. No proprietary
fixtures are used.

## Limits

Only the observed **uncompressed 64-bit** variant is supported. Compression,
LZ77-compression and payload-checksum flags are rejected explicitly. Section
metadata XOR checksums are checked, but the real header disables payload
checksums; metadata checks do not authenticate the memory contents.

Uncaptured address gaps read as zero in the sparse file. They are distinct from
explicit zero sections and must not be treated as proof of the original RAM
contents. The map defines the captured ranges; this is not a complete RAM dump
or an image that can be flashed back to a camera. WBI2 in other firmware/models
and compressed WBI2 remain unverified. No extracted code was executed.
