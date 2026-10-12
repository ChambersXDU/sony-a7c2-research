# fwtool.py #

A tool to unpack Sony camera firmware images, originally ported from [nex-hack's fwtool](http://www.personal-view.com/faqs/sony-hack/fwtool).

## Camera Compatibility ###
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

## Usage ##
Download the [latest release](https://github.com/ma1co/fwtool.py/releases/latest) (Windows or OS X) or clone this repository. Run `fwtool --help` for more information.

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
