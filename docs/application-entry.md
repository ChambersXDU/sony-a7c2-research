# ILCE-7CM2 2.01 application entry observations

These observations use the official firmware verified in
[the extraction report](ilce-7cm2-2.01.md), after kernel-symbol recovery commit
`fb5d8c47c75755bc0e107c0bc69bd242c546c331`. They identify a bounded starting
point for application-framework analysis. No target code was executed.

## Target and address convention

`nflasha15_unpacked/lib/appFw.so` is a 99,960,744-byte AArch64 ELF shared library,
SHA-256 `2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b`.
Its dynamic symbol table has 950 entries. The defined exported function with
a recorded size is `Application_System_Init`, address `0x1796918`, size 264.
Addresses below are ELF-relative virtual addresses; the runtime load base is
unknown. LLVM 17 supplied the static disassembly.

## Observed initialization chain

The entry formats a message using its own dynamically relocated function
pointer, copies its argument into a 256-byte global buffer at `0x5f64630`,
and uses `AppConfig.so` when the argument is null. This string assignment does
not establish that a library is dynamically loaded.

At `0x17969fc`, it loads the pointer from GOT slot `0x5bbd118`.
That slot has `R_AARCH64_RELATIVE` relocation addend **`0x1796d60`**. It then
calls `0x36ec384` with that callback, a null second argument and index zero.
The wrapper reads the index-zero descriptor at `0x58db4b0` and transfers to
`0x36ec1c4`. The latter stores the callback and argument in a per-index
record, then calls the imported `osal_create_waitable_thread` at `0x36ec318`.
The descriptor's name pointer has relocation addend `0x519febe`, which points
to **`AppFw`**. The supplied OSAL thread trampoline at `0x36ec0ec` loads the
callback/argument pair from record offsets 8 and 16 at `0x36ec1a0`, moves
the argument to `x0`, and calls the callback through `blr x20` at `0x36ec1ac`.
This closes the static callback chain; actual thread execution is unobserved.

The callback at `0x1796d60` calls imported `uxengine_init2`, initializes
additional state through `0x1796a20`, and supplies these strings to named
UX/graphics/resource-manager imports:

| String address | Value | Observed use |
| --- | --- | --- |
| `0x370c945` | `/usr/share/app/` | `sys_setCurrentDirectory` |
| `0x370c955` | `/usr/share/app/area_check_data.dat` | `setCheckDataPath` |
| `0x370c978` | `/tmp/area_check_log.dat` | `setLogPath` |
| `0x370c990` | `global.xdb` | `setDatabase` |

Both `share/app/area_check_data.dat` and `share/app/global.xdb` exist in the
extracted `nflasha15` filesystem. After a 256-byte `strncmp` against
`AppConfig.so`, the default-config branch constructs a local application
object and reaches `0x1799e8c`. The other branch calls the imported
`app_adjchk_ui::main_loop()`. This establishes branch structure and call sites;
the meaning of the configuration argument, object methods and resource formats
remains unverified.

## Reproduce the bounded static inspection

Use an AArch64-capable LLVM objdump on your own extracted copy:

```sh
llvm-objdump -d --start-address=0x1796918 --stop-address=0x1796a20 appFw.so
llvm-objdump -d --start-address=0x1796d60 --stop-address=0x1796f18 appFw.so
llvm-objdump -d --start-address=0x36ec1c4 --stop-address=0x36ec478 appFw.so
llvm-objdump --section-headers --dynamic-syms --reloc appFw.so
```

Resolve pointer slots through `.rela.dyn` before following them. Do not treat
objdump's nearest exported-symbol labels as names for the otherwise stripped
functions. Do not execute the ELF to inspect it. The useful next questions are
the OSAL trampoline's callback ABI, the `0x1799e8c` application's event loop,
and the `global.xdb` resource format. Imported names alone do not prove runtime
behavior or describe hardware interfaces. Proprietary binaries and full
disassembly remain outside this repository.
