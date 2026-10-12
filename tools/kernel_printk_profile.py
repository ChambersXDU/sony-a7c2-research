#!/usr/bin/env python3
"""Build partial A7C2 2.01 printk/task ISFs from Sony source and generated DWARF."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.kernel_symbols import recoverSymbols

SOURCE_SHA256 = '99a6f717659a87a60fd92475edcfe734f73617874650c6aa1d28ca71e2140d3d'
KERNEL_SHA256 = '620a6a3c2b4f09a3696f2fbf06bab98b49be5eaad6bdb366a1f33319fcb6e9d2'
PRINTK_SYMBOLS = {'log_buf': 'd', 'log_buf_len': 'd', 'log_first_idx': 'b',
                 'log_next_idx': 'b', 'log_first_seq': 'b', 'log_next_seq': 'b'}


def sha256(path):
 digest = hashlib.sha256()
 with Path(path).open('rb') as file:
  for block in iter(lambda: file.read(1024 * 1024), b''):
   digest.update(block)
 return digest.hexdigest()


def selectPrintkSymbols(symbols):
 selected = []
 for name, kind in PRINTK_SYMBOLS.items():
  candidates = [s for s in symbols if s['name'] == name and s['type'] == kind]
  if len(candidates) != 1:
   raise ValueError('Expected one %s symbol of kind %s' % (name, kind))
  selected.extend(candidates)
 return selected


def sourceTypes(archive):
 """Extract definitions, never compile a vendored approximation of printk_log."""
 with tarfile.open(archive, 'r:gz') as tar:
  def read(name):
   with tar.extractfile('linux-kernel/' + name) as file:
    return file.read().decode('utf-8')
  printk = read('kernel/printk/printk.c')
  integers = read('include/uapi/asm-generic/int-ll64.h')
  config = read('arch/arm64/configs/cxd90057_set_defconfig')
 for setting in ['CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y', 'CONFIG_LOG_BUF_SHIFT=17',
                 'CONFIG_ARM64_VA_BITS=39', 'CONFIG_ARM64_4K_PAGES=y']:
  if setting not in config.splitlines():
   raise ValueError('Unsupported Sony config: missing ' + setting)
 declaration = re.search(r'struct printk_log \{.*?\n;', printk, re.S)
 if declaration is None:
  raise ValueError('Missing source printk_log declaration')
 aliases = []
 for width in [8, 16, 32, 64]:
  typedef = re.search(r'typedef unsigned (?:char|short|int|long long) __u%d;' % width, integers)
  if typedef is None:
   raise ValueError('Missing unsigned integer typedef')
  aliases.append(typedef.group().replace('__u', 'u'))
 globals = []
 for name in PRINTK_SYMBOLS:
  variable = re.search(r'^static ((?:char \*|u32 |u64 )%s)(?: = [^;]+)?;' % name, printk, re.M)
  if variable is None:
   raise ValueError('Missing source declaration for ' + name)
  globals.append(variable[1] + ';')
 return '\n'.join(aliases + ['#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1',
  '#define __packed __attribute__((packed))', '#define __aligned(x) __attribute__((aligned(x)))',
  declaration.group(), 'struct printk_log force_type;'] + globals) + '\n'


def validateTypes(isf):
 """Check the compiled ABI needed by Volatility's existing ring-buffer reader."""
 try:
  log = isf['user_types']['printk_log']
  if log['size'] != 16 or isf['base_types']['pointer']['size'] != 8:
   raise ValueError('Unsupported printk ABI size')
  fields = log['fields']
  for name, offset in [('ts_nsec', 0), ('len', 8), ('text_len', 10), ('dict_len', 12),
                       ('facility', 14), ('flags', 15), ('level', 15)]:
   if fields[name]['offset'] != offset:
    raise ValueError('Unsupported printk field offset: ' + name)
  for name, position, length in [('flags', 0, 5), ('level', 5, 3)]:
   field = fields[name]['type']
   if field['kind'] != 'bitfield' or field['bit_position'] != position or field['bit_length'] != length:
    raise ValueError('Unsupported printk bitfield: ' + name)
  for name in PRINTK_SYMBOLS:
   if 'type' not in isf['symbols'][name]:
    raise ValueError('Missing DWARF symbol type: ' + name)
 except KeyError as error:
  raise ValueError('Incomplete printk ISF: ' + str(error)) from error


def buildTaskTypes(source, tmp, selected, clang, dwarf2json, make, hostcc):
 """Generate headers, then compile types only; no replacement kernel is built."""
 build = tmp / 'build'
 build.mkdir()
 with tarfile.open(source, 'r:gz') as tar:
  # The caller has already verified the official archive's exact SHA-256.
  tar.extractall(build)
 tree = build / 'linux-kernel'
 makeArgs = [make, '-C', str(tree), 'ARCH=arm64', 'CROSS_COMPILE=aarch64-linux-gnu-',
             'CC=' + clang, 'HOSTCC=' + hostcc, 'CLANG_FLAGS=--target=aarch64-linux-gnu']
 with (tmp / 'headers-build.log').open('w') as log:
  try:
   for target in ['cxd90057_set_defconfig', 'prepare0']:
    subprocess.run(makeArgs + [target], check=True, timeout=180, stdout=log, stderr=log)
  except subprocess.CalledProcessError:
   log.flush()
   sys.stderr.write((tmp / 'headers-build.log').read_text()[-8000:])
   raise
 (tmp / 'task-types.c').write_text('#include <linux/sched.h>\n#include <linux/nsproxy.h>\n'
                                 'struct task_struct init_task;\nstruct nsproxy force_nsproxy;\n')
 args = [clang, '--target=aarch64-linux-gnu', '-g', '-gdwarf-4', '-fstandalone-debug',
         '-ffreestanding', '-D__KERNEL__', '-include', str(tree / 'include/linux/kconfig.h')]
 for name in ['arch/arm64/include', 'arch/arm64/include/generated', 'include', 'include/uapi',
              'include/generated/uapi', 'arch/arm64/include/uapi', 'arch/arm64/include/generated/uapi']:
  args += ['-I', str(tree / name)]
 args += ['-c', 'task-types.c', '-o', 'task-types.o']
 with (tmp / 'task-build.log').open('w') as log:
  try:
   subprocess.run(args, cwd=tmp, check=True, timeout=60, stdout=log, stderr=log)
  except subprocess.CalledProcessError:
   log.flush()
   sys.stderr.write((tmp / 'task-build.log').read_text()[-8000:])
   raise
 (tmp / 'task.map').write_text('%016x %s %s\n' %
                             (selected['address'], selected['type'], selected['name']))
 result = subprocess.run([dwarf2json, 'linux', '--elf', 'task-types.o', '--system-map', 'task.map'],
                         cwd=tmp, check=True, timeout=60, capture_output=True)
 isf = json.loads(result.stdout)
 isf['symbols'] = {'init_task': isf['symbols']['init_task']}
 (tmp / 'task.json').write_text(json.dumps(isf, indent=2) + '\n')
 shutil.copyfile(tree / '.config', tmp / 'candidate.config')
 metadata = {'isfSha256': sha256(tmp / 'task.json'), 'candidateConfigSha256': sha256(tmp / 'candidate.config'),
             'headerTargets': ['cxd90057_set_defconfig', 'prepare0'],
             'scope': 'Candidate config types; only task-list fields are cross-checked against captured memory.',
             'taskSize': isf['user_types']['task_struct']['size']}
 shutil.rmtree(build)
 return metadata


def buildProfile(source, kernel, output, clang, dwarf2json, tasks=False, make='make', hostcc='clang'):
 output = Path(output).resolve()
 if output.exists():
  raise ValueError('Output directory already exists')
 if sha256(source) != SOURCE_SHA256 or sha256(kernel) != KERNEL_SHA256:
  raise ValueError('Expected the documented official A7C2 2.01 source and kernel hashes')
 types = sourceTypes(source)
 recovered = recoverSymbols(Path(kernel).read_bytes())
 selected = selectPrintkSymbols(recovered['symbols'])
 output.parent.mkdir(parents=True, exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='.printk-profile-', dir=str(output.parent)) as tmp:
  tmp = Path(tmp)
  (tmp / 'printk-types.c').write_text(types)
  (tmp / 'printk.map').write_text(''.join('%016x %s %s\n' %
   (s['address'], s['type'], s['name']) for s in selected))
  compileArgs = [clang, '--target=aarch64-linux-gnu', '-g', '-gdwarf-4', '-fstandalone-debug',
                 '-ffreestanding', '-c', 'printk-types.c', '-o', 'printk-types.o']
  subprocess.run(compileArgs, cwd=tmp, check=True, timeout=60, capture_output=True)
  convertArgs = [dwarf2json, 'linux', '--elf', 'printk-types.o', '--system-map', 'printk.map']
  result = subprocess.run(convertArgs, cwd=tmp, check=True, timeout=60, capture_output=True)
  isf = json.loads(result.stdout)
  validateTypes(isf)
  # Remove temporary object-file symbols with offsets unrelated to captured RAM.
  isf['symbols'] = {name: isf['symbols'][name] for name in PRINTK_SYMBOLS}
  (tmp / 'printk.json').write_text(json.dumps(isf, indent=2) + '\n')
  metadata = {'scope': 'printk only; not a complete kernel profile or original build DWARF',
              'sourceSha256': SOURCE_SHA256, 'kernelSha256': KERNEL_SHA256,
              'isfSha256': sha256(tmp / 'printk.json'), 'recoveredSymbolCount': recovered['symbolCount'],
              'selectedSymbols': selected, 'compileCommand': compileArgs, 'convertCommand': convertArgs,
              'clangVersion': subprocess.check_output([clang, '--version'], text=True).splitlines()[0],
              'dwarf2jsonVersion': isf['metadata']['producer'],
              'configBasis': 'cxd90057_set_defconfig; not claimed to be the exact shipping .config'}
  if tasks:
   candidates = [s for s in recovered['symbols'] if s['name'] == 'init_task' and s['type'] == 'D']
   if len(candidates) != 1:
    raise ValueError('Expected one init_task data symbol')
   metadata['tasks'] = buildTaskTypes(source, tmp, candidates[0], clang, dwarf2json, make, hostcc)
  (tmp / 'profile.json').write_text(json.dumps(metadata, indent=2) + '\n')
  os.rename(tmp, output)
 return metadata


def main():
 parser = argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--source', required=True, help='official linux-kernel.tar.gz')
 parser.add_argument('--kernel', required=True, help='original vmlinux.bin')
 parser.add_argument('--clang', default='clang', help='Clang with AArch64 ELF/DWARF support')
 parser.add_argument('--dwarf2json', required=True, help='dwarf2json executable')
 parser.add_argument('--tasks', action='store_true', help='also compile task-list types using generated official headers')
 parser.add_argument('--make', default='make', help='GNU make for --tasks')
 parser.add_argument('--hostcc', default='clang', help='host C compiler for --tasks')
 parser.add_argument('-o', required=True, help='new profile directory')
 args = parser.parse_args()
 buildProfile(args.source, args.kernel, args.o, args.clang, args.dwarf2json,
              args.tasks, args.make, args.hostcc)
 print('Built partial printk%s ISF from official source and recovered kernel symbols' %
       ('/task' if args.tasks else ''))


if __name__ == '__main__':
 main()
