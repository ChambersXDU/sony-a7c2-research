#!/usr/bin/env python3
"""Run existing Volatility 3 readers with explicit, scoped A7C2 kernel mappings."""

import argparse
from importlib.metadata import version
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.kernel_printk_profile import KERNEL_SHA256, PRINTK_SYMBOLS, sha256, validateTypes, selectPrintkSymbols
from tools.kernel_symbols import recoverSymbols

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import physical, lime, segmented
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux import extensions
from volatility3.framework.objects import utility
from volatility3.plugins.banners import Banners
from volatility3.plugins.linux.kmsg import ABCKmsg
from volatility3.plugins.linux.pslist import PsList

PHYSICAL_BASE = 0x400080000
LINEAR_BASE = 0xffffffc000000000
MEMSTART = 0x400000000


class CapturedKernelLayer(segmented.SegmentedLayer):
 """Expose only captured kernel-image and direct-map aliases; no page-table walk."""

 def __init__(self, context, config_path, name, linkedBase, imageSize):
  self.linkedBase, self.imageSize = linkedBase, imageSize
  super().__init__(context, config_path, name)

 def _load_segments(self):
  layer = self.context.layers[self._base_layer]
  self._segments = [(s + self.linkedBase - PHYSICAL_BASE, s, n, n)
                    for s, n, _, _, _ in layer.mapping(PHYSICAL_BASE, self.imageSize, ignore_errors=True)]
  self._segments += [(s + LINEAR_BASE - MEMSTART, s, n, n)
                    for s, n, _, _, _ in layer.mapping(layer.minimum_address,
                    layer.maximum_address - layer.minimum_address + 1, ignore_errors=True)]
  self._segments.sort()


def validateRing(context, module):
 """Bound the native parser's walk and reject missing or inconsistent records."""
 values = {n: int(module.object_from_symbol(n)) for n in PRINTK_SYMBOLS}
 size, first, end = (values[n] for n in ['log_buf_len', 'log_first_idx', 'log_next_idx'])
 count = values['log_next_seq'] - values['log_first_seq']
 if size != 1 << 17 or not 0 <= first < size or not 0 <= end < size or not 0 <= count < size // 16:
  raise ValueError('Unsupported or inconsistent printk ring counters')
 layer = context.layers[module.layer_name]
 base = values['log_buf']
 if not layer.is_valid(base, size):
  raise ValueError('Printk buffer includes uncaptured memory')
 idx, visited, records, wrapped = first, set(), 0, False
 while idx != end:
  if idx in visited:
   raise ValueError('Cyclic printk record walk')
  visited.add(idx)
  if idx + 16 > size:
   raise ValueError('Printk header crosses ring boundary')
  msg = module.object('printk_log', offset=base + idx, absolute=True)
  length = int(msg.len)
  if length == 0:
   if wrapped or idx == 0 or first <= end:
    raise ValueError('Unexpected printk wrap marker')
   wrapped, idx = True, 0
   continue
  limit = end if idx < end else size
  if length < 16 or length % 4 or idx + length > limit or int(msg.text_len) + int(msg.dict_len) > length - 16:
   raise ValueError('Invalid printk record lengths')
  layer.read(base + idx, length)  # Never pad absent bytes.
  records += 1
  idx += length
  if records > count:
   raise ValueError('More printk records than sequence counters')
 if records != count:
  raise ValueError('Printk sequence count does not match record walk')
 return dict(values, records=records, activeBytes=sum(
  int(module.object('printk_log', offset=base + i, absolute=True).len) for i in visited))


def validateTaskList(context, module):
 """Independently check raw links and used fields before invoking PsList."""
 layer = context.layers[module.layer_name]
 taskType = module.get_type('task_struct')
 offsets = {n: taskType.relative_child_offset(n) for n in ['tasks', 'pid', 'tgid', 'comm']}
 init = module.get_symbol('init_task').address
 head = init + offsets['tasks']
 def fields(addr):
  if not layer.is_valid(addr, taskType.size):
   raise ValueError('Task structure includes uncaptured memory')
  pid = struct.unpack('<i', layer.read(addr + offsets['pid'], 4))[0]
  tgid = struct.unpack('<i', layer.read(addr + offsets['tgid'], 4))[0]
  comm = layer.read(addr + offsets['comm'], 16).split(b'\0')[0]
  if not 0 <= pid <= 4194304 or not 0 <= tgid <= 4194304 or not comm or any(b < 32 or b > 126 for b in comm):
   raise ValueError('Invalid task ID or comm in candidate layout')
  return {'virtualAddress': addr, 'pid': pid, 'tgid': tgid, 'comm': comm.decode('ascii')}
 if fields(init) != {'virtualAddress': init, 'pid': 0, 'tgid': 0, 'comm': 'swapper/0'}:
  raise ValueError('Candidate task layout fails init_task anchor')
 next, tail = struct.unpack('<QQ', layer.read(head, 16))
 previous, seen, raw = head, set(), []
 while next != head:
  if next in seen or len(seen) >= 10000:
   raise ValueError('Task list does not close at init_task')
  seen.add(next)
  following, backlink = struct.unpack('<QQ', layer.read(next, 16))
  if backlink != previous:
   raise ValueError('Task list reciprocal link mismatch')
  raw.append(fields(next - offsets['tasks']))
  previous, next = next, following
 if tail != previous or len({t['pid'] for t in raw}) != len(raw):
  raise ValueError('Task list tail or PID uniqueness mismatch')
 return offsets, raw


def analyseLime(imagePath, kernelPath, profilePath):
 profilePath = Path(profilePath)
 profile = json.loads((profilePath / 'profile.json').read_text())
 if sha256(kernelPath) != KERNEL_SHA256 or profile['kernelSha256'] != KERNEL_SHA256:
  raise ValueError('Expected the documented A7C2 2.01 kernel Image')
 if sha256(profilePath / 'printk.json') != profile['isfSha256']:
  raise ValueError('Printk profile hash mismatch')
 isf = json.loads((profilePath / 'printk.json').read_text())
 validateTypes(isf)
 image = Path(kernelPath).read_bytes()
 recovered = recoverSymbols(image)
 lookup = {s['name']: s['address'] for s in recovered['symbols']}
 for symbol in selectPrintkSymbols(recovered['symbols']):
  if isf['symbols'][symbol['name']]['address'] != symbol['address']:
   raise ValueError('Printk symbol does not match recovered kernel: ' + symbol['name'])
 context = contexts.Context()
 context.config['file.location'] = Path(imagePath).resolve().as_uri()
 fileLayer = physical.FileLayer(context, 'file', 'file')
 context.layers.add_layer(fileLayer)
 try:
  layer = lime.LimeStacker.stack(context, 'file')
  if layer is None:
   raise ValueError('Expected a LiME memory image')
  context.layers.add_layer(layer)
  segments = list(layer.mapping(layer.minimum_address,
                  layer.maximum_address - layer.minimum_address + 1, ignore_errors=True))
  for _, n, offset, _, _ in segments:
   if offset + n > fileLayer.maximum_address + 1:
    raise ValueError('Truncated LiME payload')
  anchors = [0, 0x800, 0x95d78, 0x4262a0, 0x4267f0, 0x430090]
  for offset in anchors:
   if layer.read(PHYSICAL_BASE + offset, 64) != image[offset:offset + 64]:
    raise ValueError('Captured kernel physical mapping fails byte anchor')
  context.config['kernel.base_layer'] = layer.name
  kernelLayer = CapturedKernelLayer(context, 'kernel', 'kernel', recovered['baseAddress'], recovered['imageSize'])
  context.layers.add_layer(kernelLayer)
  def scalar(name):
   return struct.unpack('<Q', kernelLayer.read(lookup[name], 8))[0]
  if scalar('memstart_addr') != MEMSTART or scalar('kimage_voffset') != recovered['baseAddress'] - PHYSICAL_BASE:
   raise ValueError('Captured ARM64 mapping globals disagree with proposed mappings')
  # Check a physical hole through Volatility itself, rather than through a sidecar.
  gaps = []
  for a, b in zip(segments, segments[1:]):
   end = a[0] + a[1]
   if end < b[0]:
    if layer.is_valid(end):
     raise ValueError('LiME hole unexpectedly readable')
    try:
     layer.read(end, 1)
    except exceptions.InvalidAddressException:
     pass
    else:
     raise ValueError('LiME hole unexpectedly returned data')
    gaps.append({'physicalAddress': end, 'size': b[0] - end})
  context.symbol_space.append(intermed.IntermediateSymbolTable(
   context, 'printk', 'printk', isf_url=(profilePath / 'printk.json').resolve().as_uri()))
  module = context.module('printk', kernelLayer.name, 0)
  ring = validateRing(context, module)
  if ring['log_buf'] != lookup['__log_buf']:
   raise ValueError('Only the validated static printk buffer is supported')
  context.config['analysis.kernel'] = module.name
  logs = [dict(zip(['facility', 'level', 'timestamp', 'caller', 'line'], row))
          for row in ABCKmsg.run_all(context, context.config.branch('analysis'))] if ring['records'] else []
  banners = [{'physicalAddress': int(offset), 'banner': banner}
             for offset, banner in Banners.locate_banners(context, layer.name)]
  expectedBannerAddress = PHYSICAL_BASE + lookup['linux_banner'] - recovered['baseAddress']
  if not any(b['physicalAddress'] == expectedBannerAddress for b in banners):
   raise ValueError('Volatility did not identify the recovered linux_banner address')
  report = {'volatilityVersion': version('volatility3'), 'formatLayer': type(layer).__name__,
            'scope': 'Explicit ARM64 kernel image/direct map; no MMU translation or process address spaces.',
            'kernelSha256': KERNEL_SHA256, 'limeSha256': sha256(imagePath),
            'physicalBase': PHYSICAL_BASE, 'linkedBase': recovered['baseAddress'],
            'verifiedByteAnchors': anchors, 'capturedSections': len(segments),
            'capturedBytes': sum(s[1] for s in segments), 'unmappedGaps': len(gaps),
            'gapBytesWithinSpan': sum(g['size'] for g in gaps), 'banners': banners,
            'ring': ring, 'kmsgLines': len(logs), 'kmsgReader': 'volatility3.plugins.linux.kmsg.ABCKmsg.run_all'}
  tasks = None
  if 'tasks' in profile:
   taskPath = profilePath / 'task.json'
   if sha256(taskPath) != profile['tasks']['isfSha256']:
    raise ValueError('Task profile hash mismatch')
   taskISF = json.loads(taskPath.read_text())
   if taskISF['symbols']['init_task']['address'] != lookup['init_task']:
    raise ValueError('Task symbol does not match recovered kernel')
   context.symbol_space.append(intermed.IntermediateSymbolTable(context, 'tasks', 'tasks',
    isf_url=taskPath.resolve().as_uri(), class_types={'task_struct': extensions.task_struct,
                                                 'list_head': extensions.list_head}))
   taskModule = context.module('tasks', kernelLayer.name, 0)
   offsets, raw = validateTaskList(context, taskModule)
   tasks = [{'virtualAddress': t.vol.offset, 'pid': int(t.pid), 'tgid': int(t.tgid),
             'comm': utility.array_to_string(t.comm)} for t in PsList.list_tasks(context, taskModule.name)]
   if tasks != raw:
    raise ValueError('Volatility task results disagree with complete raw reciprocal-link walk')
   report['tasks'] = {'count': len(tasks), 'checkedOffsets': offsets,
                      'reader': 'volatility3.plugins.linux.pslist.PsList.list_tasks',
                      'limitations': 'Reachable task list only; idle task excluded. Candidate config does not validate all fields.'}
  return report, logs, tasks
 finally:
  fileLayer.destroy()


def main():
 parser = argparse.ArgumentParser(description=__doc__)
 parser.add_argument('-f', required=True, help='memory.lime')
 parser.add_argument('--kernel', required=True, help='original A7C2 2.01 vmlinux.bin')
 parser.add_argument('--profile', required=True, help='generated partial profile directory')
 parser.add_argument('-o', required=True, help='new analysis output directory')
 args = parser.parse_args()
 output = Path(args.o).resolve()
 if output.exists():
  parser.error('Output directory already exists')
 report, logs, tasks = analyseLime(args.f, args.kernel, args.profile)
 output.parent.mkdir(parents=True, exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='.volatility-wbi2-', dir=str(output.parent)) as tmp:
  for name, value in [('analysis.json', report), ('kmsg.json', logs), ('tasks.json', tasks)]:
   if value is not None:
    (Path(tmp) / name).write_text(json.dumps(value, indent=2) + '\n')
  os.rename(tmp, output)
 print('Volatility %s: %d printk records, %d output lines%s' %
       (report['volatilityVersion'], report['ring']['records'], len(logs),
        '; %d reachable tasks' % len(tasks) if tasks is not None else ''))


if __name__ == '__main__':
 main()
