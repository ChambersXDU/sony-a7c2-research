#!/usr/bin/env python3
"""Recover Linux 4.9 AArch64 relative kallsyms and build an analysis-only ELF."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fwtool.sony import wbi

ALIGNMENT = 256
MAX_SYMBOLS = 1000000
MAX_IMAGE_BYTES = 64 * 1024 * 1024


def align(value, alignment=ALIGNMENT):
 return (value + alignment - 1) & ~(alignment - 1)


def readTokens(image, table, index, offsets):
 tokens = []
 end = table
 for offset in offsets:
  if table + offset != end:
   raise ValueError('Invalid token boundary')
  end = image.find(b'\0', end, index)
  if end < 0:
   raise ValueError('Unterminated token')
  token = image[table + offset:end]
  if any(c < 32 or c > 126 for c in token):
   raise ValueError('Non-ASCII token')
  tokens.append(token)
  end += 1
 if align(end) != index or any(image[end:index]):
  raise ValueError('Invalid token padding')
 return tokens


def readCandidate(image, countOffset, table, index, tokens, imageSize):
 count = struct.unpack_from('<Q', image, countOffset)[0]
 if not 2 <= count <= MAX_SYMBOLS:
  raise ValueError('Invalid symbol count')
 names = align(countOffset + 8)
 markerBytes = ((count + 255) // 256) * 8
 markers = (table - markerBytes) & ~(ALIGNMENT - 1)
 relativeBase = countOffset - ALIGNMENT
 offsets = (relativeBase - count * 4) & ~(ALIGNMENT - 1)
 if offsets < 64 or names >= markers or align(markers + markerBytes) != table:
  raise ValueError('Invalid table layout')
 base = struct.unpack_from('<Q', image, relativeBase)[0]
 if base >> 48 != 0xffff or base & 4095 or base + imageSize >= 1 << 64:
  raise ValueError('Invalid kernel base')
 for start, end in [(offsets + count * 4, relativeBase),
                    (relativeBase + 8, countOffset), (countOffset + 8, names),
                    (markers + markerBytes, table)]:
  if any(image[start:end]):
   raise ValueError('Invalid table padding')
 values = struct.unpack_from('<%dI' % count, image, offsets)
 if values[0] != 0 or values[-1] > imageSize or any(a > b for a,b in zip(values, values[1:])):
  raise ValueError('Unsupported address encoding or invalid address order')
 actualMarkers = struct.unpack_from('<%dQ' % (markerBytes // 8), image, markers)
 position = names
 expectedMarkers = []
 symbols = []
 for i, value in enumerate(values):
  if i % 256 == 0:
   expectedMarkers.append(position - names)
  if position >= markers:
   raise ValueError('Truncated symbol names')
  length = image[position]
  if not length or position + 1 + length > markers:
   raise ValueError('Invalid compressed name')
  codes = image[position+1:position+1+length]
  if any(not tokens[c] for c in codes):
   raise ValueError('Compressed symbol references an empty token')
  expanded = b''.join(tokens[c] for c in codes)
  if len(expanded) < 2 or len(expanded) > 128 or not chr(expanded[0]).isalpha():
   raise ValueError('Invalid expanded symbol')
  symbols.append({'address': base + value, 'type': chr(expanded[0]),
                  'name': expanded[1:].decode('ascii')})
  position += length + 1
 if expectedMarkers != list(actualMarkers) or align(position) != markers or any(image[position:markers]):
  raise ValueError('Invalid symbol markers or padding')
 lookup = {s['name']: s['address'] for s in symbols}
 if lookup.get('_text') != base or lookup.get('_end') != base + imageSize:
  raise ValueError('Kernel boundary symbols do not match header')
 banner = lookup.get('linux_banner', base) - base
 if image[banner:banner+14] != b'Linux version ':
  raise ValueError('Kernel banner anchor does not match')
 return {'baseAddress': base, 'imageSize': imageSize, 'symbolCount': count,
         'encoding': 'base-relative-u32', 'tableAlignment': ALIGNMENT,
         'layout': {'offsets': offsets, 'relativeBase': relativeBase,
                    'count': countOffset, 'names': names, 'markers': markers,
                    'tokenTable': table, 'tokenIndex': index}, 'symbols': symbols}


def recoverSymbols(image):
 if len(image) < 64 or image[56:60] != b'ARM\x64':
  raise ValueError('Expected an AArch64 Linux Image header')
 imageSize = struct.unpack_from('<Q', image, 16)[0]
 if struct.unpack_from('<Q', image, 24)[0] & 1:
  raise ValueError('Big-endian kernel images are unsupported')
 if len(image) > MAX_IMAGE_BYTES or not len(image) <= imageSize <= 256 * 1024 * 1024:
  raise ValueError('Unsupported kernel image size')
 candidates = []
 for index in range(ALIGNMENT, len(image) - 511, ALIGNMENT):
  if image[index:index+2] != b'\0\0' or image[index+2:index+4] == b'\0\0':
   continue
  offsets = struct.unpack_from('<256H', image, index)
  if not all(a < b for a,b in zip(offsets, offsets[1:])):
   continue
  for table in range(index - ALIGNMENT, max(0, index - 65536), -ALIGNMENT):
   try:
    tokens = readTokens(image, table, index, offsets)
   except ValueError:
    continue
   for countOffset in range(ALIGNMENT, table, ALIGNMENT):
    count = struct.unpack_from('<Q', image, countOffset)[0]
    if not 2 <= count <= MAX_SYMBOLS:
     continue
    try:
     candidates.append(readCandidate(image, countOffset, table, index, tokens, imageSize))
    except (ValueError, struct.error):
     continue
 if len(candidates) != 1:
  raise ValueError('Expected exactly one validated kallsyms table; found %d' % len(candidates))
 return candidates[0]


def buildElf(image, recovered):
 """Create a derived ELF, preserving Image bytes and names, without invented sizes."""
 base = recovered['baseAddress']
 lookup = {s['name']: s['address'] for s in recovered['symbols']}
 boundaries = [base, lookup.get('_etext'), lookup.get('__init_begin'),
               lookup.get('_data'), lookup.get('_edata'), lookup.get('_end')]
 if any(v is None for v in boundaries) or any(a >= b for a,b in zip(boundaries, boundaries[1:])):
  raise ValueError('Missing or invalid ELF region boundaries')
 if boundaries[-2] - base != len(image) or boundaries[-1] - base != recovered['imageSize']:
  raise ValueError('ELF boundaries do not match Image lengths')
 # .init groups mixed init text/data; permissions are analysis annotations.
 regions = [('.text', 6, 5), ('.rodata', 2, 4), ('.init', 7, 7), ('.data', 3, 6)]
 names = [''] + [name for name,flags,perms in regions] + ['.bss', '.symtab', '.strtab', '.shstrtab']
 shstr = b'\0'
 nameOffsets = {}
 for name in names[1:]:
  nameOffsets[name] = len(shstr)
  shstr += name.encode('ascii') + b'\0'
 imageOffset = 4096
 output = bytearray(imageOffset) + image
 sections = [(0,)*10]
 programs = []
 for i, (name, flags, permissions) in enumerate(regions):
  start, end = boundaries[i:i+2]
  size = end - start
  offset = imageOffset + start - base
  sections.append((nameOffsets[name], 1, flags, start, offset, size, 0, 0, 1, 0))
  memSize = boundaries[-1] - start if i == 3 else size
  programs.append((1, permissions, offset, start, start, size, memSize, 1))
 sections.append((nameOffsets['.bss'], 8, 3, boundaries[-2], imageOffset + len(image),
                  boundaries[-1] - boundaries[-2], 0, 0, 1, 0))

 strings = bytearray(b'\0')
 symbolNames = {}
 local, globalSymbols = [], []
 boundaryNames = {'_text', '_stext', '_etext', '__init_begin', '__init_end',
                  '_data', '_sdata', '_edata', '__bss_start', '__bss_stop', '_end'}
 for symbol in recovered['symbols']:
  name, kind, address = symbol['name'], symbol['type'], symbol['address']
  if name not in symbolNames:
   symbolNames[name] = len(strings)
   strings.extend(name.encode('ascii') + b'\0')
  binding = 2 if kind in 'WwVv' else (0 if kind.islower() else 1)
  symbolType = 0 if name in boundaryNames else (2 if kind in 'TtWw' else 1)
  section = next((i+1 for i,(a,b) in enumerate(zip(boundaries,boundaries[1:])) if a <= address < b), 0xfff1)
  entry = struct.pack('<IBBHQQ', symbolNames[name], (binding << 4) | symbolType, 0,
                       section, address, 0)
  (local if binding == 0 else globalSymbols).append(entry)
 symtab = b'\0'*24 + b''.join(local + globalSymbols)
 for name, contents, sectionType, link, info, entrySize, alignment in [
  ('.symtab', symtab, 2, 7, len(local)+1, 24, 8),
  ('.strtab', strings, 3, 0, 0, 0, 1), ('.shstrtab', shstr, 3, 0, 0, 0, 1)]:
  offset = align(len(output), alignment)
  output.extend(b'\0'*(offset-len(output)))
  output.extend(contents)
  sections.append((nameOffsets[name], sectionType, 0, 0, offset, len(contents), link, info, alignment, entrySize))
 shoff = align(len(output), 8)
 output.extend(b'\0'*(shoff-len(output)))
 for section in sections:
  output.extend(struct.pack('<IIQQQQIIQQ', *section))
 output[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01'+b'\0'*9,
                           2, 183, 1, base, 64, shoff, 0, 64, 56, len(programs), 64, len(sections), 8)
 for i, program in enumerate(programs):
  output[64+i*56:64+(i+1)*56] = struct.pack('<IIQQQQQQ', *program)
 return bytes(output)


def compareSnapshot(image, recovered, file, physicalBase):
 """Compare captured kernel text and classify known static patch-table sites."""
 chunks = list(wbi.readWbi2(file))
 chunks.sort(key=lambda chunk: chunk.physicalAddr)
 if any(a.physicalAddr+a.size > b.physicalAddr for a,b in zip(chunks,chunks[1:])):
  raise ValueError('Overlapping snapshot sections')
 lookup = {s['name']:s['address'] for s in recovered['symbols']}
 base = recovered['baseAddress']
 textSize = lookup['_etext']-base
 if physicalBase < 0 or physicalBase+len(image) >= 1<<64:
  raise ValueError('Invalid physical kernel base')

 def readRange(address, size):
  data, captured = bytearray(size), bytearray(size)
  for chunk in chunks:
   start,end = max(address,chunk.physicalAddr),min(address+size,chunk.physicalAddr+chunk.size)
   if start >= end:
    continue
   chunk.contents.seek(0)
   skip = start-chunk.physicalAddr
   while skip:
    n = min(skip,65536)
    if len(chunk.contents.read(n)) != n:
     raise ValueError('Truncated snapshot section')
    skip -= n
   contents = chunk.contents.read(end-start)
   if len(contents) != end-start:
    raise ValueError('Truncated snapshot section')
   data[start-address:end-address] = contents
   captured[start-address:end-address] = b'\1'*(end-start)
  return data,captured

 anchors = []
 for name in ['_text','_stext','linux_banner','kallsyms_lookup_name','cpu_resume','cxd90057_resume_ssboot']:
  if name not in lookup:
   continue
  offset = lookup[name]-base
  contents,captured = readRange(physicalBase+offset,64)
  if offset < 0 or offset+64 > len(image) or not all(captured) or contents != image[offset:offset+64]:
   raise ValueError('Snapshot physical-base anchor mismatch: %s' % name)
  anchors.append(name)
 if len(anchors) < 3:
  raise ValueError('Too few independent snapshot anchors')
 text,captured = readRange(physicalBase,textSize)
 alternatives = []
 jumps = {}
 for begin,end,recordSize in [('__alt_instructions','__alt_instructions_end',12),
                              ('__start___jump_table','__stop___jump_table',24)]:
  if begin not in lookup or end not in lookup:
   continue
  start,stop = lookup[begin]-base,lookup[end]-base
  if not 0 <= start <= stop <= len(image) or (stop-start)%recordSize:
   raise ValueError('Invalid kernel patch table')
  for offset in range(start,stop,recordSize):
   if recordSize == 12:
    original,replacement,feature,originalSize,replacementSize = struct.unpack_from('<iiHBB',image,offset)
    alternatives.append((offset+original,originalSize,feature))
   else:
    code,target,key = struct.unpack_from('<QQQ',image,offset)
    jumps[code-base] = target
 changes = []
 def isStaticKeyWord(contents, offset, target):
  instruction = struct.unpack_from('<I',contents,offset)[0]
  immediate = instruction & 0x3ffffff
  if immediate & 0x2000000:
   immediate -= 1<<26
  return instruction == 0xd503201f or (instruction & 0xfc000000 == 0x14000000 and
                                      base+offset+immediate*4 == target)

 for offset in range(0,textSize,4):
  if not all(captured[offset:offset+4]) or image[offset:offset+4] == text[offset:offset+4]:
   continue
  kind = 'unclassified'
  feature = [f for start,size,f in alternatives if start<=offset<start+size]
  if offset in jumps:
   if isStaticKeyWord(image,offset,jumps[offset]) and isStaticKeyWord(text,offset,jumps[offset]):
    kind = 'static-key'
  elif feature:
   kind = 'alternative-site'
  changes.append({'offset':offset,'linkedAddress':base+offset,'physicalAddress':physicalBase+offset,
                  'before':image[offset:offset+4].hex(),'after':text[offset:offset+4].hex(),
                  'classification':kind,'cpuFeatures':feature})
 pages = {'matched':0,'changed':0,'uncaptured':0}
 for offset in range(0,textSize,4096):
  end = min(offset+4096,textSize)
  kind = 'uncaptured' if not all(captured[offset:end]) else (
         'matched' if image[offset:end] == text[offset:end] else 'changed')
  pages[kind] += 1
 vector = wbi.Wbi2Header.unpack(file).resumeVector
 linkedVector = base+vector-physicalBase
 return {'physicalBase':physicalBase,'linkedBase':base,'verifiedAnchors':anchors,'textBytes':textSize,
         'pageBytes':4096,'pages':pages,'resumePhysicalAddress':vector,'resumeLinkedAddress':linkedVector,
         'resumeSymbols':[s['name'] for s in recovered['symbols'] if s['address']==linkedVector],
         'alternativeRecords':len(alternatives),'jumpTableRecords':len(jumps),'changes':changes,
         'limitations':'Patch-site correlation is static evidence, not an execution trace or authenticity check. '
                       'Alternative-site matching does not validate replacement semantics. Uncaptured bytes are unknown.'}


def main():
 parser = argparse.ArgumentParser(description=__doc__)
 parser.add_argument('-f', required=True, help='AArch64 vmlinux.bin / Linux Image')
 parser.add_argument('-o', required=True, help='new output directory')
 parser.add_argument('--snapshot', help='optional WBI2 partition for captured-text comparison')
 parser.add_argument('--physical-base', type=lambda value:int(value,0), help='kernel physical base; verified with byte anchors')
 args = parser.parse_args()
 if bool(args.snapshot) != (args.physical_base is not None):
  parser.error('--snapshot and --physical-base must be supplied together')
 output = Path(args.o).resolve()
 if output.exists():
  parser.error('Output directory already exists')
 with open(args.f, 'rb') as file:
  image = file.read(MAX_IMAGE_BYTES + 1)
 recovered = recoverSymbols(image)
 elf = buildElf(image, recovered)
 comparison = None
 if args.snapshot:
  with open(args.snapshot,'rb') as file:
   comparison = compareSnapshot(image,recovered,file,args.physical_base)
 metadata = {key:value for key,value in recovered.items() if key != 'symbols'}
 metadata.update({'inputSha256': hashlib.sha256(image).hexdigest(),
                  'elfSha256': hashlib.sha256(elf).hexdigest(),
                  'elfMeaning': 'Derived analysis container, not the original ELF. Sizes are unknown; '
                                'region permissions are annotations; .bss is not captured RAM.'})
 output.parent.mkdir(parents=True, exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='.kernel-symbols-', dir=str(output.parent)) as tmp:
  root = Path(tmp)
  (root/'kernel.elf').write_bytes(elf)
  (root/'symbols.json').write_text(json.dumps(recovered['symbols'], indent=2)+'\n')
  (root/'analysis.json').write_text(json.dumps(metadata, indent=2)+'\n')
  if comparison is not None:
   (root/'snapshot-comparison.json').write_text(json.dumps(comparison,indent=2)+'\n')
  with (root/'System.map').open('w') as file:
   for symbol in recovered['symbols']:
    file.write('%016x %s %s\n' % (symbol['address'], symbol['type'], symbol['name']))
  os.rename(tmp, output)
 print('Recovered %d symbols; linked base=0x%x' % (recovered['symbolCount'], recovered['baseAddress']))


if __name__ == '__main__':
 main()
