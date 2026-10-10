import functools
import io
import operator
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from tools.kernel_symbols import buildElf, compareSnapshot, recoverSymbols

ROOT = Path(__file__).resolve().parents[1]
BASE = 0xffffff8008080000


def synthetic_kernel():
 """Independently serialize a small Linux-style table; no firmware bytes."""
 image = bytearray(0x5000)
 struct.pack_into('<Q', image, 16, 0x6000)
 image[56:60] = b'ARM\x64'
 banner = b'Linux version synthetic test\0'
 image[0x1100:0x1100+len(banner)] = banner
 symbols = [(0, 'T', '_text'), (0, 't', '_head'), (0x80, 'T', '_stext')]
 symbols += [(0x100+i*4, 't', 'function_%03d'%i) for i in range(300)]
 symbols += [(0xc00, 'W', 'weak_function'), (0x1000, 'R', '_etext'), (0x1100, 'R', 'linux_banner'),
             (0x1400, 'T', '__init_begin'), (0x1800, 'D', '_data'),
             (0x1900, 'd', 'state'),
             (0x1c00, 'D', '__start___jump_table'), (0x1c18, 'D', '__stop___jump_table'),
             (0x1d00, 'R', '__alt_instructions'), (0x1d0c, 'R', '__alt_instructions_end'),
             (0x5000, 'D', '_edata'), (0x6000, 'B', '_end')]
 struct.pack_into('<II', image, 0x700, 0xd503201f, 0xd503201f)
 struct.pack_into('<QQQ', image, 0x1c00, BASE+0x700, BASE+0x708, BASE+0x1900)
 struct.pack_into('<iiHBB', image, 0x1d00, 0x704-0x1d00, 0x1e00-0x1d04, 9, 4, 4)
 rounded = lambda value: (value+255)//256*256
 offsets = 0x2000
 position = offsets
 for value,kind,name in symbols:
  struct.pack_into('<I', image, position, value)
  position += 4
 relativeBase = rounded(position)
 struct.pack_into('<Q', image, relativeBase, BASE)
 countOffset = rounded(relativeBase+8)
 struct.pack_into('<Q', image, countOffset, len(symbols))
 names = rounded(countOffset+8)
 position = names
 markers = []
 for i,(value,kind,name) in enumerate(symbols):
  if i%256 == 0:
   markers.append(position-names)
  encoded = (kind+name).encode('ascii')
  image[position] = len(encoded)
  image[position+1:position+1+len(encoded)] = encoded
  position += len(encoded)+1
 markerOffset = rounded(position)
 for i,value in enumerate(markers):
  struct.pack_into('<Q', image, markerOffset+i*8, value)
 tokenTable = rounded(markerOffset+len(markers)*8)
 position = tokenTable
 tokenOffsets = []
 for i in range(256):
  tokenOffsets.append(position-tokenTable)
  token = bytes([i]) if 32<=i<=126 else b''
  image[position:position+len(token)+1] = token+b'\0'
  position += len(token)+1
 tokenIndex = rounded(position)
 struct.pack_into('<256H', image, tokenIndex, *tokenOffsets)
 return bytes(image), {'offsets':offsets, 'relativeBase':relativeBase,
                       'count':countOffset, 'names':names, 'markers':markerOffset,
                       'tokenTable':tokenTable, 'tokenIndex':tokenIndex}, symbols


def snapshot(payload):
 physical = 0x400080000
 header = struct.pack('<4s4x10Q', b'WBI2',1,0,physical+0x700,0x20060224,512,len(payload),0,0,0,len(payload))
 values = (physical,len(payload),0x0f0f0f0f,0,len(payload),0xffffffc000080000)
 checksum = functools.reduce(operator.xor,values,0x0f0f0f0f)
 return io.BytesIO(header.ljust(512,b'\0')+payload+struct.pack('<8Q',*(values+(checksum,0))))


class KernelSymbolTests(unittest.TestCase):
 def test_snapshot_patch_classes_and_captured_pages(self):
  image,layout,symbols = synthetic_kernel()
  captured = bytearray(image)
  struct.pack_into('<III',captured,0x700,0x14000002,0xd5033f9f,0xd503201f)
  comparison = compareSnapshot(image,recoverSymbols(image),snapshot(captured),0x400080000)
  self.assertEqual(comparison['pages'],{'matched':0,'changed':1,'uncaptured':0})
  self.assertEqual([c['classification'] for c in comparison['changes']],
                    ['static-key','alternative-site','unclassified'])
  self.assertEqual(comparison['changes'][1]['cpuFeatures'],[9])

 def test_snapshot_wrong_physical_base_is_rejected(self):
  image,layout,symbols = synthetic_kernel()
  with self.assertRaisesRegex(ValueError,'anchor mismatch'):
   compareSnapshot(image,recoverSymbols(image),snapshot(image),0x400081000)

 def test_recovery_addresses_aliases_and_all_markers(self):
  image,layout,symbols = synthetic_kernel()
  result = recoverSymbols(image)
  self.assertEqual(result['layout'], layout)
  self.assertEqual(result['symbolCount'], len(symbols))
  self.assertEqual(result['symbols'], [{'address':BASE+a, 'type':t, 'name':n} for a,t,n in symbols])

 def test_bad_header_and_endianness(self):
  image,layout,symbols = synthetic_kernel()
  for contents in [b'', image[:56]+b'BAD!'+image[60:], image[:60]]:
   with self.assertRaises(ValueError):
    recoverSymbols(contents)
  changed = bytearray(image)
  struct.pack_into('<Q', changed, 24, 1)
  with self.assertRaisesRegex(ValueError, 'Big-endian'):
   recoverSymbols(changed)

 def test_corrupted_tables_and_anchors_are_rejected(self):
  image,layout,symbols = synthetic_kernel()
  for offset in [layout['markers']+8, layout['tokenIndex']+10,
                 layout['relativeBase'], layout['names'], 0x1100]:
   changed = bytearray(image)
   changed[offset] ^= 1
   with self.subTest(offset=offset):
    with self.assertRaises(ValueError):
     recoverSymbols(changed)

 def test_unsupported_signed_offsets_and_excessive_counts(self):
  image,layout,symbols = synthetic_kernel()
  for offset,format,value in [(layout['offsets'], '<I', 0xffffffff),
                              (layout['count'], '<Q', 1000001)]:
   changed = bytearray(image)
   struct.pack_into(format, changed, offset, value)
   with self.assertRaises(ValueError):
    recoverSymbols(changed)

 def test_elf_preserves_image_and_exports_every_symbol(self):
  image,layout,symbols = synthetic_kernel()
  elf = buildElf(image, recoverSymbols(image))
  header = struct.unpack_from('<16sHHIQQQIHHHHHH', elf)
  self.assertEqual(header[0][:7], b'\x7fELF\x02\x01\x01')
  self.assertEqual(header[2], 183)
  self.assertEqual(header[4], BASE)
  self.assertEqual(elf[4096:4096+len(image)], image)
  sections = [struct.unpack_from('<IIQQQQIIQQ', elf, header[6]+i*64) for i in range(header[12])]
  symtab,strtab = sections[6:8]
  self.assertEqual(symtab[5]//24, len(symbols)+1)
  self.assertEqual(symtab[6], 7)
  decoded = []
  for offset in range(symtab[4]+24, symtab[4]+symtab[5], 24):
   name,info,other,section,value,size = struct.unpack_from('<IBBHQQ', elf, offset)
   start = strtab[4]+name
   text = elf[start:elf.index(b'\0',start)].decode('ascii')
   decoded.append((value,text,info>>4))
   self.assertEqual(size, 0)
  self.assertEqual(sorted((a,n) for a,n,binding in decoded), sorted((BASE+a,n) for a,t,n in symbols))
  self.assertTrue(all(binding==0 for a,n,binding in decoded[:symtab[7]-1]))
  self.assertTrue(all(binding!=0 for a,n,binding in decoded[symtab[7]-1:]))
  self.assertEqual(next(binding for a,n,binding in decoded if n=='weak_function'), 2)
  for i in range(header[10]):
   kind,flags,offset,vaddr,paddr,filesz,memsz,alignment = struct.unpack_from('<IIQQQQQQ',elf,header[5]+i*56)
   self.assertEqual(elf[offset:offset+filesz], image[vaddr-BASE:vaddr-BASE+filesz])
   self.assertGreaterEqual(memsz, filesz)

 def test_missing_region_boundary_refuses_elf(self):
  image,layout,symbols = synthetic_kernel()
  result = recoverSymbols(image)
  result['symbols'] = [s for s in result['symbols'] if s['name']!='_etext']
  with self.assertRaisesRegex(ValueError, 'boundaries'):
   buildElf(image, result)

 def test_cli_exports_and_refuses_overwrite(self):
  image,layout,symbols = synthetic_kernel()
  with tempfile.TemporaryDirectory(prefix='fwtool-symbols-') as tmp:
   source,output = Path(tmp)/'Image',Path(tmp)/'out'
   source.write_bytes(image)
   args = [sys.executable,str(ROOT/'tools/kernel_symbols.py'),'-f',str(source),'-o',str(output)]
   result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,text=True,timeout=60)
   self.assertEqual(result.returncode, 0, result.stdout)
   self.assertEqual(len((output/'System.map').read_text().splitlines()),len(symbols))
   original = (output/'kernel.elf').read_bytes()
   again = subprocess.run(args, stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
   self.assertNotEqual(again.returncode,0)
   self.assertEqual((output/'kernel.elf').read_bytes(),original)

 def test_cli_invalid_input_publishes_nothing(self):
  with tempfile.TemporaryDirectory(prefix='fwtool-symbols-') as tmp:
   source,output = Path(tmp)/'Image',Path(tmp)/'out'
   source.write_bytes(b'ARM\x64')
   result = subprocess.run([sys.executable,str(ROOT/'tools/kernel_symbols.py'),'-f',str(source),'-o',str(output)],
                           stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
   self.assertNotEqual(result.returncode,0)
   self.assertFalse(output.exists())


if __name__ == '__main__':
 unittest.main()
