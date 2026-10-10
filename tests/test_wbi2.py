import functools
import io
import operator
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml
from fwtool.sony import constants, wbi
from tests.samples import cbc_fdat, dat_container, plain_fdat

ROOT = Path(__file__).resolve().parents[1]


def sample_wbi2(trailing=b''):
 raw = bytes(range(256)) * 2
 specifications = [(0x400001000, raw), (0x400003000, 512), (0x400005000, b'\0' * 512)]
 payload = b''
 entries = b''
 for addr, contents in specifications:
  is_zero = isinstance(contents, int)
  size = contents if is_zero else len(contents)
  values = (addr, 0 if is_zero else size, 0x0f0f0f0f, int(is_zero), size,
            0xffffffc000000000 + addr - 0x400000000)
  metadata_checksum = functools.reduce(operator.xor, values, 0x0f0f0f0f)
  entries += struct.pack('<8Q', *(values + (metadata_checksum, 0)))
  if not is_zero:
   payload += contents
 header = struct.pack('<4s4x10Q', b'WBI2', 3, 0, 0x400001000, 0x20060224,
                      512, len(payload), 0, 0, 0x0f0f0f0f, 1536)
 return header.ljust(512, b'\0') + payload + entries + trailing


def replace_section(sample, index, field, value):
 result = bytearray(sample)
 offset = 1536 + index * 64
 struct.pack_into('<Q', result, offset + field * 8, value)
 values = struct.unpack_from('<6Q', result, offset)
 struct.pack_into('<Q', result, offset + 48, functools.reduce(operator.xor, values, 0x0f0f0f0f))
 return bytes(result)


class Wbi2Tests(unittest.TestCase):
 def test_64bit_sections_zero_fill_and_trailing_bytes(self):
  sample = sample_wbi2(trailing=b'unused bytes from an older image')
  file = io.BytesIO(sample)
  self.assertTrue(wbi.isWbi(file))
  self.assertTrue(wbi.isWbi2(file))
  chunks = list(wbi.readWbi(file))
  self.assertEqual(len(chunks), 3)
  self.assertEqual(chunks[0].physicalAddr, 0x400001000)
  self.assertEqual(chunks[0].virtualAddr, 0xffffffc000001000)
  for chunk, expected in zip(chunks, [bytes(range(256))*2, b'\0'*512, b'\0'*512]):
   self.assertEqual(chunk.size, len(expected))
   self.assertEqual(chunk.contents.read(), expected)
   chunk.contents.seek(0)
   self.assertEqual(chunk.contents.read(), expected)

 def test_zero_first_data_sector_is_not_skipped(self):
  sample = bytearray(sample_wbi2())
  sample[512:1024] = b'\0' * 512
  chunks = list(wbi.readWbi2(io.BytesIO(sample)))
  self.assertEqual(chunks[0].contents.read(), b'\0' * 512)

 def test_metadata_checksum_error(self):
  sample = bytearray(sample_wbi2())
  sample[1536] ^= 1
  with self.assertRaisesRegex(ValueError, 'metadata checksum'):
   list(wbi.readWbi2(io.BytesIO(sample)))

 def test_truncated_header_data_and_table(self):
  sample = sample_wbi2()
  for cut in [0, 4, 87, 511, 1535, len(sample)-1]:
   with self.subTest(cut=cut):
    self.assertFalse(wbi.isWbi2(io.BytesIO(sample[:min(cut,87)])))
    with self.assertRaisesRegex(ValueError, 'Truncated WBI2'):
     list(wbi.readWbi2(io.BytesIO(sample[:cut])))

 def test_unsupported_header_flags(self):
  for flag in [1, 4, 8, 0x100]:
   sample = bytearray(sample_wbi2())
   struct.pack_into('<Q', sample, 16, flag)
   with self.subTest(flag=flag):
    with self.assertRaisesRegex(ValueError, 'Unsupported WBI2 flags'):
     list(wbi.readWbi2(io.BytesIO(sample)))

 def test_invalid_sector_size(self):
  for size in [0, 64, 513]:
   sample = bytearray(sample_wbi2())
   struct.pack_into('<Q', sample, 40, size)
   with self.assertRaisesRegex(ValueError, 'sector size'):
    list(wbi.readWbi2(io.BytesIO(sample)))

 def test_invalid_section_sizes_flags_and_addresses(self):
  for index, field, value, error in [(0, 1, 0, 'section size'),
                                     (1, 1, 512, 'section size'),
                                     (0, 4, 511, 'section size'),
                                     (0, 3, 2, 'section flags'),
                                     (0, 0, (1<<64)-256, 'section address')]:
   sample = replace_section(sample_wbi2(), index, field, value)
   with self.subTest(index=index, field=field):
    with self.assertRaisesRegex(ValueError, error):
     list(wbi.readWbi2(io.BytesIO(sample)))

 def test_original_total_size_mismatch(self):
  sample = bytearray(sample_wbi2())
  struct.pack_into('<Q', sample, 80, 2048)
  with self.assertRaisesRegex(ValueError, 'total section size'):
   list(wbi.readWbi2(io.BytesIO(sample)))

 def test_legacy_wbi1_compressed_regression(self):
  contents = b'abcdefgh'
  compressed = b'\x0f\0' + struct.pack('<H', len(contents)) + contents
  header = struct.pack('<4s10I', b'WBI1', 1, 1, 0, 0x20060224, 512,
                       len(compressed), 0, 0, 0, len(contents))
  table = struct.pack('<8I', 0x80001000, len(compressed), 0, 0, len(contents), 0xc0001000, 0, 0)
  file = io.BytesIO(header.ljust(512,b'\0') + compressed + table)
  self.assertTrue(wbi.isWbi(file))
  self.assertFalse(wbi.isWbi2(file))
  chunks = list(wbi.readWbi(file))
  self.assertEqual(len(chunks), 1)
  self.assertEqual(chunks[0].contents.read(), contents)

 def test_cli_raw_wbi2(self):
  with tempfile.TemporaryDirectory(prefix='fwtool-wbi2-') as tmp:
   source = Path(tmp) / 'image.wbi'
   output = Path(tmp) / 'out'
   source.write_bytes(sample_wbi2())
   result = subprocess.run([sys.executable, str(ROOT/'fwtool.py'), 'unpack',
                            '-f', str(source), '-o', str(output)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
   self.assertEqual(result.returncode, 0, result.stdout)
   self.assertEqual((output/'0x400001000.dat').read_bytes(), bytes(range(256))*2)
   self.assertEqual((output/'0x400003000.dat').read_bytes(), b'\0'*512)
   metadata = yaml.safe_load((output/'memory.yaml').read_text())
   self.assertEqual(len(metadata['sections']), 3)
   self.assertEqual(metadata['sections'][0]['physicalAddr'], 0x400001000)

 def test_cli_nested_wbi2_in_encrypted_dat(self):
  snapshot = sample_wbi2()
  firmware = io.BytesIO()
  with tarfile.open(fileobj=firmware, mode='w', format=tarfile.USTAR_FORMAT) as tar:
   member = tarfile.TarInfo('partitions/snapshot')
   member.size = len(snapshot)
   tar.addfile(member, io.BytesIO(snapshot))
  payload = plain_fdat(firmware=firmware.getvalue())
  with tempfile.TemporaryDirectory(prefix='fwtool-nested-wbi2-') as tmp:
   source = Path(tmp) / 'BODYDATA.DAT'
   output = Path(tmp) / 'out'
   source.write_bytes(dat_container(cbc_fdat(payload, constants.key_cxd90057_k8)))
   result = subprocess.run([sys.executable, str(ROOT/'fwtool.py'), 'unpack',
                            '-f', str(source), '-o', str(output)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
   self.assertEqual(result.returncode, 0, result.stdout)
   partition = output/'firmware.tar_unpacked/partitions/snapshot'
   self.assertEqual(partition.read_bytes(), snapshot)
   memory = partition.with_name('snapshot_unpacked')
   self.assertEqual((memory/'0x400001000.dat').read_bytes(), bytes(range(256))*2)
   self.assertEqual((memory/'0x400003000.dat').read_bytes(), b'\0'*512)
   self.assertEqual(len(yaml.safe_load((memory/'memory.yaml').read_text())['sections']), 3)


if __name__ == '__main__':
 unittest.main()
