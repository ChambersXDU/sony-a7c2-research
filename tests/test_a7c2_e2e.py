"""Opt-in test of the official ILCE-7CM2 2.01 download; no firmware fixture."""

import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_SHA256 = 'eb4943e6099754d64deaef5047942e9bfe258f232d0b7bc39fa23b3cd10e1e31'
OUTPUTS = {
 'firmware.fdat': (1135475712, '03eee07301010ff644fae1073f7c7f6dd2d60278f18aa3e6053938d5f1426d1f'),
 'firmware.tar': (1134221824, 'c29eaafab7f5f46dc364ebee244d75b1f93e017af651df5f4f92ec239df953b7'),
 'updater.img': (1253376, '788db9cdfb38edc171686b07635efea397279c303cef49308d8303601d0dcf0e'),
}


def sha256(path):
 digest = hashlib.sha256()
 with path.open('rb') as file:
  for chunk in iter(lambda: file.read(1024*1024), b''):
   digest.update(chunk)
 return digest.hexdigest()


class A7C2EndToEndTests(unittest.TestCase):
 def test_official_201_unpack(self):
  source = os.environ.get('SONY_A7C2_FW')
  if not source or not Path(source).is_file():
   self.skipTest('SONY_A7C2_FW does not name an existing firmware file')
  source = Path(source).resolve()
  self.assertEqual(source.stat().st_size, 1139929560)
  self.assertEqual(sha256(source), FIRMWARE_SHA256)
  # Firmware output plus WBI2 sections/image is under 4.5 GiB; allow overhead.
  self.assertGreaterEqual(shutil.disk_usage(tempfile.gettempdir()).free, 6*1024**3,
                          'At least 6 GiB free space is required in the temporary directory')
  with tempfile.TemporaryDirectory(prefix='fwtool-a7c2-') as tmp:
   output = Path(tmp) / 'unpacked'
   result = subprocess.run([sys.executable, str(ROOT / 'fwtool.py'), 'unpack',
                            '-f', str(source), '-o', str(output)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
   self.assertEqual(result.returncode, 0, result.stdout)
   config = yaml.safe_load((output / 'config.yaml').read_text())
   self.assertEqual(config['fdat'], {
    'model': 0x20030014, 'region': 0, 'version': '2.01', 'isAccessory': False,
   })
   self.assertEqual(config['dat']['crypterName'], 'CXD90057_k8')
   self.assertFalse(config['dat']['isLens'])
   for name, (size, digest) in OUTPUTS.items():
    with self.subTest(output=name):
     self.assertEqual((output / name).stat().st_size, size)
     self.assertEqual(sha256(output / name), digest)
   partitions = output / 'firmware.tar_unpacked/0700_part_image/dev'
   for name in ['nflasha3', 'nflasha7', 'nflasha8', 'nflasha15']:
    self.assertTrue(any((partitions / (name + '_unpacked')).rglob('*')), name)
   self.assertGreater((output / 'updater.img_unpacked/bodylib/libupdaterbody.so').stat().st_size, 0)
   self.assertTrue((output / 'firmware.tar_unpacked/0750_nor_loader/loader_nor.tar_unpacked/loader_nor.bin').is_file())
   # Check WBI2 output against the raw table independently of the new reader.
   self.assertEqual((partitions / 'nflasha5').stat().st_size, 267171648)
   with (partitions / 'nflasha5').open('rb') as file:
    self.assertEqual(file.read(4), b'WBI2')
   memory = partitions / 'nflasha5_unpacked'
   mapping = yaml.safe_load((memory / 'memory.yaml').read_text())
   self.assertEqual(len(mapping['sections']), 1181)
   self.assertEqual(sum(s['size'] for s in mapping['sections']), 292888576)
   flat = Path(tmp) / 'memory'
   exported = subprocess.run([sys.executable, str(ROOT / 'tools/wbi2_memory.py'),
                              '-f', str(partitions / 'nflasha5'), '-o', str(flat)],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
   self.assertEqual(exported.returncode, 0, exported.stdout)
   flatMapping = yaml.safe_load((flat / 'memory.yaml').read_text())
   self.assertEqual(flatMapping['baseAddress'], 0x400001000)
   self.assertEqual(flatMapping['resumeVector'], 0x4004a67f0)
   self.assertEqual(flatMapping['capturedBytes'], 292888576)
   self.assertEqual(flatMapping['imageSize'], 570421248)
   self.assertEqual((flat / 'memory.img').stat().st_size, flatMapping['imageSize'])
   self.assertEqual(sha256(flat / 'memory.img'),
                    '00899f2277c52a09fe138c4b28140d2556680fb837aa682e97171e15f9516687')
   with (partitions / 'nflasha5').open('rb') as raw:
    raw.seek(266834432)
    entries = list(struct.iter_unpack('<8Q', raw.read(1181*64)))
    self.assertEqual(mapping['sections'], [
     {'file': '0x%08x.dat' % entry[0], 'physicalAddr': entry[0],
      'virtualAddr': entry[5], 'size': entry[4]} for entry in entries
    ])
    self.assertEqual(flatMapping['sections'], sorted([
     {'physicalAddr': entry[0], 'virtualAddr': entry[5],
      'offset': entry[0] - flatMapping['baseAddress'], 'size': entry[4]} for entry in entries
    ], key=lambda section: section['physicalAddr']))
    offset = 512
    for addr, size, checksum, flag, originalSize, virt, metaChecksum, padding in entries:
     file = memory / ('0x%08x.dat' % addr)
     self.assertEqual(file.stat().st_size, originalSize)
     raw.seek(offset)
     with file.open('rb') as extracted:
      remaining = originalSize
      while remaining:
       n = min(remaining, 65536)
       expected = b'\0' * n if flag & 1 else raw.read(n)
       self.assertEqual(extracted.read(n), expected, hex(addr))
       remaining -= n
     offset += size
    self.assertEqual(offset, 266834432)


if __name__ == '__main__':
 unittest.main()
