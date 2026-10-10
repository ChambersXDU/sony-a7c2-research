"""Opt-in test of the official ILCE-7CM2 2.01 download; no firmware fixture."""

import hashlib
import os
from pathlib import Path
import shutil
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
  # Output is about 3.84 GiB; keep room for filesystem overhead.
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
   # WBI2 is preserved as a raw partition, not claimed as a parsed filesystem.
   self.assertEqual((partitions / 'nflasha5').stat().st_size, 267171648)
   with (partitions / 'nflasha5').open('rb') as file:
    self.assertEqual(file.read(4), b'WBI2')
   self.assertFalse((partitions / 'nflasha5_unpacked').exists())


if __name__ == '__main__':
 unittest.main()
