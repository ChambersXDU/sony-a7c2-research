import gzip
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml
from fwtool.sony import constants
from tests.samples import cbc_fdat, dat_container, plain_fdat

ROOT = Path(__file__).resolve().parents[1]


class UnpackCommandTests(unittest.TestCase):
 def test_synthetic_dat_and_nested_archives(self):
  contents = b'synthetic nested archive contents'
  nested = gzip.compress(contents, mtime=0)
  firmware = io.BytesIO()
  with tarfile.open(fileobj=firmware, mode='w', format=tarfile.USTAR_FORMAT) as tar:
   member = tarfile.TarInfo('payload.gz')
   member.size = len(nested)
   member.mode = 0o644
   tar.addfile(member, io.BytesIO(nested))
  payload = plain_fdat(firmware=firmware.getvalue())
  with tempfile.TemporaryDirectory(prefix='fwtool-synthetic-') as tmp:
   source = Path(tmp) / 'BODYDATA.DAT'
   output = Path(tmp) / 'unpacked'
   source.write_bytes(dat_container(cbc_fdat(payload, constants.key_cxd90057_k8)))
   result = subprocess.run([sys.executable, str(ROOT / 'fwtool.py'), 'unpack',
                            '-f', str(source), '-o', str(output)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
   self.assertEqual(result.returncode, 0, result.stdout)
   config = yaml.safe_load((output / 'config.yaml').read_text())
   self.assertEqual(config['dat']['crypterName'], 'CXD90057_k8')
   self.assertEqual(config['fdat']['model'], 0x12345678)
   self.assertEqual(config['fdat']['version'], '2.01')
   self.assertEqual((output / 'firmware.fdat').read_bytes(), payload)
   self.assertEqual((output / 'firmware.tar').read_bytes(), firmware.getvalue())
   self.assertEqual((output / 'updater.img').read_bytes(), b'test updater')
   self.assertEqual((output / 'firmware.tar_unpacked/payload.gz_unpacked').read_bytes(), contents)


if __name__ == '__main__':
 unittest.main()
