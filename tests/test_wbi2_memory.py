import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml
from tests.test_wbi2 import replace_section, sample_wbi2
from tools.wbi2_memory import exportMemory

ROOT = Path(__file__).resolve().parents[1]


class MemoryExportTests(unittest.TestCase):
 def test_physical_offsets_zero_sections_and_uncaptured_gaps(self):
  image = io.BytesIO(b'old contents' * 1000)
  mapping = exportMemory(io.BytesIO(sample_wbi2()), image)
  self.assertEqual(mapping['baseAddress'], 0x400001000)
  self.assertEqual(mapping['imageSize'], 0x4200)
  self.assertEqual(mapping['capturedBytes'], 1536)
  self.assertEqual(mapping['resumeVector'], 0x400001000)
  self.assertEqual([s['offset'] for s in mapping['sections']], [0, 0x2000, 0x4000])
  self.assertIn('Uncaptured', mapping['gapMeaning'])
  self.assertEqual(image.getvalue()[:512], bytes(range(256)) * 2)
  self.assertEqual(image.getvalue()[512:], b'\0' * (0x4200-512))

 def test_overlap_is_rejected_before_output_changes(self):
  source = replace_section(sample_wbi2(), 1, 0, 0x400001100)
  image = io.BytesIO(b'preserve')
  with self.assertRaisesRegex(ValueError, 'Overlapping'):
   exportMemory(io.BytesIO(source), image)
  self.assertEqual(image.getvalue(), b'preserve')

 def test_cli_creates_image_and_map_and_refuses_overwrite(self):
  with tempfile.TemporaryDirectory(prefix='fwtool-memory-') as tmp:
   source = Path(tmp) / 'snapshot.wbi'
   source.write_bytes(sample_wbi2())
   output = Path(tmp) / 'snapshot'
   args = [sys.executable, str(ROOT / 'tools/wbi2_memory.py'), '-f', str(source), '-o', str(output)]
   result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
   self.assertEqual(result.returncode, 0, result.stdout)
   self.assertEqual((output/'memory.img').stat().st_size, 0x4200)
   self.assertEqual(yaml.safe_load((output/'memory.yaml').read_text())['baseAddress'], 0x400001000)
   again = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
   self.assertNotEqual(again.returncode, 0)
   self.assertIn('already exists', again.stdout)

 def test_invalid_input_leaves_no_output_directory(self):
  with tempfile.TemporaryDirectory(prefix='fwtool-memory-') as tmp:
   source = Path(tmp) / 'snapshot.wbi'
   source.write_bytes(b'WBI2')
   output = Path(tmp) / 'snapshot'
   result = subprocess.run([sys.executable, str(ROOT/'tools/wbi2_memory.py'),
                            '-f', str(source), '-o', str(output)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
   self.assertNotEqual(result.returncode, 0)
   self.assertFalse(output.exists())


if __name__ == '__main__':
 unittest.main()
