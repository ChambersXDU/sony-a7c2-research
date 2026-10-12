import hashlib
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import yaml
from tests.test_wbi2 import replace_section, sample_wbi2
from tools.wbi2_lime import exportLime

ROOT = Path(__file__).resolve().parents[1]


class LimeExportTests(unittest.TestCase):
 def test_independent_headers_payloads_zero_provenance_and_gaps(self):
  output = io.BytesIO(b'old' * 1000)
  mapping = exportLime(io.BytesIO(sample_wbi2()), output)
  data = output.getvalue()
  offset = 0
  for addr, payload in [(0x400001000, bytes(range(256)) * 2),
                        (0x400003000, b'\0' * 512), (0x400005000, b'\0' * 512)]:
   self.assertEqual(struct.unpack_from('<IIQQQ', data, offset), (0x4c694d45, 1, addr, addr + 511, 0))
   self.assertEqual(data[offset + 32:offset + 544], payload)
   offset += 544
  self.assertEqual(len(data), offset)
  self.assertEqual(mapping['imageSize'], 1632)
  self.assertEqual(mapping['capturedBytes'], 1536)
  self.assertEqual([s['wbi2Zero'] for s in mapping['sections']], [False, True, False])
  self.assertEqual(mapping['gaps'], [{'physicalAddr': 0x400001200, 'size': 7680},
                                    {'physicalAddr': 0x400003200, 'size': 7680}])

 def test_overlap_and_malformed_input_preserve_output(self):
  for source in [replace_section(sample_wbi2(), 1, 0, 0x400001100), sample_wbi2()[:-1], b'WBI2']:
   output = io.BytesIO(b'preserve')
   with self.assertRaises(ValueError):
    exportLime(io.BytesIO(source), output)
   self.assertEqual(output.getvalue(), b'preserve')

 def test_unsorted_input_and_top_of_64bit_address_space(self):
  source = replace_section(sample_wbi2(), 0, 0, (1 << 64) - 512)
  output = io.BytesIO()
  mapping = exportLime(io.BytesIO(source), output)
  self.assertEqual([s['physicalAddr'] for s in mapping['sections']], [0x400003000, 0x400005000, (1 << 64) - 512])
  self.assertEqual(struct.unpack_from('<IIQQQ', output.getvalue(), 1088)[3], (1 << 64) - 1)
  self.assertEqual(output.getvalue()[1120:], bytes(range(256)) * 2)

 def test_cli_publication_overwrite_and_invalid_input(self):
  with tempfile.TemporaryDirectory() as tmp:
   source, output = Path(tmp) / 'snapshot', Path(tmp) / 'out'
   source.write_bytes(sample_wbi2())
   args = [sys.executable, str(ROOT / 'tools/wbi2_lime.py'), '-f', str(source), '-o', str(output)]
   first = subprocess.run(args, capture_output=True, text=True, timeout=60)
   self.assertEqual(first.returncode, 0, first.stderr)
   self.assertEqual((output / 'memory.lime').stat().st_size, 1632)
   mapping = yaml.safe_load((output / 'memory.yaml').read_text())
   self.assertEqual(mapping['sourceSha256'], hashlib.sha256(source.read_bytes()).hexdigest())
   self.assertNotEqual(subprocess.run(args, capture_output=True, timeout=60).returncode, 0)
   source.write_bytes(b'WBI2')
   args[-1] = str(Path(tmp) / 'bad')
   self.assertNotEqual(subprocess.run(args, capture_output=True, timeout=60).returncode, 0)
   self.assertFalse((Path(tmp) / 'bad').exists())


class VolatilityLimeTests(unittest.TestCase):
 def test_native_layer_uses_high_physical_addresses_and_refuses_holes(self):
  try:
   from volatility3.framework import contexts, exceptions
   from volatility3.framework.layers import physical, lime
  except ImportError:
   self.skipTest('Install requirements-forensics.txt for third-party layer tests')
  with tempfile.TemporaryDirectory() as tmp:
   path = Path(tmp) / 'memory.lime'
   with path.open('w+b') as output:
    exportLime(io.BytesIO(sample_wbi2()), output)
   context = contexts.Context()
   context.config['file.location'] = path.as_uri()
   file = physical.FileLayer(context, 'file', 'file')
   context.layers.add_layer(file)
   try:
    layer = lime.LimeStacker.stack(context, 'file')
    context.layers.add_layer(layer)
    self.assertEqual(layer.minimum_address, 0x400001000)
    self.assertEqual(layer.read(0x400001000, 512), bytes(range(256)) * 2)
    self.assertEqual(layer.read(0x400003000, 512), b'\0' * 512)
    for addr in [0, 0x400001200, 0x400002fff, 0x400003200, 0x400005200]:
     self.assertFalse(layer.is_valid(addr))
     with self.assertRaises(exceptions.InvalidAddressException):
      layer.read(addr, 1)
    with self.assertRaises(exceptions.InvalidAddressException):
     layer.read(0x4000011ff, 2)
   finally:
    file.destroy()
