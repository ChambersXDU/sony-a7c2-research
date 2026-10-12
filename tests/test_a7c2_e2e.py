"""Opt-in test of the official ILCE-7CM2 2.01 download; no firmware fixture."""

from collections import Counter
import hashlib
import importlib.util
import json
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
   kernel = partitions / 'nflasha3_unpacked/vmlinux.bin'
   self.assertEqual(sha256(kernel), '620a6a3c2b4f09a3696f2fbf06bab98b49be5eaad6bdb366a1f33319fcb6e9d2')
   symbolOutput = Path(tmp) / 'kernel-symbols'
   exported = subprocess.run([sys.executable, str(ROOT / 'tools/kernel_symbols.py'),
                              '-f', str(kernel), '-o', str(symbolOutput),
                              '--snapshot', str(partitions / 'nflasha5'), '--physical-base', '0x400080000'],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
   self.assertEqual(exported.returncode, 0, exported.stdout)
   metadata = json.loads((symbolOutput / 'analysis.json').read_text())
   self.assertEqual(metadata['symbolCount'], 41265)
   self.assertEqual(metadata['baseAddress'], 0xffffff8008080000)
   symbols = json.loads((symbolOutput / 'symbols.json').read_text())
   lookup = {s['name']:s['address'] for s in symbols}
   self.assertEqual(lookup['cxd90057_resume_ssboot'], 0xffffff80084a67f0)
   self.assertEqual(lookup['linux_banner'], 0xffffff80084b0090)
   comparison = json.loads((symbolOutput / 'snapshot-comparison.json').read_text())
   self.assertEqual(comparison['pages'], {'matched':1004,'changed':68,'uncaptured':0})
   self.assertEqual(comparison['resumeSymbols'], ['cxd90057_resume_ssboot'])
   self.assertEqual(Counter(c['classification'] for c in comparison['changes']),
                    {'static-key':131,'alternative-site':16})
   elf = (symbolOutput / 'kernel.elf').read_bytes()
   self.assertEqual(elf[4096:4096+kernel.stat().st_size], kernel.read_bytes())
   # Independently anchor Image code to captured physical memory, not a guessed base.
   with kernel.open('rb') as original, (flat / 'memory.img').open('rb') as captured:
    for offset in [0, 0x800, 0x95d78, 0x4262a0, 0x4267f0, 0x430090]:
     original.seek(offset)
     captured.seek(0x400080000 + offset - flatMapping['baseAddress'])
     self.assertEqual(captured.read(64), original.read(64), hex(offset))
   self.verify_forensics(Path(tmp), partitions, kernel, entries)

 def verify_forensics(self, tmp, partitions, kernel, entries):
  lime = tmp / 'lime'
  result = subprocess.run([sys.executable, str(ROOT / 'tools/wbi2_lime.py'),
                           '-f', str(partitions / 'nflasha5'), '-o', str(lime)],
                          capture_output=True, text=True, timeout=300)
  self.assertEqual(result.returncode, 0, result.stderr)
  image = lime / 'memory.lime'
  mapping = yaml.safe_load((lime / 'memory.yaml').read_text())
  self.assertEqual(image.stat().st_size, 292926368)
  self.assertEqual(sha256(image), '3d5292bd82685355ff5538e1b8349dd6408d6196880741132138158a9efabb14')
  self.assertEqual(mapping['capturedBytes'], 292888576)
  self.assertEqual(mapping['sourceSha256'], 'db3730c8dbb2de71cfb7a66c343ba8e752e0f374a3a4104196ceac1e9d1b08dc')
  self.assertEqual(len(mapping['gaps']), 1140)
  self.assertEqual(sum(g['size'] for g in mapping['gaps']), 277532672)
  self.assertEqual(sum(s['size'] for s in mapping['sections'] if s['wbi2Zero']), 26054656)
  # Read the original raw descriptor table and every payload independently.
  payloadOffsets, offset = {}, 512
  for entry in entries:
   payloadOffsets[entry[0]] = offset
   offset += entry[1]
  with image.open('rb') as exported, (partitions / 'nflasha5').open('rb') as raw:
   for entry, section in zip(sorted(entries), mapping['sections']):
    addr, storedSize, _, flag, size, virt, _, _ = entry
    self.assertEqual(struct.unpack('<IIQQQ', exported.read(32)), (0x4c694d45, 1, addr, addr + size - 1, 0))
    self.assertEqual(section, {'physicalAddr': addr, 'virtualAddr': virt,
                              'offset': exported.tell(), 'size': size, 'wbi2Zero': bool(flag & 1)})
    raw.seek(payloadOffsets[addr])
    remaining = size
    while remaining:
     n = min(remaining, 65536)
     self.assertEqual(exported.read(n), b'\0' * n if flag & 1 else raw.read(n), hex(addr))
     remaining -= n
   self.assertEqual(exported.read(), b'')
  if importlib.util.find_spec('volatility3'):
   from volatility3.framework import contexts, exceptions
   from volatility3.framework.layers import physical, lime as limeLayers
   context = contexts.Context()
   context.config['file.location'] = image.as_uri()
   file = physical.FileLayer(context, 'file', 'file')
   context.layers.add_layer(file)
   try:
    layer = limeLayers.LimeStacker.stack(context, 'file')
    context.layers.add_layer(layer)
    for section in mapping['sections']:
     self.assertTrue(layer.is_valid(section['physicalAddr'], section['size']))
    for gap in mapping['gaps']:
     for addr in [gap['physicalAddr'], gap['physicalAddr'] + gap['size'] - 1]:
      self.assertFalse(layer.is_valid(addr))
      with self.assertRaises(exceptions.InvalidAddressException):
       layer.read(addr, 1)
   finally:
    file.destroy()
   banners = subprocess.run([sys.executable, '-c',
                             'import sys; sys.argv[0] = "vol"; from volatility3.cli import main; main()',
                             '-q', '--offline', '-f', str(image), '-r', 'json', 'banners.Banners'],
                            capture_output=True, text=True, timeout=120)
   self.assertEqual(banners.returncode, 0, banners.stderr)
   rows = json.loads(banners.stdout)
   self.assertEqual(len(rows), 1)
   self.assertEqual(rows[0]['Offset'], 0x4004b0090)
   self.assertTrue(rows[0]['Banner'].startswith('Linux version 4.9.337-scel+'))
  # Opt-in source/tool dependencies regenerate the DWARF profile, rather than
  # silently relying on a pre-existing local profile.
  if os.environ.get('SONY_A7C2_SOURCE'):
   profile = tmp / 'profile'
   for name in ['SONY_A7C2_CLANG', 'SONY_DWARF2JSON']:
    self.assertTrue(os.environ.get(name), 'Set ' + name + ' for full source-based forensics validation')
   build = subprocess.run([sys.executable, str(ROOT / 'tools/kernel_printk_profile.py'),
                           '--source', os.environ['SONY_A7C2_SOURCE'], '--kernel', str(kernel),
                           '--clang', os.environ['SONY_A7C2_CLANG'], '--dwarf2json', os.environ['SONY_DWARF2JSON'],
                           '--tasks', '-o', str(profile)], capture_output=True, text=True, timeout=600)
   self.assertEqual(build.returncode, 0, build.stderr)
   from tools.volatility_wbi2 import analyseLime
   report, logs, tasks = analyseLime(image, kernel, profile)
   self.assertEqual(report['capturedSections'], 1181)
   self.assertEqual(report['unmappedGaps'], 1140)
   self.assertEqual(report['ring']['log_buf'], 0xffffff80086e7538)
   self.assertEqual(report['ring']['records'], 573)
   self.assertEqual(report['ring']['activeBytes'], 37212)
   self.assertEqual(len(logs), 672)
   self.assertEqual(logs[0]['line'], 'Booting Linux on physical CPU 0x0')
   self.assertEqual(logs[-1]['line'], 'WBI: count_sections_p2:1181, 71506, 11764a00(11764a00)')
   self.assertEqual(71506 * 4096, mapping['capturedBytes'])
   self.assertEqual(len(tasks), 286)
   self.assertEqual([(t['pid'], t['comm']) for t in tasks[:2]], [(1, 'init2'), (2, 'kthreadd')])
   self.assertEqual(report['tasks']['checkedOffsets'], {'tasks': 648, 'pid': 904, 'tgid': 908, 'comm': 1336})


if __name__ == '__main__':
 unittest.main()
