#!/usr/bin/env python3
"""Export captured WBI2 ranges as LiME v1; absent ranges remain unmapped."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fwtool.sony import wbi
import yaml

LIME_HEADER = struct.Struct('<IIQQQ')
LIME_MAGIC = 0x4c694d45


def capturedSections(file):
 chunks = sorted(wbi.readWbi2(file), key=lambda c: c.physicalAddr)
 if not chunks:
  raise ValueError('No WBI2 memory sections')
 end = 0
 for chunk in chunks:
  if chunk.physicalAddr < end:
   raise ValueError('Overlapping WBI2 memory sections')
  end = chunk.physicalAddr + chunk.size
 return chunks


def exportLime(file, imageFile):
 chunks = capturedSections(file)
 header = wbi.Wbi2Header.unpack(file)
 descriptors = [wbi.Wbi2SectionHeader.unpack(
  file, header.sectorSize + header.dataSize + i * wbi.Wbi2SectionHeader.size)
  for i in range(header.numSections)]
 zero = {d.addr for d in descriptors if d.flag & wbi.wbi2SectionZero}
 imageFile.seek(0)
 imageFile.truncate(0)
 sections, gaps = [], []
 end = chunks[0].physicalAddr
 for chunk in chunks:
  if chunk.physicalAddr > end:
   gaps.append({'physicalAddr': end, 'size': chunk.physicalAddr - end})
  imageFile.write(LIME_HEADER.pack(LIME_MAGIC, 1, chunk.physicalAddr,
                                   chunk.physicalAddr + chunk.size - 1, 0))
  offset = imageFile.tell()
  shutil.copyfileobj(chunk.contents, imageFile)
  if imageFile.tell() != offset + chunk.size:
   raise ValueError('Truncated WBI2 section payload')
  sections.append({'physicalAddr': chunk.physicalAddr, 'virtualAddr': chunk.virtualAddr,
                   'offset': offset, 'size': chunk.size,
                   'wbi2Zero': chunk.physicalAddr in zero})
  end = chunk.physicalAddr + chunk.size
 return {'format': 'LiME v1', 'baseAddress': chunks[0].physicalAddr,
         'endAddress': end, 'imageSize': imageFile.tell(),
         'capturedBytes': sum(c.size for c in chunks), 'resumeVector': header.resumeVector,
         'gapMeaning': 'Uncaptured; omitted from LiME, not zero memory.',
         'gapScope': 'Only gaps within the captured span; total RAM extent is unknown.',
         'sections': sections, 'gaps': gaps}


def main():
 parser = argparse.ArgumentParser(description=__doc__)
 parser.add_argument('-f', required=True, help='input WBI2 partition')
 parser.add_argument('-o', required=True, help='new output directory for memory.lime and memory.yaml')
 args = parser.parse_args()
 source, output = Path(args.f).resolve(), Path(args.o).resolve()
 if output.exists():
  parser.error('Output directory already exists')
 output.parent.mkdir(parents=True, exist_ok=True)
 with source.open('rb') as file:
  chunks = capturedSections(file)
  required = sum(c.size + LIME_HEADER.size for c in chunks)
  if required > shutil.disk_usage(output.parent).free:
   raise ValueError('Not enough disk space for captured WBI2 memory and LiME headers')
  digest = hashlib.sha256()
  file.seek(0)
  for block in iter(lambda: file.read(1024 * 1024), b''):
   digest.update(block)
  with tempfile.TemporaryDirectory(prefix='.wbi2-lime-', dir=str(output.parent)) as tmp:
   with (Path(tmp) / 'memory.lime').open('w+b') as image:
    metadata = exportLime(file, image)
   metadata['sourceSha256'] = digest.hexdigest()
   with (Path(tmp) / 'memory.yaml').open('w') as mapping:
    yaml.safe_dump(metadata, mapping, sort_keys=False)
   os.rename(tmp, output)
 print('Exported %d captured sections, %d bytes; %d unmapped gaps' %
       (len(metadata['sections']), metadata['capturedBytes'], len(metadata['gaps'])))


if __name__ == '__main__':
 main()
