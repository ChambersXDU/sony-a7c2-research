#!/usr/bin/env python3
"""Export a WBI2 snapshot to a sparse image with an explicit physical address map."""

import argparse
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fwtool.sony import wbi
import yaml


def exportMemory(file, imageFile):
 chunks = sorted(wbi.readWbi2(file), key=lambda chunk: chunk.physicalAddr)
 if not chunks:
  raise ValueError('No WBI2 memory sections')
 baseAddress = chunks[0].physicalAddr
 endAddress = baseAddress
 for chunk in chunks:
  if chunk.physicalAddr < endAddress:
   raise ValueError('Overlapping WBI2 memory sections')
  endAddress = chunk.physicalAddr + chunk.size
 imageSize = endAddress - baseAddress
 imageFile.seek(0)
 imageFile.truncate(0)
 sections = []
 for chunk in chunks:
  offset = chunk.physicalAddr - baseAddress
  imageFile.seek(offset)
  shutil.copyfileobj(chunk.contents, imageFile)
  sections.append({'physicalAddr': chunk.physicalAddr, 'virtualAddr': chunk.virtualAddr,
                   'offset': offset, 'size': chunk.size})
 imageFile.truncate(imageSize)
 header = wbi.Wbi2Header.unpack(file)
 return {'baseAddress': baseAddress, 'imageSize': imageSize,
         'capturedBytes': sum(chunk.size for chunk in chunks), 'resumeVector': header.resumeVector,
         'gapMeaning': 'Uncaptured memory; zero bytes in gaps do not prove original contents.',
         'sections': sections}


def main():
 parser = argparse.ArgumentParser(description=__doc__)
 parser.add_argument('-f', required=True, help='input WBI2 partition')
 parser.add_argument('-o', required=True, help='new output directory for memory.img and memory.yaml')
 args = parser.parse_args()
 output = Path(args.o).resolve()
 if output.exists():
  parser.error('Output directory already exists')
 output.parent.mkdir(parents=True, exist_ok=True)
 with open(args.f, 'rb') as file:
  chunks = list(wbi.readWbi2(file))
  if sum(chunk.size for chunk in chunks) > shutil.disk_usage(output.parent).free:
   raise ValueError('Not enough disk space for the captured WBI2 memory')
  with tempfile.TemporaryDirectory(prefix='.wbi2-', dir=str(output.parent)) as tmp:
   with open(Path(tmp) / 'memory.img', 'w+b') as imageFile:
    metadata = exportMemory(file, imageFile)
   with open(Path(tmp) / 'memory.yaml', 'w') as mapFile:
    yaml.safe_dump(metadata, mapFile, sort_keys=False)
   os.rename(tmp, output)
 print('Exported %d sections; base=0x%x, image size=%d bytes' %
       (len(metadata['sections']), metadata['baseAddress'], metadata['imageSize']))


if __name__ == '__main__':
 main()
