"""Parser for warm boot images"""

from collections import namedtuple
import io

from .. import lz77
from ..io import *
from ..util import *

WbiChunk = namedtuple('WbiChunk', 'physicalAddr, virtualAddr, size, contents')

WbiHeader = Struct('WbiHeader', [
 ('magic', Struct.STR % 4),
 ('numSections', Struct.INT32),
 ('flag', Struct.INT32),
 ('resumeVector', Struct.INT32),
 ('version', Struct.INT32),
 ('sectorSize', Struct.INT32),
 ('dataSize', Struct.INT32),
 ('kernelStart', Struct.INT32),
 ('kernelSize', Struct.INT32),
 ('kernelChecksum', Struct.INT32),
 ('oDataSize', Struct.INT32),
])
wbiHeaderMagic = b'WBI1'
wbiHeaderVersion = 0x20060224
wbiFlagCompressed = 1

Wbi2Header = Struct('Wbi2Header', [
 ('magic', Struct.STR % 4),
 ('...', 4),
 ('numSections', Struct.INT64),
 ('flag', Struct.INT64),
 ('resumeVector', Struct.INT64),
 ('version', Struct.INT64),
 ('sectorSize', Struct.INT64),
 ('dataSize', Struct.INT64),
 ('kernelStart', Struct.INT64),
 ('kernelSize', Struct.INT64),
 ('kernelChecksum', Struct.INT64),
 ('oDataSize', Struct.INT64),
])
wbi2HeaderMagic = b'WBI2'

Wbi2SectionHeader = Struct('Wbi2SectionHeader', [
 ('addr', Struct.INT64),
 ('size', Struct.INT64),
 ('checksum', Struct.INT64),
 ('flag', Struct.INT64),
 ('osize', Struct.INT64),
 ('virt', Struct.INT64),
 ('metaChecksum', Struct.INT64),
 ('...', 8),
])
wbi2FlagNotKernelRo = 2
wbi2SectionZero = 1

def isWbi2(file):
 header = Wbi2Header.unpack(file)
 return header and header.magic == wbi2HeaderMagic

def readWbi2(file):
 """Reads uncompressed 64-bit WBI2 sections, including omitted zero pages"""
 header = Wbi2Header.unpack(file)
 if not header:
  raise ValueError('Truncated WBI2 header')
 if header.magic != wbi2HeaderMagic:
  raise ValueError('Wrong WBI2 magic')
 if header.version != wbiHeaderVersion:
  raise ValueError('Wrong WBI2 version')
 if header.flag & ~wbi2FlagNotKernelRo:
  raise ValueError('Unsupported WBI2 flags (compressed or checksummed payload)')
 sectorSize = header.sectorSize
 if sectorSize < Wbi2Header.size or sectorSize & (sectorSize - 1) or header.dataSize % sectorSize:
  raise ValueError('Invalid WBI2 sector size or data alignment')

 file.seek(0, 2)
 fileSize = file.tell()
 tableOffset = sectorSize + header.dataSize
 if tableOffset > fileSize or header.numSections > (fileSize - tableOffset) // Wbi2SectionHeader.size:
  raise ValueError('Truncated WBI2 data or section table')

 sections = []
 offset = sectorSize
 totalSize = 0
 for i in range(header.numSections):
  section = Wbi2SectionHeader.unpack(file, tableOffset + i * Wbi2SectionHeader.size)
  # Sony's wb_section metadata checksum covers the first six unsigned longs.
  checksum = 0x0f0f0f0f
  for value in section[:6]:
   checksum ^= value
  if checksum != section.metaChecksum:
   raise ValueError('Wrong WBI2 section metadata checksum')
  if section.flag & ~wbi2SectionZero:
   raise ValueError('Unsupported WBI2 section flags')
  isZero = bool(section.flag & wbi2SectionZero)
  if not section.osize or section.osize % sectorSize or section.size != (0 if isZero else section.osize):
   raise ValueError('Invalid WBI2 section size')
  if section.addr + section.osize > 1 << 64 or section.virt + section.osize > 1 << 64:
   raise ValueError('Invalid WBI2 section address')
  sections.append((section, offset))
  offset += section.size
  totalSize += section.osize
 if offset != tableOffset or totalSize != header.oDataSize:
  raise ValueError('Wrong WBI2 total section size')

 for section, offset in sections:
  if section.flag & wbi2SectionZero:
   def generateZeros(size=section.osize):
    while size:
     n = min(size, 65536)
     yield b'\0' * n
     size -= n
   contents = ChunkedFile(generateZeros, section.osize)
  else:
   contents = FilePart(file, offset, section.size)
  yield WbiChunk(section.addr, section.virt, section.osize, contents)

WbiSectionHeader = Struct('WbiSectionHeader', [
 ('addr', Struct.INT32),
 ('size', Struct.INT32),
 ('checksum', Struct.INT32),
 ('flag', Struct.INT32),
 ('osize', Struct.INT32),
 ('virt', Struct.INT32),
 ('pad', Struct.INT32),
 ('metaChecksum', Struct.INT32),
])

def isWbi(file):
 header = WbiHeader.unpack(file)
 return (header and header.magic == wbiHeaderMagic) or isWbi2(file)

def readWbi(file):
 if isWbi2(file):
  for section in readWbi2(file):
   yield section
  return
 header = WbiHeader.unpack(file)

 if header.magic != wbiHeaderMagic:
  raise Exception('Wrong magic')

 if header.version != wbiHeaderVersion:
  raise Exception('Wrong version')

 if not (header.flag & wbiFlagCompressed):
  raise Exception('Uncompressed WBI is not supported')

 # Skip empty sectors:
 wbiHeaderSize = header.sectorSize
 while True:
  file.seek(wbiHeaderSize)
  sector = file.read(header.sectorSize)
  if sector != len(sector) * b'\0' and sector != len(sector) * b'\xff':
   break
  wbiHeaderSize += header.sectorSize

 offset = 0
 for i in range(header.numSections):
  section = WbiSectionHeader.unpack(file, wbiHeaderSize + header.dataSize + i * WbiSectionHeader.size)

  def generateChunks(offset=offset, section=section):
   file.seek(wbiHeaderSize + offset)
   block = io.BytesIO(file.read(section.size))
   read = 0
   while read < section.osize:
    contents = lz77.inflateLz77(block)
    yield contents
    read += len(contents)

  yield WbiChunk(section.addr, section.virt, section.osize, ChunkedFile(generateChunks))
  offset += section.size
