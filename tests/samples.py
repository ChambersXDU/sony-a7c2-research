"""Small synthetic fixtures; no Sony firmware contents."""

import binascii
import struct

from Cryptodome.Cipher import AES
from fwtool.sony import constants


def plain_fdat(model=0x12345678, region=0, version=(2, 1), firmware=b'test firmware', fs=b'test updater'):
 header = bytearray(512)
 header[:8] = b'UDTRFIRM'
 header[12:16] = b'0100'
 header[16] = ord('U')
 header[20] = ord('N')
 struct.pack_into('<BB', header, 32, version[1], version[0])
 struct.pack_into('<II', header, 36, model, region)
 struct.pack_into('<III', header, 48, 512 + len(fs), len(firmware), 2)
 struct.pack_into('<c3xII4x', header, 64, b'U', 512, len(fs))
 struct.pack_into('<c3xII4x', header, 80, b'P', 512, 0)
 struct.pack_into('<I', header, 8, binascii.crc32(header[12:]) & 0xffffffff)
 return bytes(header) + fs + firmware


def block_payload(payload):
 blocks = []
 for offset in range(0, len(payload), 1020):
  part = payload[offset:offset+1020]
  size = len(part) | (0x8000 if offset + 1020 >= len(payload) else 0)
  body = struct.pack('<H', size) + part + b'\xff' * (1020-len(part))
  checksum = sum(struct.unpack('<511H', body)) & 0xffff
  blocks.append(struct.pack('<H', checksum) + body)
 return b''.join(blocks)


def cbc_fdat(payload, key, iv=bytes(range(16)), packed=None):
 # First 512 bytes use ECB; the remaining blocks share a single CBC chain.
 blocks = block_payload(payload) if packed is None else packed
 return (AES.new(constants.key_aes, AES.MODE_ECB).encrypt(blocks[:512])
         + AES.new(key, AES.MODE_CBC, iv).encrypt(blocks[512:])
         + iv + b'\0' * 256)


def dat_container(payload):
 data = b'\x89UFU\r\n\x1a\n'
 for kind, body in [(b'DATV', b'\x01\x00\x00\x00'),
                    (b'PROV', b'\x01\x00\x00\x00'),
                    (b'UDID', b'\0' * 4), (b'FDAT', payload)]:
  data += struct.pack('>I4s', len(body), kind) + body
 return data + struct.pack('>I4sI', 4, b'DEND', binascii.crc32(data) & 0xffffffff)
