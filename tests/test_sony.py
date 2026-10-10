import io
import struct
import unittest
from pathlib import Path

import yaml
from Cryptodome.Cipher import AES

from fwtool.sony import constants, dat, fdat
from tests.samples import block_payload, cbc_fdat, dat_container, plain_fdat

ROOT = Path(__file__).resolve().parents[1]


class DeviceTests(unittest.TestCase):
 def test_schema_and_existing_models(self):
  class UniqueLoader(yaml.SafeLoader):
   pass
  def mapping(loader, node):
   result = {}
   for key, value in node.value:
    name = loader.construct_object(key)
    if name in result:
     raise ValueError('Duplicate device field: ' + name)
    result[name] = loader.construct_object(value)
   return result
  UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
  devices = yaml.load((ROOT / 'devices.yml').read_text(), Loader=UniqueLoader)
  for name, config in devices.items():
   with self.subTest(device=name):
    self.assertIsInstance(config['arch'], str)
    self.assertIs(type(config['model']), int)
    self.assertTrue(0 <= config['model'] <= 0xffffffff)
    if 'key' in config:
     self.assertIsInstance(config['key'], str)
  self.assertEqual(devices['ILCE-7M4'], {'arch': 'CXD90057', 'model': 0x01030081})
  self.assertEqual(devices['ILCE-7']['model'], 0x41030013)

 def test_ilce_7cm2_verified_metadata(self):
  devices = yaml.safe_load((ROOT / 'devices.yml').read_text())
  self.assertEqual(devices['ILCE-7CM2'], {
   'arch': 'CXD90057', 'key': 'k8', 'model': 0x20030014,
  })
  config = devices['ILCE-7CM2']
  self.assertIn(config['arch'] + '_' + config['key'], fdat._crypters)


class CrypterTests(unittest.TestCase):
 def test_cxd90057_keys_and_cbc_continuation(self):
  payload = plain_fdat(firmware=bytes(range(256)) * 12)
  for name, key in [('CXD90057_k0', constants.key_cxd90057_k0),
                    ('CXD90057_k8', constants.key_cxd90057_k8)]:
   with self.subTest(crypter=name):
    encrypted = cbc_fdat(payload, key)
    selected, decrypted = fdat.decryptFdat(io.BytesIO(encrypted))
    self.assertEqual(selected, name)
    self.assertEqual(decrypted.read(), payload)
    decrypted.seek(0)
    self.assertEqual(decrypted.read(), payload)

 def test_cbc_checksum_error(self):
  payload = plain_fdat(firmware=b'X' * 2500)
  packed = bytearray(block_payload(payload))
  packed[1024+10] ^= 1
  encrypted = cbc_fdat(payload, constants.key_cxd90057_k8, packed=bytes(packed))
  decrypted = fdat._crypters['CXD90057_k8']().decrypt(io.BytesIO(encrypted))
  with self.assertRaisesRegex(fdat.BlockCryptException, 'Wrong checksum'):
   decrypted.read()

 def test_last_block_flag_error(self):
  packed = bytearray(block_payload(plain_fdat()))
  packed[3] ^= 0x80
  struct.pack_into('<H', packed, 0, sum(struct.unpack('<511H', packed[2:])) & 0xffff)
  encrypted = cbc_fdat(b'', constants.key_cxd90057_k8, packed=bytes(packed))
  with self.assertRaisesRegex(fdat.BlockCryptException, 'Wrong last block flag'):
   fdat._crypters['CXD90057_k8']().decrypt(io.BytesIO(encrypted)).read()

 def test_truncated_encrypted_blocks(self):
  encrypted = cbc_fdat(plain_fdat(), constants.key_cxd90057_k8)
  for sample in [b'', b'\0', encrypted[:-1], encrypted[:-273]]:
   with self.subTest(size=len(sample)):
    with self.assertRaisesRegex(Exception, 'No decrypter found'):
     fdat.decryptFdat(io.BytesIO(sample))

 def test_legacy_aes_and_double_aes(self):
  payload = plain_fdat(firmware=b'X' * 2500)
  packed = block_payload(payload)
  for name, key in [('CXD4132', None), ('CXD90014', constants.key_cxd90014)]:
   with self.subTest(crypter=name):
    if key is None:
     encrypted = AES.new(constants.key_cxd4132, AES.MODE_ECB).encrypt(packed)
    else:
     inner = AES.new(key, AES.MODE_ECB).encrypt(packed[512:])
     encrypted = AES.new(constants.key_aes, AES.MODE_ECB).encrypt(packed[:512] + inner)
    selected, result = fdat.decryptFdat(io.BytesIO(encrypted))
    self.assertEqual(selected, name)
    self.assertEqual(result.read(), payload)

 def test_existing_cxd90045_cbc_keys(self):
  payload = plain_fdat(firmware=b'X' * 2500)
  for name, key in [('CXD90045_k0', constants.key_cxd90045_k0),
                    ('CXD90045_k8', constants.key_cxd90045_k8)]:
   with self.subTest(crypter=name):
    selected, result = fdat.decryptFdat(io.BytesIO(cbc_fdat(payload, key)))
    self.assertEqual(selected, name)
    self.assertEqual(result.read(), payload)

 def test_cbc_encryption_is_unsupported(self):
  with self.assertRaisesRegex(Exception, 'Encryption not supported'):
   fdat._crypters['CXD90057_k8']().encrypt(io.BytesIO())


class FormatTests(unittest.TestCase):
 def test_headers_and_metadata(self):
  payload = plain_fdat()
  wrapped = dat_container(payload)
  self.assertTrue(dat.isDat(io.BytesIO(wrapped)))
  self.assertTrue(fdat.isFdat(io.BytesIO(payload)))
  parsed = fdat.readFdat(io.BytesIO(payload))
  self.assertEqual((parsed.model, parsed.region, parsed.version), (0x12345678, 0, '2.01'))
  self.assertEqual(parsed.firmware.read(), b'test firmware')
  self.assertEqual(dat.readDat(io.BytesIO(wrapped)).firmwareData.read(), payload)
  for sample in [b'', b'garbage', b'UDTRFIRM', b'\x89UFU']:
   self.assertFalse(dat.isDat(io.BytesIO(sample)))
   self.assertFalse(fdat.isFdat(io.BytesIO(sample)))

 def test_dat_checksum_error(self):
  sample = bytearray(dat_container(plain_fdat()))
  sample[-1] ^= 1
  with self.assertRaisesRegex(Exception, 'Wrong checksum'):
   dat.readDat(io.BytesIO(sample))

 def test_fdat_checksum_error(self):
  sample = bytearray(plain_fdat())
  sample[36] ^= 1
  with self.assertRaisesRegex(Exception, 'Wrong checksum'):
   fdat.readFdat(io.BytesIO(sample))

 def test_truncated_dat(self):
  sample = dat_container(plain_fdat())
  for cut in [0, 7, 8, 15, 19, len(sample)-1, len(sample)-12]:
   with self.subTest(cut=cut):
    with self.assertRaisesRegex(ValueError, 'Truncated DAT'):
     dat.readDat(io.BytesIO(sample[:cut]))

 def test_truncated_fdat(self):
  sample = plain_fdat()
  for cut in [0, 8, 511, len(sample)-1]:
   with self.subTest(cut=cut):
    with self.assertRaisesRegex(ValueError, 'Truncated FDAT'):
     fdat.readFdat(io.BytesIO(sample[:cut]))

 def test_ext2_detection_regression(self):
  from fwtool.archive.ext2 import isExt2
  image = bytearray(4096)
  struct.pack_into('<I', image, 1028, 4)
  struct.pack_into('<I', image, 1056, 4)
  struct.pack_into('<I', image, 1064, 8)
  image[1080:1082] = b'\x53\xef'
  self.assertTrue(isExt2(io.BytesIO(image)))
  self.assertFalse(isExt2(io.BytesIO(image[:-1])))
  struct.pack_into('<I', image, 1048, 31)
  self.assertFalse(isExt2(io.BytesIO(image)))


if __name__ == '__main__':
 unittest.main()
