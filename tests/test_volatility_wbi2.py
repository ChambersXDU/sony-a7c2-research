import importlib.util
import struct
from types import SimpleNamespace
import unittest


@unittest.skipUnless(importlib.util.find_spec('volatility3'), 'Install requirements-forensics.txt')
class RingValidationTests(unittest.TestCase):
 def fixture(self, records, first, end, count):
  from tools.volatility_wbi2 import validateRing
  memory = bytearray(1 << 17)
  for offset, length, text, dictionary in records:
   struct.pack_into('<QHHHBB', memory, offset, 123, length, text, dictionary, 0, 6 << 5)
  class Layer:
   def is_valid(self, addr, size):
    return 0 <= addr <= addr + size <= len(memory)
   def read(self, addr, size):
    return memory[addr:addr + size]
  class Module:
   layer_name = 'test'
   def object_from_symbol(self, name):
    return {'log_buf': 0, 'log_buf_len': len(memory), 'log_first_idx': first,
            'log_next_idx': end, 'log_first_seq': 7, 'log_next_seq': 7 + count}[name]
   def object(self, type, offset, absolute):
    ts, length, text, dictionary, _, _ = struct.unpack_from('<QHHHBB', memory, offset)
    return SimpleNamespace(ts_nsec=ts, len=length, text_len=text, dict_len=dictionary)
  return validateRing, SimpleNamespace(layers={'test': Layer()}), Module()

 def test_wrapped_and_empty_rings(self):
  validate, context, module = self.fixture([(131008, 20, 4, 0), (131028, 0, 0, 0), (0, 20, 4, 0)], 131008, 20, 2)
  self.assertEqual(validate(context, module)['records'], 2)
  self.assertEqual(validate(context, module)['activeBytes'], 40)
  validate, context, module = self.fixture([], 0, 0, 0)
  self.assertEqual(validate(context, module)['records'], 0)

 def test_corrupt_lengths_wraps_and_sequence_counters_are_rejected(self):
  for records, first, end, count in [([(0, 0, 0, 0)], 0, 20, 1),
                                    ([(0, 12, 0, 0)], 0, 12, 1),
                                    ([(0, 20, 5, 0)], 0, 20, 1),
                                    ([(0, 20, 4, 0)], 0, 16, 1),
                                    ([(0, 20, 4, 0)], 0, 20, 2),
                                    ([(0, 20, 4, 0)], 0, 20, 0)]:
   with self.subTest(records=records, count=count):
    validate, context, module = self.fixture(records, first, end, count)
    with self.assertRaises(ValueError):
     validate(context, module)


@unittest.skipUnless(importlib.util.find_spec('volatility3'), 'Install requirements-forensics.txt')
class TaskValidationTests(unittest.TestCase):
 def fixture(self):
  from tools.volatility_wbi2 import validateTaskList
  memory = bytearray(640)
  offsets = {'tasks': 16, 'pid': 32, 'tgid': 36, 'comm': 40}
  for addr, next, prev, pid, comm in [(64, 272, 464, 0, b'swapper/0'),
                                    (256, 464, 80, 1, b'init'), (448, 80, 272, 2, b'kthreadd')]:
   struct.pack_into('<QQ', memory, addr + 16, next, prev)
   struct.pack_into('<ii', memory, addr + 32, pid, pid)
   memory[addr + 40:addr + 40 + len(comm)] = comm
  class Layer:
   def is_valid(self, addr, size):
    return 0 <= addr <= addr + size <= len(memory)
   def read(self, addr, size):
    return memory[addr:addr + size]
  taskType = SimpleNamespace(size=96, relative_child_offset=lambda n: offsets[n])
  module = SimpleNamespace(layer_name='test', get_type=lambda n: taskType,
                           get_symbol=lambda n: SimpleNamespace(address=64))
  return validateTaskList, SimpleNamespace(layers={'test': Layer()}), module, memory

 def test_reciprocal_list_and_candidate_fields(self):
  validate, context, module, _ = self.fixture()
  offsets, tasks = validate(context, module)
  self.assertEqual(offsets['comm'], 40)
  self.assertEqual([(t['pid'], t['comm']) for t in tasks], [(1, 'init'), (2, 'kthreadd')])

 def test_bad_backlinks_cycles_tail_pid_and_idle_anchor(self):
  for offset, fmt, value in [(280, '<Q', 123), (464, '<Q', 272), (88, '<Q', 272),
                             (480, '<i', 1), (104, '<B', ord('X'))]:
   with self.subTest(offset=offset):
    validate, context, module, memory = self.fixture()
    struct.pack_into(fmt, memory, offset, value)
    with self.assertRaises(ValueError):
     validate(context, module)
