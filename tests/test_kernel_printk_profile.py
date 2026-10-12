import copy
from pathlib import Path
import tempfile
import unittest

from tools.kernel_printk_profile import PRINTK_SYMBOLS, buildProfile, selectPrintkSymbols


class PrintkProfileTests(unittest.TestCase):
 def test_same_name_other_compilation_unit_does_not_override_typed_data(self):
  symbols = [{'name': n, 'type': t, 'address': 0x1000 + i * 8}
             for i, (n, t) in enumerate(PRINTK_SYMBOLS.items())]
  duplicate = {'name': 'log_buf', 'type': 'b', 'address': 0xdeadbeef}
  selected = selectPrintkSymbols(symbols + [duplicate])
  self.assertEqual(selected, symbols)
  self.assertNotIn(duplicate, selected)
  with self.assertRaisesRegex(ValueError, 'Expected one log_buf'):
   selectPrintkSymbols(symbols + [copy.copy(symbols[0])])
  with self.assertRaises(ValueError):
   selectPrintkSymbols(symbols[1:])

 def test_wrong_source_is_rejected_before_compilation_or_publication(self):
  with tempfile.TemporaryDirectory() as tmp:
   source = Path(tmp) / 'source'
   source.write_bytes(b'not the official source archive')
   output = Path(tmp) / 'out'
   with self.assertRaisesRegex(ValueError, 'official A7C2'):
    buildProfile(source, source, output, 'missing-compiler', 'missing-dwarf2json')
   self.assertFalse(output.exists())

 def test_existing_output_is_preserved_before_inputs_are_read(self):
  with tempfile.TemporaryDirectory() as tmp:
   with self.assertRaisesRegex(ValueError, 'already exists'):
    buildProfile('missing', 'missing', tmp, 'missing', 'missing')
