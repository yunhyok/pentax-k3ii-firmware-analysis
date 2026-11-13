"""Trust-boundary checks; original firmware replay is the separate CLI check."""
import builtins
import os
from pathlib import Path
import sys
import subprocess
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
REPOSITORY=Path(os.environ.get('TONE_REPOSITORY',ROOT))
ns={'__name__':'tested_tone_cli','__file__':str(ROOT/'verify_tone_provenance.py')}
exec(compile((ROOT/'verify_tone_provenance.py').read_bytes(),ns['__file__'],'exec'),ns)

class Boundaries(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('TONE_TEST_TMP'))
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def test_typed_json_and_optimized_require(self):
        for a,b in ((0,False),(1,True),(1,1.0)):
            self.assertNotEqual(ns['canonical']({'x':a}),ns['canonical']({'x':b}))
        with self.assertRaises(ValueError):ns['require'](1,2,'active under -O')

    def test_captured_import_ignores_cache_and_disk(self):
        captured=ns['capture_sources'](REPOSITORY,ROOT)
        poison=ModuleType('verify_findings');poison.require=lambda *a:None
        importer=builtins.__import__
        with patch.dict(sys.modules,{'verify_findings':poison}),patch.object(Path,'read_bytes',side_effect=AssertionError('unexpected reread')):
            loaded=ns['load_captured'](captured)('verify_tone_path')
            with self.assertRaises(ValueError):loaded.require(1,2,'not cached poison')
        self.assertIs(builtins.__import__,importer)

    def test_captured_source_hash_is_rechecked(self):
        captured=ns['capture_sources'](REPOSITORY,ROOT)
        raw,path,pin=captured['verify_findings']
        captured['verify_findings']=(raw+b'\nraise RuntimeError("unverified code")\n',path,pin)
        with self.assertRaisesRegex(ValueError,'captured bytes before exec'):
            ns['load_captured'](captured)('verify_findings')

    def test_existing_hardlink_and_symlink_preserved(self):
        source=self.root/'source';source.write_bytes(b'original')
        alias=self.root/'alias';os.link(source,alias)
        for path in (source,alias,self.root/'x'/'..'/'source'):
            if path.parent.name=='..':(self.root/'x').mkdir(exist_ok=True)
            with self.assertRaises((ValueError,FileExistsError)):ns['write_new'](path,b'replacement')
        link=self.root/'link'
        try:link.symlink_to(source)
        except OSError:pass
        else:
            with self.assertRaises((ValueError,FileExistsError)):ns['write_new'](link,b'replacement')
        self.assertEqual(source.read_bytes(),b'original')

    def test_dangling_link_is_not_followed(self):
        link=self.root/'dangling'
        try:link.symlink_to(self.root/'absent')
        except OSError:self.skipTest('symlink creation is unavailable')
        with self.assertRaises(ValueError):ns['write_new'](link,b'replacement')
        self.assertFalse((self.root/'absent').exists())

    def test_publish_race_preserves_other_writer(self):
        target=self.root/'result.json';original_link=os.link
        def race(src,dst):
            Path(dst).write_bytes(b'other writer')
            return original_link(src,dst)
        with patch.object(os,'link',side_effect=race):
            with self.assertRaises(FileExistsError):ns['write_new'](target,b'candidate')
        self.assertEqual(target.read_bytes(),b'other writer')
        self.assertEqual(list(self.root.glob('.tone-*')),[])

    def test_failed_flush_leaves_no_output(self):
        target=self.root/'result.json'
        with patch.object(os,'fsync',side_effect=OSError('simulated storage failure')):
            with self.assertRaises(OSError):ns['write_new'](target,b'candidate')
        self.assertFalse(target.exists())
        self.assertEqual(list(self.root.glob('.tone-*')),[])

    def test_new_output_exact_bytes(self):
        target=self.root/'result.json';ns['write_new'](target,b'{"ok":true}\n')
        self.assertEqual(target.read_bytes(),b'{"ok":true}\n')

    def test_actual_cli_rejects_bad_image_before_emulator_import(self):
        for index,payload in enumerate((b'wrong size',bytes(ns['IMAGE_SIZE']))):
            source=self.root/f'bad-{index}.bin';source.write_bytes(payload)
            output=self.root/f'bad-{index}.json'
            result=subprocess.run([sys.executable,'-B','-I','-S',str(ROOT/'verify_tone_provenance.py'),str(source),'--repository',str(REPOSITORY),'--output',str(output)],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,1)
            self.assertIn('decoded',result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual(source.read_bytes(),payload)

if __name__=='__main__':unittest.main()
