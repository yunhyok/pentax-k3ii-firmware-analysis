"""Asset-free whole-witness and output guards. GPL-2.0-only."""
from pathlib import Path
import copy,hashlib,json,os,runpy,shutil,stat,subprocess,sys,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
CLI=ROOT/'verify_tone_selectors.py';API=runpy.run_path(str(CLI))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

class SelectorGuards(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=os.environ.get('TONE_TEST_TMP'));self.addCleanup(temp.cleanup);self.work=Path(temp.name)
    def record(self):return json.loads((ROOT/'analysis/tone-selectors.json').read_bytes())['observations']
    def invoke(self,image,output,script=CLI,optimized=False):
        return subprocess.run([sys.executable,'-B','-I','-S',*(['-O'] if optimized else []),str(script),str(image),'--output',str(output)],capture_output=True,text=True,timeout=20)
    def test_whole_record_and_current_identity(self):
        public=json.loads((ROOT/'analysis/tone-selectors.json').read_bytes());API['project_checked'](public['observations'])
        self.assertEqual(public['current_execution']['CLI_sha256'],sha(CLI))
        self.assertNotEqual(public['current_execution']['CLI_sha256'],public['historical35']['script_sha256'])
        self.assertEqual(len(public['observations']['native_cases']),5)
    def test_all_top_fields_and_observation_mutations_rejected(self):
        record=self.record()
        for k in record:
            wrong=copy.deepcopy(record);wrong.pop(k)
            with self.subTest(missing=k),self.assertRaises(ValueError):API['project_checked'](wrong)
        edits=[(['input_sha256'],'0'*64),(['script_sha256'],'0'*64),(['versions','unicorn'],'other'),(['static','source_ranges',0,'sha256'],'0'*64),(['static','direct_branches',0,'target'],'0x0'),(['native_cases',0,'fixture','source5_argument'],False),(['native_cases',0,'setter_entries',0,'value'],1),(['native_cases',0,'reads',0,'address'],'0x0'),(['native_cases',0,'writes',0,'value'],1),(['native_cases',0,'trace',0,'pc'],'0x0'),(['native_cases',0,'all_other_scratch_bytes_unchanged'],1)]
        for path,value in edits:
            wrong=copy.deepcopy(record);at=wrong
            for key in path[:-1]:at=at[key]
            at[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError):API['project_checked'](wrong)
        with self.assertRaises(ValueError):API['project_checked'](dict(reversed(list(record.items()))))
    def test_types_and_extra_fields(self):
        for value in [None,1.0,{'x':(1,)},{1:'x'}]:
            with self.subTest(value=value),self.assertRaises(ValueError):API['typed_digest'](value)
        self.assertNotEqual(API['typed_digest']({'x':False}),API['typed_digest']({'x':0}))
        record=self.record();record['extra']=0
        with self.assertRaises(ValueError):API['project_checked'](record)
    def test_wrong_input_and_optimized_guards_before_imports(self):
        bad=self.work/'bad';bad.write_bytes(b'x');out=self.work/'out'
        for opt in (False,True):
            result=self.invoke(bad,out,optimized=opt)
            self.assertEqual(result.returncode,1);self.assertIn('decoded size/type',result.stderr);self.assertNotIn('No module named',result.stderr);self.assertFalse(out.exists())
        bad.write_bytes(b'\x00'*16838656)
        result=self.invoke(bad,out);self.assertEqual(result.returncode,1);self.assertIn('decoded SHA256',result.stderr)
    def test_existing_and_hardlink_output_preserved_before_input(self):
        original=self.work/'original';original.write_bytes(b'preserve');link=self.work/'hard';link.hardlink_to(original)
        for target in (original,link,self.work,CLI):
            result=self.invoke(self.work/'missing-input',target)
            self.assertEqual(result.returncode,1);self.assertIn('existing output',result.stderr)
        self.assertEqual(original.read_bytes(),b'preserve')
    def test_dangling_output_preserved(self):
        target=self.work/'dangling'
        try:target.symlink_to(self.work/'missing')
        except OSError:self.skipTest('symlink unsupported')
        result=self.invoke(self.work/'missing-input',target);self.assertEqual(result.returncode,1);self.assertIn('existing output',result.stderr);self.assertTrue(target.is_symlink())
    def test_package_mutations_rejected_before_optional_imports(self):
        package=self.work/'portable package';(package/'tools/tone_provenance').mkdir(parents=True)
        for name in ('verify_tone_selectors.py',*API['PINS']):shutil.copyfile(ROOT/name,package/name)
        for name in API['PINS']:
            f=package/name;old=f.read_bytes();changed=bytearray(old);changed[0]^=1;f.write_bytes(changed)
            result=self.invoke(self.work/'missing',self.work/'new',package/'verify_tone_selectors.py')
            self.assertEqual(result.returncode,1);self.assertIn('package '+name+' SHA256',result.stderr);f.write_bytes(old)
    def test_regular_descriptor_and_bounded_capture(self):
        f=self.work/'small';f.write_bytes(b'abc')
        with patch.object(API['os'],'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR,st_size=3)):
            with self.assertRaisesRegex(ValueError,'descriptor'):API['capture'](f,3,sha(f),'small')
        with self.assertRaises(ValueError):API['capture'](self.work,0,'unused','directory')
        self.assertEqual(API['capture'](f,3,sha(f),'small'),b'abc')
    def test_no_source_output_option(self):
        r=subprocess.run([sys.executable,'-B','-I','-S',str(CLI),'--help'],capture_output=True,text=True)
        self.assertEqual(r.returncode,0);self.assertNotIn('--source-output',r.stdout)
    def test_prewrite_guard_and_exclusive_mode(self):
        record=self.record();captured,source=API['capture_package']();out=self.work/'race'
        scope_helper=('def reconstruct(data):\n    return '+repr(record)+'\n').encode()
        source=copy.deepcopy(source);source['source_ranges']=[]
        # Exercise the real final guard without additional firmware execution.
        original=API['project_checked']
        def create_output(value):
            out.write_bytes(b'other writer');return original(value)
        run_globals=API['run'].__globals__
        fake=SimpleNamespace(__version__='test-only')
        with patch.dict(run_globals,{'capture_package':lambda:(dict(captured,**{'tools/tone_provenance/selectors.py.inc':scope_helper}),source),'capture':lambda *a:b'', 'project_checked':create_output}),patch.dict(sys.modules,{'capstone':fake,'unicorn':fake}),patch.object(API['importlib'].metadata,'version',return_value='test-only'):
            with self.assertRaisesRegex(ValueError,'existing output'):API['run'](self.work/'unused',out)
        self.assertEqual(out.read_bytes(),b'other writer')
    def test_no_optional_runtime_imports(self):
        self.assertNotIn('capstone',sys.modules);self.assertNotIn('unicorn',sys.modules)

if __name__=='__main__':unittest.main()
