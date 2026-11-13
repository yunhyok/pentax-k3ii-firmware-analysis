"""Firmware-free canonical-record and I/O guards; no Capstone is required."""
from pathlib import Path
from hashlib import sha256
import copy,json,os,runpy,shutil,stat,subprocess,sys,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(os.environ.get('TONE_MANAGER_CANDIDATE',Path(__file__).resolve().parents[1]))
CLI=ROOT/'verify_tone_manager.py';API=runpy.run_path(str(CLI))
class ToneManagerGuards(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(dir=os.environ.get('TONE_TEST_TMP'));self.addCleanup(tmp.cleanup);self.work=Path(tmp.name)
    def invoke(self,image,output,*extra):
        return subprocess.run([sys.executable,'-B','-I','-S',str(CLI),str(image),'--output',str(output),*map(str,extra)],capture_output=True,text=True,timeout=20)
    def record(self):return json.loads((ROOT/'analysis/tone-manager.json').read_bytes())
    def test_complete_canonical_record_and_distinct_source_identity(self):
        public=self.record();record=public['observations'];API['project_checked'](record)
        self.assertEqual(len(record['source_ranges']),19);self.assertEqual(record['decoded_instruction_count'],312)
        self.assertEqual(len(record['branches']),18);self.assertEqual(len(record['literals']),12);self.assertEqual(len(record['callers']),2)
        self.assertEqual(record['reproduction_source_sha256'],public['original_research_source_sha256'])
        self.assertEqual(public['public_checker_sha256'],sha256(CLI.read_bytes().replace(b'\r\n',b'\n')).hexdigest())
        self.assertNotEqual(public['public_checker_sha256'],public['original_research_source_sha256'])
        self.assertFalse(public['capstone_rechecked'])
    def test_missing_tampered_typed_and_reordered_whole_record(self):
        record=self.record()['observations']
        for key in record:
            value=copy.deepcopy(record);del value[key]
            with self.subTest(missing=key),self.assertRaises(ValueError):API['project_checked'](value)
        values=[]
        for path,replacement in [(['callers',0,'writer_r2'],False),(['callers',0,'scratch'],0),(['branches',0,'link'],1),(['symbolic_state_examples',0,'not_executed'],1),(['reproduction_source_sha256'],'0'*64),(['source_listing_sha256'],'0'*64),(['capstone_version'],'other')]:
            v=copy.deepcopy(record);at=v
            for key in path[:-1]:at=at[key]
            at[path[-1]]=replacement;values.append(v)
        v=copy.deepcopy(record);del v['writer_order'][0]['action'];values.append(v)
        v=copy.deepcopy(record);v['unexpected']=0;values.append(v)
        for v in values:
            with self.assertRaises(ValueError):API['project_checked'](v)
        with self.assertRaisesRegex(ValueError,'serialized'):API['project_checked'](dict(reversed(list(record.items()))))
    def test_image_identity_precedes_optional_decoder_import(self):
        image=self.work/'bad.bin';out=self.work/'out.json'
        for size,error in [(3,'decoded size'),(API['IMAGE_SIZE'],'decoded SHA256')]:
            image.write_bytes(bytes(size));p=self.invoke(image,out,'--check-decoder')
            self.assertEqual(p.returncode,1);self.assertIn(error,p.stderr);self.assertNotIn('No module named',p.stderr);self.assertFalse(out.exists())
        p=self.invoke(self.work,out);self.assertEqual(p.returncode,1);self.assertIn('regular decoded',p.stderr)
    def test_regular_descriptor_rechecked(self):
        path=self.work/'file';path.write_bytes(b'abc')
        with patch.object(API['os'],'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR)):
            with self.assertRaisesRegex(ValueError,'descriptor'):API['read_regular'](path,8,'test')
            with self.assertRaisesRegex(ValueError,'descriptor'):API['read_image'](path)
    def test_existing_output_and_hardlink_are_preserved(self):
        original=self.work/'input';original.write_bytes(b'original');alias=self.work/'alias';alias.hardlink_to(original)
        for target in (original,alias,self.work):
            p=self.invoke(original,target);self.assertEqual(p.returncode,1);self.assertIn('existing output',p.stderr)
        self.assertEqual(original.read_bytes(),b'original');self.assertEqual(alias.read_bytes(),b'original')
    def test_dangling_output_link_is_preserved(self):
        referent=self.work/'absent';link=self.work/'link'
        try:link.symlink_to(referent)
        except OSError as e:self.skipTest(str(e))
        p=self.invoke(self.work/'unused',link);self.assertEqual(p.returncode,1);self.assertIn('existing output',p.stderr)
        self.assertTrue(link.is_symlink());self.assertFalse(referent.exists())
    def test_compare_regular_file_and_bounded_read(self):
        path=self.work/'compare';path.write_bytes(b'{}');self.assertEqual(API['read_regular'](path,2,'compare'),b'{}')
        path.write_bytes(b'{} ')
        with self.assertRaisesRegex(ValueError,'bounded size'):API['read_regular'](path,2,'compare')
        with self.assertRaisesRegex(ValueError,'regular'):API['read_regular'](self.work,10,'compare')
        if hasattr(os,'mkfifo'):
            fifo=self.work/'fifo';os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError,'regular'):API['read_regular'](fifo,10,'compare')
    def test_compare_type_drift_or_oversize_creates_no_output(self):
        baseline=self.work/'compare.json';out=self.work/'out.json';fixture={'observations':{'writer_r2':0}}
        args=['unused','--output',str(out),'--compare',str(baseline)]
        with patch.dict(API['main'].__globals__,{'read_image':lambda _:b'','run':lambda *_:fixture}):
            baseline.write_text(json.dumps({'observations':{'writer_r2':False}}))
            with self.assertRaisesRegex(ValueError,'typed'):API['main'](args)
            self.assertFalse(out.exists());baseline.write_bytes(b' '*10000)
            with self.assertRaisesRegex(ValueError,'bounded size'):API['main'](args)
            self.assertFalse(out.exists())
    def test_manifest_drift_fails_before_input_read(self):
        stage=self.work/'stage';(stage/'tools/tone_provenance').mkdir(parents=True)
        shutil.copyfile(CLI,stage/CLI.name)
        manifest=ROOT/'tools/tone_provenance/manager-ranges.json'
        (stage/'tools/tone_provenance/manager-ranges.json').write_bytes(manifest.read_bytes()+b' ')
        main=runpy.run_path(str(stage/CLI.name))['main']
        with patch.dict(main.__globals__,{'read_image':lambda _:self.fail('input read before manifest validation')}):
            with self.assertRaisesRegex(ValueError,'manifest identity'):main(['unused','--output',str(self.work/'new')])
    def test_whole_record_gate_precedes_optional_decoder(self):
        data=b'fixture';decoder=lambda *_:self.fail('decoder used before complete record gate')
        with patch.dict(API['run'].__globals__,{'IMAGE_SIZE':len(data),'IMAGE_SHA256':sha256(data).hexdigest(),'analyze':lambda *_:{},'check_decoder':decoder}):
            with self.assertRaisesRegex(ValueError,'complete II33'):API['run'](data,{'spans':[]},'source',True)
    def test_exclusive_writer_race_and_fsync_failure(self):
        target=self.work/'race';real_link=os.link
        def competitor(source,destination):
            Path(destination).write_bytes(b'competitor');return real_link(source,destination)
        with patch.object(API['os'],'link',side_effect=competitor):
            with self.assertRaises(FileExistsError):API['write_new'](target,b'ours')
        self.assertEqual(target.read_bytes(),b'competitor');self.assertFalse(list(self.work.glob('.tone-manager-*')))
        clean=self.work/'clean'
        with patch.object(API['os'],'fsync',side_effect=OSError('fixture fsync failure')):
            with self.assertRaises(OSError):API['write_new'](clean,b'ours')
        self.assertFalse(clean.exists());self.assertFalse(list(self.work.glob('.tone-manager-*')))
    def test_normal_exclusive_output(self):
        target=self.work/'new';API['write_new'](target,b'complete\n');self.assertEqual(target.read_bytes(),b'complete\n')

if __name__=='__main__':unittest.main(verbosity=2)
