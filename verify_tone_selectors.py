"""Reproduce five pinned K-3 II leaf cases, then publish the gated observations.

Firmware is supplied separately. No disassembly output option. -O is supported.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import argparse,hashlib,importlib.metadata,json,os,stat,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PINS={'tools/tone_provenance/selectors.py.inc':(9777,'ac537ab8894478180b7fca4317422f5d38c79b47de9b2f98a5d8854bc96dbf22'),
      'tools/tone_provenance/selectors-source.json':(4282,'ded01d577bd9b2e6979a23c36cd8cb5d548678939345a46014a15331fcf3b6d6')}
CANONICAL='d0f24af070098f6ce8084f382894ca78f987cd2b00adeca5099aa3a3ff57989d'
HISTORICAL_FILE='1e6ed678c9ce1a3a2e9a2dcb5935893bab09a9ac650d4020c7d01a29b4a647c5'
sha=lambda b:hashlib.sha256(b).hexdigest()

def require(ok,label):
    if not ok:raise ValueError(label)

def typed_digest(value):
    def walk(v):
        if type(v) is dict:
            require(all(type(k) is str for k in v),'record key type')
            for item in v.values():walk(item)
        elif type(v) is list:
            for item in v:walk(item)
        else:require(type(v) in (str,int,bool),'record value type')
    walk(value)
    return sha(json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(',',':')).encode())

def gate_record(record):
    require(type(record) is dict and typed_digest(record)==CANONICAL,'complete II35 typed observation mismatch')
    # Original II35 was serialized on Windows; retain that historical identity.
    historical=(json.dumps(record,indent=2)+'\n').replace('\n','\r\n').encode()
    require(sha(historical)==HISTORICAL_FILE,'complete II35 serialized observation mismatch')

def project_checked(record):
    gate_record(record)
    # The witness contains addresses/values, not instruction bytes or disassembly.
    return {'observations':record,'physical_selector_meaning_known':False,'actual_menu_or_capture_reached':False,
            'whole_entry_or_service_execution':False,'firmware_bytes_or_disassembly_exported':False}

def capture(path,size,digest,label):
    require(path.is_file() and path.stat().st_size==size,label+' size/type mismatch')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NONBLOCK',0)
    with os.fdopen(os.open(path,flags),'rb') as f:
        s=os.fstat(f.fileno());require(stat.S_ISREG(s.st_mode) and s.st_size==size,label+' descriptor mismatch')
        data=f.read(size+1);require(os.fstat(f.fileno()).st_size==size,label+' changed during capture')
    require(len(data)==size and sha(data)==digest,label+' SHA256 mismatch')
    return data

def capture_package():
    captured={name:capture(HERE/name,*pin,'package '+name) for name,pin in PINS.items()}
    source=json.loads(captured['tools/tone_provenance/selectors-source.json'])
    require(source['original35']['typed_canonical_sha256']==CANONICAL and source['original35']['result_file_sha256']==HISTORICAL_FILE,'source contract mismatch')
    return captured,source

def guard_output(output):
    require(not os.path.lexists(output),'existing output or alias rejected')
    require(output.parent.is_dir(),'output parent must exist')

def run(decoded,output):
    guard_output(output)
    captured,source=capture_package()
    own=Path(__file__).read_bytes();require(len(own)<=131072,'CLI source cap')
    data=capture(decoded,source['input']['bytes'],source['input']['sha256'],'decoded')
    for r in source['source_ranges']:
        lo=int(r['start'],16);hi=int(r['end_exclusive'],16)
        require(0<=lo<hi<=len(data) and hi-lo==r['bytes'] and sha(data[lo:hi])==r['sha256'],'original sparse range mismatch')
    scope={'__name__':'captured_selectors36','__file__':'captured selectors helper'}
    exec(compile(captured['tools/tone_provenance/selectors.py.inc'],scope['__file__'],'exec'),scope)
    record=scope['reconstruct'](data)
    projection=project_checked(record)
    import capstone,unicorn
    result={'schema':'k3ii-tone-selectors-v1','historical35':source['original35'],
            'current_execution':{'python':sys.version.split()[0],'capstone_module':capstone.__version__,'unicorn_module':unicorn.__version__,
                'capstone_distribution':importlib.metadata.version('capstone'),'unicorn_distribution':importlib.metadata.version('unicorn'),
                'CLI_sha256':sha(own),'captured_helper_sha256':PINS['tools/tone_provenance/selectors.py.inc'][1]},
            'source_contract_sha256':PINS['tools/tone_provenance/selectors-source.json'][1],
            'complete_original35_typed_and_serialized_gate_passed':True,'decoded_file_captures':1,
            'original_leaf_replay_cases':5,'new_services_MMIO_CP15':False,'whole_boot_or_capture':False,**projection}
    payload=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode()
    guard_output(output)
    with output.open('xb') as f:f.write(payload)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded',type=Path);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();run(a.decoded,a.output)
    print(json.dumps({'whole_II35_verified':True,'original_leaf_cases':5,'services_MMIO_CP15':False}))
if __name__=='__main__':
    try:main()
    except (ValueError,OSError,ImportError) as error:
        print(str(error),file=sys.stderr);raise SystemExit(1)
