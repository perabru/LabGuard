"""Real upgrade and DNS/Central coexistence, restricted to a disposable CI runner."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,tempfile,time,socket
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def run(args,timeout=90):
    p=subprocess.run([str(x) for x in args],timeout=timeout)
    if p.returncode:raise RuntimeError('Failed: '+str(args[0])+'; '+str(p.returncode))

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def digest_tree(folder):
    return {str(p.relative_to(folder)):hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.rglob('*') if p.is_file()}

def main():
    if os.name!='nt' or os.environ.get('GITHUB_ACTIONS')!='true':raise RuntimeError('Disposable Windows CI only.')
    import uuid
    out=ROOT/'ti/dist';out.mkdir(parents=True,exist_ok=True)
    home=Path.home();data=home/'.labguard'
    if data.exists() and any(data.iterdir()):raise RuntimeError('The runner already has LabGuard user data; refusing to replace it.')
    from labguard.preferences import PreferenceStore,default_preferences
    prefs=PreferenceStore();settings=default_preferences();settings['local_dns']={'host':'192.168.15.10','lab_cidr':'192.168.15.0/24','upstream':'1.1.1.1','start_on_open':True};prefs.save(settings)
    from labguard.banlist import BanlistDatabase
    db=BanlistDatabase(data/'banlists/policy2.sqlite3');db.upsert('keep.school.example','Outros');db.close()
    (data/'user-preserved.txt').write_text('school-owned fixture - preserve on upgrade',encoding='utf-8')
    original=digest_tree(data)
    install=Path(os.environ['LOCALAPPDATA'])/'Programs/LabGuard'
    if (install/'LabGuard.exe').exists():raise RuntimeError('Previous installed executable unexpectedly exists.')
    old=ROOT/'ti/previous/LabGuard-Setup.exe';new=out/'LabGuard-TI-Setup.exe'
    args=['/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/DIR='+str(install)]
    run([old,*args]);run([new,*args])
    assert original==digest_tree(data),'Preferences/rules changed during installer upgrade'
    exe=install/'LabGuard.exe'
    run([exe,'--self-test','--output',out/'core-self-test.json'])
    report=json.loads((out/'core-self-test.json').read_text(encoding='utf-8'))
    assert report['ok'] and report['version']=='2.4.5'
    run([exe,'--dns-self-test','--output',out/'dns-self-test.json'])
    dnsreport=json.loads((out/'dns-self-test.json').read_text())
    assert dnsreport['ok'] and dnsreport['udp_blocked'] and dnsreport['tcp_blocked']
    run([exe,'--ti-smoke','--output-dir',out/'ui'])
    assert original==digest_tree(data),'GUI smoke touched real test-user settings'
    for d in (ROOT/'central',ROOT/'client'):sys.path.insert(0,str(d))
    import labguard_tecnico as launcher
    import labguard_central as central
    from ti.bridge import health
    from labguard.local_dns import DNSFilter
    from dnslib import DNSRecord,RCODE
    centraldir=Path(os.environ['ProgramFiles'])/('LabGuard-TI-CI-'+uuid.uuid4().hex)
    launcher.private_directory(centraldir)
    panelport,agentport=free_port(),free_port()
    central.initialize(centraldir,'Temporary CI password 123456','127.0.0.1','127.0.0.0/8',agentport,panelport)
    centralexe=ROOT/'ti/payload/LabGuardTecnico.exe'
    service=subprocess.Popen([str(centralexe),'run','--directory',str(centraldir)])
    dns=DNSFilter('127.0.0.1','127.0.0.0/8',port=free_port(),rules={'poki.com':'Jogos','keep.school.example':'Outros'})
    def blocked(tcp=False):
        response=DNSRecord.parse(DNSRecord.question('poki.com').send('127.0.0.1',dns.port,tcp=tcp,timeout=3))
        return response.header.rcode==RCODE.NXDOMAIN
    try:
        deadline=time.monotonic()+45
        while time.monotonic()<deadline and not health(panelport)['ready']:
            if service.poll() is not None:raise RuntimeError('Central process exited: '+str(service.returncode))
            time.sleep(.3)
        assert health(panelport)['ready'],'Actual Central did not respond'
        dns.start();assert blocked() and blocked(True),'DNS did not filter while Central was running'
        service.terminate();service.wait(timeout=15)
        assert blocked() and blocked(True),'Stopping Central interrupted original DNS'
        assert original==digest_tree(data),'Coexistence test changed saved preferences'
    finally:
        dns.close()
        if service.poll() is None:service.terminate();service.wait(timeout=15)
    checks={'ok':True,'upgrade_from':'2.4.4','upgrade_to':'2.4.5','same_app_id':True,
            'preferences_and_rule_files_byte_identical':len(original),'original_modes':report['controller_modes'],
            'original_dns_udp_tcp':True,'original_reports':report['reports'],
            'central_running_together_with_dns':True,'dns_survived_central_stop':True,
            'tests_used':'disposable runner; fictitious rules; DNS only on loopback',
            'real_school_machines_tested':False}
    (out/'PRESERVACAO_E_TESTES.json').write_text(json.dumps(checks,ensure_ascii=False,indent=2),encoding='utf-8')
    print('PASS: real in-place installer upgrade, unchanged user rules/settings, original UDP/TCP DNS, packaged original resources and concurrent actual Central.')

if __name__=='__main__':main()
