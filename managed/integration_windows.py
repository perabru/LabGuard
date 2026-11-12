"""Real .NET client -> HTTPS Central test with disposable enrollment and events only."""
from pathlib import Path
import sys, tempfile, json, socket, threading, subprocess
ROOT=Path(__file__).resolve().parents[1]
for d in (ROOT/'managed',ROOT/'central',ROOT/'client'):sys.path.insert(0,str(d))
import alerts
alerts.install()
import websites
websites.install()
import labguard_central as core

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
with tempfile.TemporaryDirectory(prefix='labguard-tls-') as tmp:
    folder=Path(tmp)
    core.initialize(folder,'Integration test 123456789','127.0.0.1','127.0.0.0/8',port(),port())
    panel,agents=core.build_servers(folder,assets_dir=ROOT/'managed/build/assets')
    for server in (panel,agents):threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        config=panel.application.enrollment()['config'];link=folder/'vinculo.json';link.write_text(json.dumps(config))
        result=folder/'reply.json'
        p=subprocess.run([str(ROOT/'managed/dist/LabGuard-Jogos.exe'),'--central-integration',str(link),str(result)],timeout=50)
        if p.returncode:raise RuntimeError('C# HTTPS integration failed: '+str(p.returncode))
        reply=json.loads(result.read_text());assert reply['ok'] and reply['policy']['block_youtube']
        assert 'term.ooo' in reply['web_policy']['blocked_domains'] and reply['web_protocol']==1
        state=panel.application.store.state()
        assert len([r for r in state['alerts'] if r['kind']=='game_closed'])==1
        assert any(r['name']=='LAB-TESTE' for r in state['devices'])
        device=state['devices'][0]['device_id'];panel.application.store.revoke_device(device)
        print('PASS: real C# HTTPS enrollment, certificate pin mismatch rejected, telemetry received, duplicate events suppressed. No protection installed.')
    finally:
        for server in (panel,agents):server.shutdown();server.server_close()
