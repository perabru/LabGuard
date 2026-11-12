"""Graphics smoke on a fictitious profile; never touches the operator's real rules."""
from pathlib import Path
import json,os,tempfile,time
from unittest.mock import patch

def gui_smoke(folder):
    from ti.app import App
    from labguard.demo import DemoTransport
    from PIL import ImageGrab
    folder.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='labguard-ti-gui-') as tmp,patch('pathlib.Path.home',return_value=Path(tmp)):
        app=App(transport=DemoTransport(),updates_enabled=False)
        try:
            deadline=time.monotonic()+1.2
            while time.monotonic()<deadline:app.update();time.sleep(.03)
            assert set(app._nav)=={'home','devices','sites','activity','central'}
            assert all(callable(getattr(app,n)) for n in ('_open_network_map','_open_banlist','_open_remote','_open_integrations','_open_desktop_web','_open_dns_setup','_toggle_ai','_check_for_updates','_restore_saved_dns'))
            for size in ((1240,820),(1000,700)):
                app.geometry('%dx%d+0+0'%size)
                for page in ('home','sites','central'):
                    app.show_page(page);app.update();app.update_idletasks()
                    p=folder/('ti-%s-%d.png'%(page,size[0]))
                    x,y=app.winfo_rootx(),app.winfo_rooty()
                    ImageGrab.grab(bbox=(x,y,x+app.winfo_width(),y+app.winfo_height())).save(p)
            (folder/'ti-ui-check.json').write_text(json.dumps({'ok':True,'original_views':4,'added_views':1,'original_handlers':'inherited','profile':'fictitious'},indent=2))
        finally:app.close()
