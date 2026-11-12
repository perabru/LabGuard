"""Exercise actual admin HTML and API with disposable data. No installation."""
from pathlib import Path
import os,sys,tempfile,socket,threading
R=Path(__file__).resolve().parents[1]
for d in (R/'central',R/'client',R/'managed'):sys.path.insert(0,str(d))
import websites
websites.install()
import labguard_central as core
from playwright.sync_api import sync_playwright,expect

def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
with tempfile.TemporaryDirectory() as t:
 p,a=port(),port();password='Sites UI test 123456789'
 core.initialize(Path(t),password,'127.0.0.1','127.0.0.0/8',a,p)
 panel,agent=core.build_servers(Path(t),assets_dir=R/'managed/build/assets')
 for server in (panel,agent):threading.Thread(target=server.serve_forever,daemon=True).start()
 try:
  with sync_playwright() as pw:
   if os.name=='nt':
    from smoke_browser import _edge_executable
    executable=str(_edge_executable())
   else:executable='/usr/bin/chromium'
   browser=pw.chromium.launch(executable_path=executable,headless=True,args=['--no-sandbox'])
   page=browser.new_page(viewport={'width':1440,'height':1000});errors=[];page.on('pageerror',lambda e:errors.append(str(e)));page.on('dialog',lambda d:d.accept())
   page.goto(f'http://127.0.0.1:{p}/');page.locator('#password').fill(password);page.locator('#login-form button[type=submit]').click();expect(page.locator('#app-shell')).to_be_visible()
   page.locator('button.nav-link[data-view=websites]').click();expect(page.locator('#web-heading')).to_be_visible();expect(page.locator('#web-sites-body tr')).to_have_count(6)
   row=page.locator('tr[data-web-id=termo]');expect(row).to_contain_text('term.ooo');row.get_by_role('button',name='Liberar',exact=True).click();expect(row).to_contain_text('Sem bloqueio nesta lista')
   page.locator('#web-block-all').click();expect(row).to_contain_text('Bloqueio solicitado');expect(page.locator('#web-result')).to_contain_text('Joguester')
   j=page.locator('tr[data-web-id=joguester]');expect(j.get_by_role('button',name='Bloquear',exact=True)).to_be_disabled();j.get_by_role('button',name='Editar endereço').click()
   page.locator('#web-edit-domains').fill('game.example');page.locator('#web-edit-save').click();expect(page.locator('#web-edit-dialog')).not_to_be_visible();expect(j).to_contain_text('game.example')
   j.get_by_role('button',name='Editar endereço').click();page.locator('#web-edit-domains').fill('');page.locator('#web-edit-blocked').uncheck();page.locator('#web-edit-save').click();expect(j).to_contain_text('Endereço pendente')
   (R/'managed/dist').mkdir(exist_ok=True);page.screenshot(path=str(R/'managed/dist/Painel-Sites-Rapidos.png'),full_page=True)
   page.set_viewport_size({'width':390,'height':844});page.screenshot(path=str(R/'managed/dist/Painel-Sites-Mobile.png'),full_page=True)
   assert not errors,errors;browser.close()
   print('PASS: real admin browser login, quick-sites view, individual release, Block All, pending unknown domain, edit/save, desktop/mobile screenshots.')
 finally:
  for server in (panel,agent):server.shutdown();server.server_close()
