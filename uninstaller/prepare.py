"""Assemble the shipping source and fixed restoration resources; never import installed code."""
import ast
from pathlib import Path
import shutil

HERE=Path(__file__).resolve().parent
REPO=HERE.parent
OUT=HERE/'build-source'
OUT.mkdir(exist_ok=True)
RES=OUT/'resources';RES.mkdir(exist_ok=True)
shutil.copy2(REPO/'client/labguard_cliente.py',OUT/'_vendor_labguard_cliente.py')
shutil.copy2(HERE/'operations.ps1',RES/'operations.ps1')
shutil.copy2(REPO/'network-tools/LabGuard-DNS-Sem-Cliente.ps1',RES/'restore-network.ps1')
parsed=ast.parse((REPO/'labguard/station_dns.py').read_text(encoding='utf-8-sig'))
windows=None
for node in parsed.body:
    if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_WINDOWS' for t in node.targets):
        windows=ast.literal_eval(node.value)
if not isinstance(windows,str) or '__PARAMS__' not in windows:raise RuntimeError('Station restoration resource not found')
(RES/'restore-station.ps1').write_text(windows,encoding='utf-8-sig')
source=(HERE/'main.py').read_text(encoding='utf-8')
def swap(before,after):
    global source
    if source.count(before)!=1:raise RuntimeError('Assembly point changed: '+before[:80])
    source=source.replace(before,after)
# A binary marker alone must never authorize deleting Documents or a drive root.
swap("            if not path.is_dir() or len(path.parts) < 3:\n                return", "            if path.name.casefold() not in {x.casefold() for x in APP_DIRS} | {'.labguard'}:\n                self.log('Instalacao em pasta compartilhada/nao padrao preservada: ' + str(path), True)\n                return\n            if not path.is_dir() or len(path.parts) < 3:\n                return")
# ProgramData permits creation of unrelated children; require the actual journal folder/file
# to be administrator-owned and non-user-writable, not the unrelated ProgramData ancestor.
swap("                old._lc_secure_chain(path)\n                old._lc_guard_file(owned)","                no_links(path)\n                old._lc_acl(path)\n                old._lc_guard_file(owned)")
swap("            if name not in ('labguardjogos2','labguardjogos','labguardcliente'):\n                continue", "            if name not in ('labguardjogos2','labguardjogos','labguardcliente'):\n                continue\n            if name=='labguardjogos2' and not (path/'config.json').exists():\n                continue")
swap("                old._lc_secure_chain(path)\n                if name=='labguardjogos2'", "                no_links(path)\n                old._lc_acl(path)\n                if name=='labguardjogos2'")
# Do not change attributes on another hard-link to an unrelated file.
swap("        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)\n        path.unlink()", "        if path.stat().st_nlink == 1:\n            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)\n        path.unlink()")
# Include recognized custom destinations, but retain the same strict folder-name guard.
swap("        # Registered custom install directories are accepted only with a LabGuard executable marker.", "        for installed in self.snapshot.get('installed', []):\n            if isinstance(installed.get('path'), str):\n                self.add_root(Path(installed['path']), 'programa', ('LabGuard.exe','LabGuard-Jogos.exe','LabGuardCliente.exe','LabGuardServer.exe','LabGuardTecnico.exe'))\n        # Registered custom install directories are accepted only with a LabGuard executable marker.")
# Preserve registrations when restoration data has to remain.
swap("operations('Registry',{'roots':self.roots,'profiles':self.profiles},180)","operations('Registry',{'roots':self.roots,'profiles':self.profiles,'held':list(self.held)},180)")
ast.parse(source)
(OUT/'main.py').write_text(source,encoding='utf-8')
tests=(HERE/'tests.py').read_text(encoding='utf-8')
tests=tests.replace("import main as app", "import importlib.util\nspec=importlib.util.spec_from_file_location('uninstaller_shipping',HERE/'build-source/main.py')\napp=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)")
(HERE/'tests-assembled.py').write_text(tests,encoding='utf-8')
print('Prepared uninstaller source and restoration resources.')
