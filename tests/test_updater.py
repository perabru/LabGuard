"""Updater verification never uses the network or executes an installer here."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import stat
import struct
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from urllib.request import Request

from labguard import updater as u


def pe_package():
    content = bytearray(256)
    content[:2] = b'MZ'
    struct.pack_into('<I', content, 60, 64)
    content[64:68] = b'PE\0\0'
    return bytes(content)


def tar_package(name='LabGuard/LabGuard', kind=tarfile.REGTYPE):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.size = 3 if kind == tarfile.REGTYPE else 0
        if kind == tarfile.SYMTYPE:member.linkname = '../../outside'
        archive.addfile(member, io.BytesIO(b'app') if member.size else None)
    return output.getvalue()


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manager = u.UpdateManager('2.1.0', data_dir=self.root/'updates', frozen=True)
        self.status = {'state':'installed','supported':True,'auto_apply':True,'platform':'windows-x86_64','message':''}
        self.addCleanup(patch.stopall)
        patch.object(self.manager, 'installation_status', return_value=self.status).start()
        self.package = pe_package()
        self.documents = self.release_documents(self.package)
        self.urls = []
        patch.object(self.manager, '_download', side_effect=self.download).start()

    def release_documents(self, package, version='2.2.0', platform='windows-x86_64'):
        name = u.ASSETS[platform]
        manifest = {'schema':1,'app_id':u.APP_ID,'channel':'stable','version':version,'artifacts':{
            platform:{'name':name,'sha256':hashlib.sha256(package).hexdigest(),'size':len(package)}}}
        raw = json.dumps(manifest).encode()
        sums = (hashlib.sha256(raw).hexdigest()+'  labguard-update.json\n'+hashlib.sha256(package).hexdigest()+'  '+name+'\n').encode()
        files = {'labguard-update.json':raw,'SHA256SUMS.txt':sums,name:package}
        root = u.RELEASE_ROOT+'v'+version+'/'
        release = {'draft':False,'prerelease':False,'tag_name':'v'+version,'assets':[
            {'name':key,'size':len(value),'browser_download_url':root+key} for key,value in files.items()]}
        return {u.API_URL:json.dumps(release).encode(),**{root+key:value for key,value in files.items()}}

    def download(self, url, maximum, deadline, target=None):
        self.urls.append(url)
        content = self.documents[url]
        if len(content) > maximum:raise u.UpdateError('bounded')
        if target is not None:target.write(content)
        return content if target is None else None, len(content), hashlib.sha256(content).hexdigest()

    def rewrite_release(self, mutate):
        release = json.loads(self.documents[u.API_URL]);mutate(release)
        self.documents[u.API_URL] = json.dumps(release).encode()

    def rewrite_manifest(self, mutate):
        key = next(key for key in self.documents if key.endswith('/labguard-update.json'))
        value = json.loads(self.documents[key]);mutate(value)
        self.documents[key] = json.dumps(value).encode()
        sums_key = next(key for key in self.documents if key.endswith('/SHA256SUMS.txt'))
        lines = self.documents[sums_key].decode().splitlines()
        lines[0] = hashlib.sha256(self.documents[key]).hexdigest()+'  labguard-update.json'
        self.documents[sums_key] = ('\n'.join(lines)+'\n').encode()
        self.rewrite_release(lambda r:[item.update(size=len(self.documents[item['browser_download_url']])) for item in r['assets']])

    def test_semver_accepts_only_stable_bounded_numeric_components(self):
        self.assertGreater(u.version_tuple('2.10.0'),u.version_tuple('2.9.99'))
        self.assertEqual(u.version_tuple('65535.65535.65535'),(65535,65535,65535))
        for value in ('v2.2.0','02.2.0','2.2.0-beta','2.2.0+meta','2.2','2.2.0/../','65536.0.0',None,True):
            with self.subTest(value=value),self.assertRaises(u.UpdateError):u.version_tuple(value)

    def test_current_or_downgrade_does_not_fetch_or_stage_assets(self):
        for version in ('2.1.0','1.9.9'):
            self.urls.clear();self.documents=self.release_documents(self.package,version)
            self.assertEqual(self.manager.check_update()['state'],'current')
            self.assertEqual(self.urls,[u.API_URL])
        self.assertFalse(self.manager._candidates)

    def test_check_and_stage_are_separate_and_do_not_execute(self):
        with patch.object(u.subprocess,'Popen') as execute:
            candidate = self.manager.check_update()
            self.assertEqual(candidate['state'],'available')
            self.assertFalse((self.root/'updates').exists())
            prepared = self.manager.stage_update(candidate)
            self.assertEqual(prepared['state'],'prepared')
            package = self.root/'updates'/'2.2.0'/'installer.exe'
            self.assertEqual(package.read_bytes(),self.package)
            if os.name != 'nt':self.assertEqual(stat.S_IMODE(package.stat().st_mode),0o600)
            execute.assert_not_called()
            self.assertEqual(self.manager.application_result(prepared)['state'],'pending')

    def test_forged_candidate_or_prepared_cannot_select_payload(self):
        for candidate in ({},{'candidate_id':'fake'},{'url':'https://evil.test/installer.exe'}):
            with self.assertRaises(u.UpdateError):self.manager.stage_update(candidate)
        self.assertFalse(self.manager.schedule_apply({'prepared_id':'fake'},consent=True))
        with self.assertRaises(u.UpdateError):self.manager.application_result({'prepared_id':'fake'})

    def test_candidate_dto_changes_do_not_change_internal_artifact(self):
        candidate = self.manager.check_update()
        candidate.update(version='9.0.0',url='https://evil.test/payload',sha256='0'*64)
        prepared = self.manager.stage_update(candidate)
        self.assertEqual(prepared['version'],'2.2.0')
        self.assertEqual(self.urls[-1],u.RELEASE_ROOT+'v2.2.0/LabGuard-Setup.exe')

    def test_release_assets_wrong_repo_duplicate_or_tag_refused(self):
        mutations = [lambda r:r.update(tag_name='v2.2.0-beta'),lambda r:r.update(prerelease=True),
                     lambda r:r.update(draft=True),lambda r:r['assets'][0].update(browser_download_url='https://github.com/other/Repo/releases/download/v2.2.0/labguard-update.json'),
                     lambda r:r['assets'].append(copy.deepcopy(r['assets'][0])),lambda r:r['assets'][0].update(size=True)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.documents=self.release_documents(self.package);self.rewrite_release(mutation)
                with self.assertRaises(u.UpdateError):self.manager.check_update()

    def test_manifest_wrong_identity_channel_size_hash_or_artifact_refused(self):
        mutations = [lambda m:m.update(app_id='other.app'),lambda m:m.update(schema=True),lambda m:m.update(version='2.3.0'),
                     lambda m:m.update(channel='beta'),lambda m:m['artifacts']['windows-x86_64'].update(name='other.exe'),
                     lambda m:m['artifacts']['windows-x86_64'].update(size=u.MAX_ASSET+1),
                     lambda m:m['artifacts']['windows-x86_64'].update(size=True),lambda m:m['artifacts']['windows-x86_64'].update(sha256='0'*64)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.documents=self.release_documents(self.package);self.rewrite_manifest(mutation)
                with self.assertRaises(u.UpdateError):self.manager.check_update()

    def test_manifest_own_hash_required_in_sums(self):
        sums_key = next(key for key in self.documents if key.endswith('/SHA256SUMS.txt'))
        self.documents[sums_key]=self.documents[sums_key].replace(b'labguard-update.json',b'other-manifest.json')
        self.rewrite_release(lambda r:[item.update(size=len(self.documents[item['browser_download_url']])) for item in r['assets']])
        with self.assertRaises(u.UpdateError):self.manager.check_update()

    def test_stage_rejects_bad_hash_size_and_non_pe_without_preparing_or_executing(self):
        for content in (self.package+b'extra',b'bad',b'X'*len(self.package)):
            candidate=self.manager.check_update()
            url=u.RELEASE_ROOT+'v2.2.0/LabGuard-Setup.exe';self.documents[url]=content
            with patch.object(u.subprocess,'Popen') as execute,self.assertRaises(u.UpdateError):self.manager.stage_update(candidate)
            execute.assert_not_called()
            self.assertFalse(self.manager._prepared)
            self.assertFalse(list(self.root.rglob('*.tmp')))
            self.documents=self.release_documents(self.package)
        self.documents=self.release_documents(b'X'*256)
        with self.assertRaises(u.UpdateError):self.manager.stage_update(self.manager.check_update())

    def test_staged_symlink_hardlink_and_public_file_rejected(self):
        prepared=self.manager.stage_update(self.manager.check_update())
        value=next(iter(self.manager._prepared.values()))
        path=Path(value['path']);outside=self.root/'outside';outside.write_bytes(self.package);outside.chmod(0o600)
        path.unlink()
        try:path.symlink_to(outside)
        except OSError:self.skipTest('Symlink unavailable')
        with self.assertRaises(u.UpdateError):self.manager._validate_package(path,value)
        path.unlink()
        try:os.link(outside,path)
        except OSError:self.skipTest('Hardlink unavailable')
        with self.assertRaises(u.UpdateError):self.manager._validate_package(path,value)
        path.unlink();path.write_bytes(self.package);path.chmod(0o644)
        if os.name != 'nt':
            with self.assertRaises(u.UpdateError):self.manager._validate_package(path,value)
        self.assertEqual(self.manager.application_result(prepared)['state'],'pending')

    def test_parent_symlink_and_unsafe_data_directory_rejected(self):
        real=self.root/'real';real.mkdir(mode=0o700)
        link=self.root/'linked'
        try:link.symlink_to(real,target_is_directory=True)
        except OSError:self.skipTest('Symlink unavailable')
        with self.assertRaises(u.UpdateError):u._safe_path(link/'new')
        if os.name != 'nt':
            real.chmod(0o777)
            with self.assertRaises(u.UpdateError):u._secure_directory(real)

    def test_tar_requires_bounded_regular_tree_with_expected_executable(self):
        self.status.update(auto_apply=False,platform='linux-x86_64')
        self.documents=self.release_documents(tar_package(),platform='linux-x86_64')
        self.assertFalse(self.manager.stage_update(self.manager.check_update())['can_apply'])
        for content in (tar_package('../outside'),tar_package('LabGuard/../outside'),tar_package('/LabGuard/LabGuard'),
                        tar_package('LabGuard/link',tarfile.SYMTYPE),tar_package('Other/LabGuard'),b'PK\x03\x04zip'):
            with self.subTest(content=content[:20]):
                self.documents=self.release_documents(content,'2.3.0','linux-x86_64')
                with self.assertRaises(u.UpdateError):self.manager.stage_update(self.manager.check_update())

    def test_close_cancels_pending_work_without_executing(self):
        candidate=self.manager.check_update();self.manager.close()
        for call in (self.manager.check_update,lambda:self.manager.stage_update(candidate)):
            with self.assertRaises(u.UpdateError):call()
        self.assertFalse(self.manager.schedule_apply({},consent=True))

    def test_source_status_is_pure_and_has_no_network(self):
        manager=u.UpdateManager('2.2.0',data_dir=self.root/'absent',frozen=False)
        with patch.object(manager,'_download') as network:
            self.assertEqual(manager.installation_status()['state'],'source')
            self.assertFalse(manager.check_update()['supported'])
            self.assertFalse(manager.schedule_apply({},consent=True))
            network.assert_not_called()
        self.assertFalse((self.root/'absent').exists())

    def test_schedule_requires_consent_eligible_install_and_revalidated_payload(self):
        prepared=self.manager.stage_update(self.manager.check_update())
        with patch.object(u.subprocess,'Popen') as execute:
            self.assertFalse(self.manager.schedule_apply(prepared))
            self.status['auto_apply']=False
            self.assertFalse(self.manager.schedule_apply(prepared,consent=True))
            self.status['auto_apply']=True
            Path(next(iter(self.manager._prepared.values()))['path']).write_bytes(b'tampered')
            with self.assertRaises(u.UpdateError):self.manager.schedule_apply(prepared,consent=True)
            execute.assert_not_called()

    def test_schedule_uses_fixed_packaged_helper_and_argument_list_only(self):
        executable=self.root/'LabGuard.exe';executable.write_bytes(b'installed')
        powershell=self.root/'powershell.exe';powershell.write_bytes(b'system')
        self.manager.executable=executable
        prepared=self.manager.stage_update(self.manager.check_update())
        with patch.object(u,'_installed_windows',return_value=True),patch.object(u,'_process_executable',return_value=executable.resolve()),patch.object(u,'_system_powershell',return_value=powershell),patch.object(u.subprocess,'Popen') as execute:
            with self.assertRaises(u.UpdateError):self.manager.schedule_apply(prepared,parent_pid=os.getpid()+1,consent=True)
            execute.assert_not_called()
            self.assertTrue(self.manager.schedule_apply(prepared,consent=True))
            args,kwargs=execute.call_args
            self.assertIsInstance(args[0],list)
            self.assertNotIn('shell',kwargs)
            self.assertEqual(args[0][0],str(powershell))
            metadata=Path(args[0][-1]);value=json.loads(metadata.read_text())
            self.assertEqual(value['parent_pid'],os.getpid())
            self.assertTrue(value['consent'])
            helper=metadata.parent/'apply_windows.ps1'
            self.assertEqual(value['helper_sha256'],hashlib.sha256(helper.read_bytes()).hexdigest())
            helper_text=helper.read_text()
            for flag in ('/NOCLOSEAPPLICATIONS','/NORESTARTAPPLICATIONS','/NORESTART'):
                self.assertIn(flag,helper_text)
            self.assertIn('[IO.FileShare]::Read',helper_text)
            self.assertIn('$startInfo.UseShellExecute = $false',helper_text)
            for component in ('FileMajorPart','FileMinorPart','FileBuildPart','FilePrivatePart'):
                self.assertIn('$info.'+component,helper_text)
            self.assertNotIn('GetVersionInfo($Path).FileVersion',helper_text)

    def test_schedule_is_idempotent_and_close_cancels_before_spawn(self):
        executable=self.root/'LabGuard.exe';executable.write_bytes(b'installed')
        powershell=self.root/'powershell.exe';powershell.write_bytes(b'system')
        self.manager.executable=executable
        prepared=self.manager.stage_update(self.manager.check_update())
        entered,release=threading.Event(),threading.Event()
        results=[]
        def process_path(pid):
            entered.set()
            if not release.wait(2):raise AssertionError('test failed to release updater')
            # The native query returns a resolved path, including Windows 8.3 expansion.
            return executable.resolve()
        with patch.object(u,'_installed_windows',return_value=True),patch.object(u,'_process_executable',side_effect=process_path),patch.object(u,'_system_powershell',return_value=powershell),patch.object(u.subprocess,'Popen') as execute:
            worker=threading.Thread(target=lambda:results.append(self.manager.schedule_apply(prepared,consent=True)))
            worker.start();self.assertTrue(entered.wait(2))
            self.assertFalse(self.manager.schedule_apply(prepared,consent=True))
            self.manager.close();release.set();worker.join(2)
            self.assertFalse(worker.is_alive());self.assertEqual(results,[False]);execute.assert_not_called()
        # A completed schedule cannot spawn twice, even with the same valid token.
        self.manager._closed.clear()
        with patch.object(u,'_installed_windows',return_value=True),patch.object(u,'_process_executable',return_value=executable.resolve()),patch.object(u,'_system_powershell',return_value=powershell),patch.object(u.subprocess,'Popen') as execute:
            self.assertTrue(self.manager.schedule_apply(prepared,consent=True))
            self.assertFalse(self.manager.schedule_apply(prepared,consent=True))
            self.assertEqual(execute.call_count,1)

    def test_receipt_malformed_unmatched_or_linked_remains_pending(self):
        prepared=self.manager.stage_update(self.manager.check_update())
        path=Path(next(iter(self.manager._prepared.values()))['path']).parent/'result.json'
        for receipt in ({'app_id':'other','version':'2.2.0','state':'applied','code':'OK'}, {'app_id':u.APP_ID,'version':'2.2.0','state':'applied','code':'/private/path'}):
            path.write_text(json.dumps(receipt));self.assertEqual(self.manager.application_result(prepared)['state'],'pending')
        path.write_text(json.dumps({'app_id':u.APP_ID,'version':'2.2.0','state':'applied','code':'OK'}))
        self.assertEqual(self.manager.application_result(prepared)['state'],'applied')
        # Fixed helper diagnostics survive without exposing native exception text.
        path.write_text(json.dumps({'app_id':u.APP_ID,'version':'2.2.0','state':'failed','code':'INSTALLER_VERSION'}))
        self.assertEqual(self.manager.application_result(prepared),{'state':'failed','version':'2.2.0','code':'INSTALLER_VERSION'})


class TransportTests(unittest.TestCase):
    def test_only_https_exact_hosts_no_credentials_fragment_or_alternate_port(self):
        for url in (u.API_URL,u.RELEASE_ROOT+'v2.2.0/LabGuard-Setup.exe','https://release-assets.githubusercontent.com/path?token=signed'):
            self.assertTrue(u.allowed_url(url))
        for url in ('http://github.com/x','https://github.com.evil.test/x','https://user:pass@github.com/x','https://github.com:444/x','https://github.com/x#fragment','file:///tmp/app.exe','https://objects.githubusercontent.com@evil.test/x'):
            self.assertFalse(u.allowed_url(url))

    def test_redirect_refuses_api_move_other_repository_and_non_https(self):
        for initial,new in ((u.API_URL,u.API_URL.replace('perabru','other')),(u.RELEASE_ROOT+'v2.2.0/LabGuard-Setup.exe','https://github.com/other/Repo/releases/download/v2.2.0/LabGuard-Setup.exe'),(u.RELEASE_ROOT+'v2.2.0/LabGuard-Setup.exe','http://release-assets.githubusercontent.com/payload'),(u.RELEASE_ROOT+'v2.2.0/LabGuard-Setup.exe',u.API_URL)):
            with self.subTest(new=new),self.assertRaises(u.UpdateError):u._SafeRedirect(initial).redirect_request(Request(initial),None,302,'',{},new)
        initial=u.RELEASE_ROOT+'v2.2.0/LabGuard-Setup.exe'
        result=u._SafeRedirect(initial).redirect_request(Request(initial),None,302,'',{},'https://release-assets.githubusercontent.com/signed')
        self.assertEqual(result.full_url,'https://release-assets.githubusercontent.com/signed')

    def response(self, content=b'abc', url=u.API_URL, length=None):
        response=Mock();response.status=200;response.geturl.return_value=url
        response.headers={'Content-Length':str(len(content)) if length is None else length}
        response.read1.side_effect=[content,b''];response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        return response

    def test_transport_requires_tls_verification_and_read1(self):
        response=self.response()
        manager=u.UpdateManager('2.2.0',frozen=False)
        opener=Mock();opener.open.return_value=response
        with patch.object(u,'build_opener',return_value=opener) as build:
            self.assertEqual(manager._download(u.API_URL,10,time.monotonic()+10)[0],b'abc')
            context=next(handler._context for handler in build.call_args.args if hasattr(handler,'_context'))
            self.assertTrue(context.check_hostname);self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
            response.read1.assert_called();response.read.assert_not_called()

    def test_api_redirect_final_url_size_and_network_errors_fail_closed(self):
        for response in (self.response(url=u.API_URL.replace('perabru','other')),self.response(length='999'),self.response(length='nonnumeric')):
            manager=u.UpdateManager('2.2.0',frozen=False);opener=Mock();opener.open.return_value=response
            with patch.object(u,'build_opener',return_value=opener),self.assertRaises(u.UpdateError):manager._download(u.API_URL,10,time.monotonic()+10)
        with patch.object(u,'build_opener',side_effect=ssl.SSLError('secret-url')):
            # Building a valid context/opener happens before I/O; no insecure retry exists.
            with self.assertRaises(ssl.SSLError):u.UpdateManager('2.2.0')._download(u.API_URL,10,time.monotonic()+10)

    def test_actual_read_bytes_and_global_deadline_are_bounded(self):
        manager=u.UpdateManager('2.2.0',frozen=False)
        response=self.response(b'four',length='3');opener=Mock();opener.open.return_value=response
        with patch.object(u,'build_opener',return_value=opener),self.assertRaises(u.UpdateError):manager._download(u.API_URL,3,time.monotonic()+10)
        response=self.response();opener.open.return_value=response
        with patch.object(u,'build_opener',return_value=opener),patch.object(u.time,'monotonic',side_effect=[0,0,11]),self.assertRaises(u.UpdateError):manager._download(u.API_URL,10,10)


if __name__=='__main__':unittest.main()
