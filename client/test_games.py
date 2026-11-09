"""Client game regression tests. These never uninstall or stop a real game."""
import ctypes
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


import labguard_cliente as cli

class ClientGameTests(unittest.TestCase):
    def test_supported_players(self):
        self.assertEqual(cli._game_from_image(r'C:\Users\aluno\AppData\Local\Roblox\Versions\version-8d88987437d24648\RobloxPlayerBeta.exe'), 'roblox')
        self.assertEqual(cli._game_from_image(r'C:\Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe'), 'fortnite')
        self.assertEqual(cli._game_from_image(r'C:\apps\Windows10Universal.exe','ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr'), 'roblox')
        self.assertEqual(cli._game_from_image(r'D:\store\Minecraft.Windows.exe','Microsoft.MinecraftUWP_8wekyb3d8bbwe'), 'minecraft')
        self.assertEqual(cli._game_from_image(r'C:\Users\x\Bloxstrap\Versions\version-1234567890123456\RobloxPlayerBeta.exe'), 'roblox')

    def test_studio_java_tail_names_and_unrelated_packages_excluded(self):
        for image, family in ((r'C:\School\Windows10Universal.exe','School.Editor_abc'),
                              (r'C:\School\Minecraft.Windows.exe',''),
                              (r'C:\School\cs2.exe',''),(r'C:\School\javaw.exe',''),
                              (r'C:\Roblox\Versions\version-1234567890aaaaaa\RobloxStudioBeta.exe',''),
                              (r'C:\School\RobloxPlayerBeta.exe',''),
                              (r'C:\tmp\roblox\versions\version-nothex\RobloxPlayerBeta.exe','')):
            with self.subTest(image=image):
                self.assertIsNone(cli._game_from_image(image,family))

    def test_store_catalog_only_signed_expected_packages_and_opt_in_minecraft(self):
        default = cli._game_store_script({})
        self.assertIn('ROBLOXCorporation.RobloxGDK', default)
        self.assertNotIn('Microsoft.MinecraftUWP', default)
        self.assertNotIn('Remove-Item', default)
        self.assertIn("SignatureKind -ne 'Store'", default)
        self.assertIn('-PackageTypeFilter Bundle', default)
        self.assertIsNone(cli._game_store_script({'remove_roblox': False, 'remove_games':['arbitrary; package']}))
        selected = cli._game_store_script({'remove_roblox': False, 'remove_games':['minecraft']})
        self.assertIn('Microsoft.MinecraftUWP', selected)
        self.assertNotIn('ROBLOXCORPORATION.ROBLOX', selected)

    def test_slow_maintenance_not_invoked_on_fast_cycle(self):
        with patch.object(cli,'_enforce_game_processes',return_value={'ok':True}) as processes, patch.object(cli,'_games_ps') as ps:
            self.assertTrue(cli.enforce_games({'games':['roblox','not_a_game']},maintenance=False)['ok'])
            processes.assert_called_once_with({'roblox'})
            ps.assert_not_called()

    def test_removal_failure_reflected_in_public_status(self):
        with patch.object(cli,'_enforce_game_processes',return_value={'ok':True}), patch.object(cli,'_games_ps',return_value={'ok':False,'remaining':1}):
            status = cli.enforce_games({})
        self.assertFalse(status['ok'])
        self.assertEqual(status['store']['remaining'], 1)

    def test_classic_off_skips_powershell(self):
        with patch.object(cli, '_games_ps') as ps:
            self.assertEqual(cli.remove_roblox_for_current_user({'remove_roblox':False}), {'ok':True, 'status':'desativado'})
            ps.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'API nativa do Windows')
    def test_native_process_walk_with_unmatchable_selection(self):
        # No image can map to this selection, so no terminate handle is opened.
        self.assertEqual(cli._enforce_game_processes({'__invalid__'}), {'ok':True,'stopped':0,'failures':0})

    @unittest.skipUnless(os.name == 'nt', 'PowerShell 5.1 do Windows')
    def test_windows_mocked_appx_validates_bundle_and_postcondition(self):
        # Each invocation shadows AppX commands. No Windows package is queried
        # or removed. The official package identity is a fixture.
        fixture = r"""
$script:fixturePresent = $true
function Get-AppxPackage {
    param([switch]$AllUsers, [string]$Name, [string]$PackageTypeFilter)
    if ($script:fixturePresent -and $Name -eq 'ROBLOXCORPORATION.ROBLOX' -and $PackageTypeFilter -eq 'Bundle') {
        [pscustomobject]@{Name=$Name;PackageFamilyName=($Name+'_55nm5eh3cm0pr');
         Publisher='CN=6FEF9772-62F8-4C8B-8DE0-70F628846515';PublisherId='55nm5eh3cm0pr';SignatureKind='__SIGN__';
         IsFramework=$false;IsResourcePackage=$false;PackageFullName='test-bundle'}
    }
}
function Remove-AppxPackage {
    param([switch]$AllUsers, [string]$Package, [string]$ErrorAction)
    if (!$AllUsers -or $Package -ne 'test-bundle') {throw 'Bad target'}
    __REMOVE__
}
"""
        for signature, action, expected_ok, removed, remaining in (
            ('Store', '$script:fixturePresent=$false', True, 1, 0),
            ('Developer', "throw 'Must never remove'", False, 0, 1),
            ('Store', 'return', False, 1, 1),
        ):
            with self.subTest(signature=signature, action=action):
                fixed = fixture.replace('__SIGN__',signature).replace('__REMOVE__',action)
                result = cli._games_ps(fixed + cli._game_store_script({}), 15)
                self.assertEqual((result.get('ok'),result.get('removed'),result.get('remaining')),
                                 (expected_ok,removed,remaining))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell 5.1 do Windows')
    def test_native_syntax_and_system_powershell_path(self):
        import base64
        for source in (cli._game_store_script({}), cli._GAME_CLASSIC_SCRIPT):
            payload = base64.b64encode(source.encode('utf8')).decode('ascii')
            checks = ("$src=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload +
                      "'));$errs=$null;$t=$null;$null=[Management.Automation.Language.Parser]::ParseInput($src,[ref]$t,[ref]$errs);"
                      "@{ok=(@($errs).Count -eq 0)} | ConvertTo-Json -Compress")
            self.assertTrue(cli._games_ps(checks, 15)['ok'])


if __name__ == '__main__':
    unittest.main()
