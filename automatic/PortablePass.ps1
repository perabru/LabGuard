function Remove-NonInstallerTargets {
    # Remove independent, already-recognized game trees before asking Windows Installer.
    # A slow MSI must not prevent Roblox/portable-game cleanup. Registered installations
    # and paths overlapping an MSI tree keep the original uninstall-first ordering.
    if($script:Dry){return}
    $installerRoots=@($script:Apps|Where-Object {$_.WindowsInstaller -eq 1 -and $_.InstallLocation}|ForEach-Object {Normalize ([string]$_.InstallLocation)}|Where-Object {$_})
    $eligible='^(?:Dados de jogo/emulador conhecido:|Instalacao por usuario:|Roblox Player \(preserva Studio\)|Jogo Steam:|Jogo Epic:|Jogo/emulador reconhecido, inclusive instalacao ISO:|Pasta exclusiva aprovada pelo administrador)'
    foreach($target in @($script:Targets.Values|Sort-Object {$_.Path.Length} -Descending)){
        if([DateTime]::UtcNow -gt $script:Deadline){return}
        if($target.Reason -notmatch $eligible){continue}
        $shared=$false
        foreach($installRoot in $installerRoots){if((Inside $target.Path $installRoot) -or (Inside $installRoot $target.Path)){$shared=$true;break}}
        if($shared){continue}
        Read-Config;if(-not $script:Config.Enabled){return}
        if(-not(Test-Path -LiteralPath $target.Path)){continue}
        try{
            Save-Status 'Executando' $target.Reason
            Delete-Bounded $target.Path $target.Manual
            if(Test-Path -LiteralPath $target.Path){throw 'Alvo ainda existe.'}
            $script:Removed++
            Log 'REMOVIDO' ($target.Reason+' -> '+$target.Path)
        }catch{Log 'FALHA' ($target.Path+': '+$_.Exception.Message)}
    }
}
