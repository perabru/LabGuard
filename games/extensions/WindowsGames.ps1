# Explicit package identities only. Never remove all Microsoft packages or WindowsApps.
$script:WindowsGamePackages=@('Microsoft.GamingApp','Microsoft.XboxApp','Microsoft.XboxGamingOverlay','Microsoft.XboxGameOverlay','Microsoft.MicrosoftSolitaireCollection','Microsoft.MicrosoftMahjong','Microsoft.MicrosoftMinesweeper','Microsoft.MicrosoftSudoku','Microsoft.MicrosoftJigsaw','Microsoft.MicrosoftBingo')
$script:StoreNames=@(@($script:StoreNames)+$script:WindowsGamePackages|Sort-Object -Unique)
function Is-GamePackage([string]$Name){return $script:StoreNames -contains $Name}
function Remove-Store {
    try{$packages=@(Get-AppxPackage -AllUsers -ErrorAction Stop|Where-Object {Is-GamePackage ([string]$_.Name)})}catch{Log 'PENDENTE' ('Nao foi possivel inventariar Store/Xbox: '+$_.Exception.Message);return}
    foreach($pkg in $packages){
        if([DateTime]::UtcNow -gt $script:Deadline){Log 'PENDENTE' 'Outros pacotes Store/Xbox serao retomados no proximo ciclo.';break}
        if($pkg.IsFramework -or $pkg.IsResourcePackage -or $pkg.NonRemovable){Log 'PENDENTE' ('Pacote protegido ou compartilhado preservado: '+$pkg.Name);continue}
        if($script:Dry){Log 'SIMULACAO' ('Removeria jogo/aplicativo Xbox Store: '+$pkg.PackageFullName);continue}
        Read-Config;if(-not $script:Config.Enabled){return}
        try{Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop;Log 'DESINSTALADO' ('Store/Xbox: '+$pkg.Name);$script:Removed++}catch{Log 'FALHA' ('Store/Xbox '+$pkg.Name+': '+$_.Exception.Message)}
    }
    # Remove only catalogued provisioned games so they are not added to new profiles.
    try{
        foreach($pkg in @(Get-AppxProvisionedPackage -Online -ErrorAction Stop|Where-Object {Is-GamePackage ([string]$_.DisplayName)})){
            if([DateTime]::UtcNow -gt $script:Deadline){break}
            if($script:Dry){Log 'SIMULACAO' ('Removeria provisionamento do jogo para novos usuarios: '+$pkg.DisplayName);continue}
            Read-Config;if(-not $script:Config.Enabled){return}
            try{Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -AllUsers -ErrorAction Stop|Out-Null;Log 'DESINSTALADO' ('Provisionamento: '+$pkg.DisplayName);$script:Removed++}catch{Log 'PENDENTE' ('Provisionamento '+$pkg.DisplayName+': '+$_.Exception.Message)}
        }
    }catch{Log 'PENDENTE' ('Provisionamento Store indisponivel: '+$_.Exception.Message)}
}
function Discover-WindowsGameFolders {
    foreach($base in $script:ProgramRoots){
        foreach($game in @(@('Solitaire','solitaire.exe'),@('FreeCell','freecell.exe'),@('SpiderSolitaire','SpiderSolitaire.exe'),@('Minesweeper','MineSweeper.exe'),@('Hearts','Hearts.exe'),@('Chess','Chess.exe'),@('Purble Place','PurblePlace.exe'),@('Mahjong','Mahjong.exe'))){
            $path=Join-Path $base ('Microsoft Games\'+$game[0]);if(Test-Path -LiteralPath (Join-Path $path $game[1])){Add-Target $path ('Jogo classico do Windows: '+$game[0])}
        }
    }
    foreach($drive in $script:FixedRoots){
        $root=Join-Path $drive 'XboxGames';if(-not(No-Link $root)){continue}
        foreach($dir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)){
            if((Matches-Game $dir.Name) -and ((Test-Path -LiteralPath (Join-Path $dir.FullName 'Content\MicrosoftGame.config')) -or (Test-Path -LiteralPath (Join-Path $dir.FullName 'MicrosoftGame.config')))){
                Add-Target $dir.FullName ('Jogo Xbox reconhecido: '+$dir.Name)
            }else{Log 'PENDENTE' ('XboxGames: titulo fora do catalogo; aprove somente a pasta exclusiva do jogo: '+$dir.FullName)}
        }
    }
}
function Test-WindowsGames {
    foreach($name in @('Microsoft.GamingApp','Microsoft.XboxGamingOverlay','Microsoft.MicrosoftSolitaireCollection','Microsoft.MicrosoftMinesweeper','Microsoft.MicrosoftMahjong')){if(-not(Is-GamePackage $name)){throw ('Jogo Windows nao reconhecido: '+$name)}}
    foreach($name in @('Microsoft.WindowsStore','Microsoft.WindowsCalculator','Microsoft.WindowsNotepad','Microsoft.MSPaint','Microsoft.GamingServices','Microsoft.XboxIdentityProvider','Microsoft.XboxGameCallableUI','Microsoft.MinecraftEducationEdition')){if(Is-GamePackage $name){throw ('Pacote compartilhado/educacional selecionado: '+$name)}}
    Log 'TESTE' 'Catalogo Xbox/Windows e preservacao de Store/componentes compartilhados passaram.'
}
