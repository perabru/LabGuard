using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
namespace LabGuardGames {
static class WindowsGames {
    internal static readonly string[] Packages={"Microsoft.GamingApp","Microsoft.XboxApp","Microsoft.XboxGamingOverlay","Microsoft.XboxGameOverlay","Microsoft.MicrosoftSolitaireCollection","Microsoft.MicrosoftMahjong","Microsoft.MicrosoftMinesweeper","Microsoft.MicrosoftSudoku","Microsoft.MicrosoftJigsaw","Microsoft.MicrosoftBingo","Microsoft.MinecraftUWP","Microsoft.MinecraftWindowsBeta","Microsoft.MinecraftJavaEdition","Microsoft.4297127D64EC6","ROBLOXCORPORATION.ROBLOX"};
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern int GetPackageFullName(IntPtr process,ref uint length,StringBuilder name);
    internal static string PackageOf(IntPtr process){try{uint size=0;int result=GetPackageFullName(process,ref size,null);if(result!=122||size==0||size>2048)return "";var text=new StringBuilder((int)size);return GetPackageFullName(process,ref size,text)==0?text.ToString():"";}catch{return "";}}
    internal static bool KnownPackage(string full){if(String.IsNullOrEmpty(full))return false;foreach(string name in Packages)if(full.StartsWith(name+"_",StringComparison.OrdinalIgnoreCase))return true;return false;}
    internal static bool IsGame(string path,string package){
        if(String.IsNullOrEmpty(path))return false;
        string name=Path.GetFileNameWithoutExtension(path);
        if(name.StartsWith("LabGuard",StringComparison.OrdinalIgnoreCase)||name.Equals("ApplicationFrameHost",StringComparison.OrdinalIgnoreCase)||name.Equals("RuntimeBroker",StringComparison.OrdinalIgnoreCase)||name.Equals("WinStore.App",StringComparison.OrdinalIgnoreCase))return false;
        if(KnownPackage(package))return true;
        // Legacy games are selected only inside the dedicated Microsoft Games folder.
        if(path.IndexOf("\\Microsoft Games\\",StringComparison.OrdinalIgnoreCase)<0)return false;
        var legacy=new HashSet<string>(new[]{"solitaire","sol","freecell","spidersolitaire","spider","minesweeper","winmine","hearts","mshearts","chess","purbleplace","mahjong"},StringComparer.OrdinalIgnoreCase);
        return legacy.Contains(name);
    }
    internal static void Test(){
        foreach(string name in Packages)if(!KnownPackage(name+"_1.0.0.0_x64__8wekyb3d8bbwe"))throw new Exception("Package not recognized: "+name);
        foreach(string name in new[]{"Microsoft.WindowsStore","Microsoft.WindowsCalculator","Microsoft.WindowsNotepad","Microsoft.MSPaint","Microsoft.GamingServices","Microsoft.XboxIdentityProvider","Microsoft.XboxGameCallableUI","Microsoft.MinecraftEducationEdition","Microsoft.GamingAppOther"})if(KnownPackage(name+"_1.0.0.0_x64__8wekyb3d8bbwe"))throw new Exception("Protected/non-game package selected: "+name);
        if(IsGame("C:\\Apps\\ApplicationFrameHost.exe","Microsoft.GamingApp_1_x64__test"))throw new Exception("Shared application host selected.");
        if(!IsGame("C:\\Program Files\\Microsoft Games\\Solitaire\\solitaire.exe",""))throw new Exception("Legacy game not recognized.");
        if(IsGame("C:\\Aulas\\solitaire.exe",""))throw new Exception("Generic executable selected without a catalog identity.");
        Console.WriteLine("Xbox, Windows game identities and system exclusions passed.");
    }
}
}
