#ifndef AppVersion
  #define AppVersion "1.4.0"
#endif
#define ProjectRoot AddBackslash(SourcePath) + ".."

[Setup]
AppId={{84474208-6606-4F7A-A421-EDC4FF33948C}
AppName=LabGuard
AppVersion={#AppVersion}
AppVerName=LabGuard {#AppVersion}
AppPublisher=LabGuard
AppPublisherURL=https://perabru.github.io/LabGuard/
AppSupportURL=https://github.com/perabru/LabGuard/issues
AppUpdatesURL=https://github.com/perabru/LabGuard/releases/latest
DefaultDirName={localappdata}\Programs\LabGuard
DefaultGroupName=LabGuard
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#ProjectRoot}\dist\release
OutputBaseFilename=LabGuard-Setup
SetupIconFile={#ProjectRoot}\packaging\generated\LabGuard.ico
UninstallDisplayIcon={app}\LabGuard.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardImageFile={#ProjectRoot}\packaging\generated\wizard.bmp
WizardSmallImageFile={#ProjectRoot}\packaging\generated\wizard-small.bmp
WizardImageStretch=yes
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
DisableWelcomePage=no
UninstallDisplayName=LabGuard

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar um atalho na área de trabalho"; GroupDescription: "Atalhos:"; Flags: unchecked

[Files]
Source: "{#ProjectRoot}\dist\LabGuard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\LabGuard"; Filename: "{app}\LabGuard.exe"; WorkingDir: "{app}"
Name: "{group}\Guia de instalação e uso"; Filename: "{app}\LEIA-ME.html"
Name: "{autodesktop}\LabGuard"; Filename: "{app}\LabGuard.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\LabGuard.exe"; Description: "Abrir o LabGuard"; Flags: nowait postinstall skipifsilent
