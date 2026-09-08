; Inno Setup installer script for the eMRTD Reader.
; Compile it (on Windows) with the Inno Setup compiler `iscc`:
;     iscc packaging\eMRTDReader.iss
; after running  packaging\build.bat  so that dist\eMRTDReader.exe exists.
;
; Installer output:  packaging\Output\eMRTDReader-Setup.exe

#define MyAppName "eMRTD Reader"
#define MyAppVersion "1.0.0"
#define MyAppExeName "eMRTDReader.exe"
#define MyAppId "{{7E1B02E6-4A2C-4E9B-8C0D-5F1A8C9B3D21}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=epassport_is
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=packaging\Output
OutputBaseFilename=eMRTDReader-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
; Uncomment if you add an icon: SetupIconFile=packaging\app.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; The one-file PyInstaller executable.
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
