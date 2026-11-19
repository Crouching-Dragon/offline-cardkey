; ============================================================
; 客户端安装包脚本
;
; 用法：
;   1. 先在 licguard 目录跑 python build.py，生成 dist/
;   2. 用 Inno Setup Compiler 打开本文件
;   3. 按 Ctrl+F9 编译，产物在 installer\output\ 下
;
; 想改产品名 / 版本号，改下面三行 #define 就行。
; ============================================================

#define AppName "本地安全密码"
#define AppVersion "1.0.0"
#define AppPublisher "你的名字"

[Setup]
; AppId 是这个软件的唯一标识。{ 要写成 {{ 表示一个真正的左花括号。
; 生成一次后就不要再改，否则会被当成两个不同的软件。
AppId={{8F3C2A41-5B7E-4D19-9C62-1A7B0E5D3F28}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}

; 装到当前用户目录，不需要管理员权限，也不会弹 UAC
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest

OutputDir=output
OutputBaseFilename=Setup_LicGuard_v{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64

UninstallDisplayIcon={app}\app.exe
UninstallDisplayName={#AppName}

[Languages]
; 已启用简体中文向导（依赖 Languages\ChineseSimplified.isl）
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 整个 dist/ 目录都装进去：两个 exe + 运行时 dll + payload.bin + license.lic
; recursesubdirs 负责 cryptography、bcrypt 这些子目录
Source: "..\dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; 开始菜单
Name: "{group}\{#AppName}"; Filename: "{app}\app.exe"
Name: "{group}\卸载 {#AppName}"; Filename: "{uninstallexe}"
; 桌面快捷方式（安装时由用户勾选）
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\app.exe"; Tasks: desktopicon

[Run]
; 装完可以直接启动
Filename: "{app}\app.exe"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent
