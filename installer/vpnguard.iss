; ===========================================================================
;  VPNGuard — однофайловый инсталлер (Inno Setup 6)
;  Собирается в CI: iscc /DMyAppVersion=vX.Y.Z installer\vpnguard.iss
;  Ожидает бинарники в installer\payload\ (кладёт release-job).
;
;  Установка:  файлы -> конфиг (init) -> [правка конфига] -> служба ->
;              задача планировщика для трея (автозапуск без UAC) -> трей.
;  Удаление:   трей -> задача -> служба -> vpnguard panic (снимает ВСЕ
;              фильтры из WFP, сеть гарантированно открыта).
; ===========================================================================

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif

[Setup]
AppId={{9D4E7C52-1A6B-4F3E-8C2D-5E9A0B1C2D3E}
AppName=VPNGuard
AppVersion={#MyAppVersion}
AppPublisher=VPNGuard project
DefaultDirName={autopf}\VPNGuard
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=output
OutputBaseFilename=VPNGuard-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\VpnGuard.Tray.exe
WizardStyle=modern
CloseApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Files]
Source: "payload\vpnguard.exe";      DestDir: "{app}"; Flags: ignoreversion
Source: "payload\VpnGuard.Tray.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\VPNGuard"; Filename: "{app}\VpnGuard.Tray.exe"

[Tasks]
Name: "editconfig"; Description: "Открыть конфиг перед запуском службы (указать пути к openvpn.exe и .ovpn)"
Name: "starttray";  Description: "Запустить иконку VPNGuard в трее"

[Run]
; 1. Конфиг: init не трогает существующий (обновление безопасно)
Filename: "{app}\vpnguard.exe"; Parameters: "init"; \
  StatusMsg: "Создание конфигурации..."; Flags: runhidden waituntilterminated

; 2. Правка конфига ДО старта службы — по умолчанию включено:
;    без правильного пути к .ovpn служба не сможет построить правила
;    реконнекта. Сохраните файл и закройте блокнот, установка продолжится.
Filename: "notepad.exe"; Parameters: """{commonappdata}\VPNGuard\config.yaml"""; \
  Tasks: editconfig; StatusMsg: "Правка конфигурации (сохраните и закройте блокнот)..."; \
  Flags: waituntilterminated

; 3. Служба (переустановка начисто; ошибки uninstall на чистой машине игнорируются)
Filename: "{app}\vpnguard.exe"; Parameters: "service uninstall"; \
  StatusMsg: "Удаление старой службы..."; Flags: runhidden waituntilterminated

; 4. Установка службы + автозапуск трея (schtasks вынесен в [Code]
;    AfterInstall, чтобы не воевать с кавычками Inno Setup).
Filename: "{app}\vpnguard.exe"; Parameters: "service install"; \
  StatusMsg: "Установка и запуск службы VPNGuard..."; Flags: runhidden waituntilterminated; \
  AfterInstall: SetupTrayAutostart

[UninstallRun]
; Порядок важен: трей -> задача -> служба -> panic (открыть сеть)
Filename: "taskkill.exe"; Parameters: "/IM VpnGuard.Tray.exe /F"; \
  RunOnceId: "KillTray"; Flags: runhidden waituntilterminated
Filename: "schtasks.exe"; Parameters: "/Delete /F /TN ""VPNGuard Tray"""; \
  RunOnceId: "DelTask"; Flags: runhidden waituntilterminated
Filename: "{app}\vpnguard.exe"; Parameters: "service uninstall"; \
  RunOnceId: "DelSvc"; Flags: runhidden waituntilterminated
Filename: "{app}\vpnguard.exe"; Parameters: "panic"; \
  RunOnceId: "Panic"; Flags: runhidden waituntilterminated

[Code]
const
  TrayTaskName = 'VPNGuard Tray';

// Создаёт задачу планировщика: трей стартует при входе с наивысшими
// правами и БЕЗ запроса UAC (тот же механизм, что у OpenVPN GUI).
// Затем, если выбрана задача starttray, запускает трей сразу.
// Кавычки в Pascal-строке экранируются удвоением ('') — путь к exe
// заворачивается в двойные кавычки безопасно, без \"-костылей [Run].
procedure SetupTrayAutostart;
var
  RC: Integer;
  TrayExe, CreateParams: String;
begin
  TrayExe := ExpandConstant('{app}\VpnGuard.Tray.exe');
  CreateParams :=
    '/Create /F /TN "' + TrayTaskName + '" ' +
    '/TR "\"' + TrayExe + '\"" ' +
    '/SC ONLOGON /RL HIGHEST /IT';
  Exec('schtasks.exe', CreateParams, '', SW_HIDE, ewWaitUntilTerminated, RC);

  if WizardIsTaskSelected('starttray') then
    Exec('schtasks.exe', '/Run /TN "' + TrayTaskName + '"', '',
      SW_HIDE, ewWaitUntilTerminated, RC);
end;

// Перед копированием файлов гасим то, что может их держать (обновление).
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  RC: Integer;
begin
  Exec('taskkill.exe', '/IM VpnGuard.Tray.exe /F', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Exec('sc.exe', 'stop VPNGuard', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Sleep(1500);
  Result := '';
end;

// Отметить "править конфиг" по умолчанию только при первой установке:
// при обновлении конфиг уже настроен, блокнот не нужен.
procedure InitializeWizard();
begin
  if FileExists(ExpandConstant('{commonappdata}\VPNGuard\config.yaml')) then
    WizardSelectTasks('starttray')
  else
    WizardSelectTasks('editconfig,starttray');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    MsgBox('VPNGuard удалён. Все сетевые фильтры сняты, сеть работает без ограничений.' + #13#10 +
           'Папка с конфигом и логами оставлена: ' +
           ExpandConstant('{commonappdata}\VPNGuard'), mbInformation, MB_OK);
end;
