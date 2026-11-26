[Setup]
AppId={{F401C834-9A87-4A34-A4F7-30DE73A3511C}
AppName=Kalvium SafeAgent
AppVersion={#AgentVersion}
DefaultDirName={localappdata}\Kalvium\SafeAgent
DisableDirPage=yes
UsePreviousAppDir=no
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=safeagent-{#AgentVersion}-windows-x64
UninstallDisplayName=Kalvium SafeAgent
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Student path is: Install (or tick the safety box on update) -> Finish. Fewer pages, same checks.
DisableWelcomePage=yes
DisableReadyPage=yes
VersionInfoVersion={#AgentVersion}
VersionInfoCompany=Kalvium
VersionInfoProductName=Kalvium SafeAgent
CloseApplications=no
RestartApplications=no
SetupLogging=yes

[Files]
Source: "{#AgentBinary}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#OutputDir}\host-template.json"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
Root: HKCU; Subkey: "Software\Google\Chrome\NativeMessagingHosts\com.kalvium.safeagent"; ValueType: string; ValueData: "{app}\com.kalvium.safeagent.json"; Flags: uninsdeletekey

[UninstallDelete]
Type: files; Name: "{app}\com.kalvium.safeagent.json"

[Messages]
FinishedLabel=SafeAgent is installed.%n%nGo back to your assessment page in Chrome and press Detect SafeAgent, then run the check again. You do not need to restart Chrome or remove the old version.

[Code]
var
  SafetyPage: TInputOptionWizardPage;

// Chrome starts SafeAgent fresh for every check, so a first install is safe with Chrome open.
// Only replacing an existing agent can interrupt a check that is running right now.
function IsUpdate: Boolean;
begin
  Result := FileExists(ExpandConstant('{localappdata}\Kalvium\SafeAgent\safeagent.exe'));
end;

procedure InitializeWizard;
begin
  if IsUpdate then begin
    SafetyPage := CreateInputOptionPage(wpWelcome, 'Before updating',
      'Do not update SafeAgent during an assessment.',
      'Finish or leave any assessment you are taking before continuing. Chrome can stay open.', True, False);
    SafetyPage.Add('I am not taking an assessment right now.');
  end;
end;

// With the Ready page disabled, the last page before installing must say Install.
procedure CurPageChanged(CurPageID: Integer);
begin
  if (SafetyPage <> nil) and (CurPageID = SafetyPage.ID) then
    WizardForm.NextButton.Caption := SetupMessage(msgButtonInstall);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (SafetyPage <> nil) and (CurPageID = SafetyPage.ID) then
    Result := SafetyPage.Values[0];
end;

function InitializeSetup: Boolean;
begin
  Result := True;
  if WizardSilent and IsUpdate then
    Result := SuppressibleMsgBox('Confirm you are not taking an assessment before updating SafeAgent.', mbConfirmation, MB_YESNO, IDYES) = IDYES;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  RegisteredManifest: String;
begin
  Result := '';
  if CompareText(ExpandConstant('{app}'), ExpandConstant('{localappdata}\Kalvium\SafeAgent')) <> 0 then begin
    Result := 'Custom installation paths are not supported. Use the fixed default directory.';
    Exit;
  end;
  // A registration pointing at a manifest that no longer exists is stale (deleted folder or
  // half-removed install); overwrite it instead of sending the student to uninstall.
  if RegQueryStringValue(HKCU, 'Software\Google\Chrome\NativeMessagingHosts\com.kalvium.safeagent', '', RegisteredManifest) then
    if (CompareText(RegisteredManifest, ExpandConstant('{app}\com.kalvium.safeagent.json')) <> 0)
      and FileExists(RegisteredManifest) then
      Result := 'An older copy of SafeAgent is installed in a different place. Open Windows Settings > Apps, uninstall Kalvium SafeAgent, then run this installer again. If that does not work, contact Kalvium support and mention code SA-REG.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Template: AnsiString;
  Manifest, BinaryPath: String;
begin
  if CurStep = ssPostInstall then begin
    if not LoadStringFromFile(ExpandConstant('{app}\host-template.json'), Template) then
      RaiseException('Cannot read native host manifest template');
    Manifest := String(Template);
    BinaryPath := ExpandConstant('{app}\safeagent.exe');
    StringChangeEx(BinaryPath, '\', '\\', True);
    StringChangeEx(Manifest, '@BINARY@', BinaryPath, True);
    if not SaveStringToFile(ExpandConstant('{app}\com.kalvium.safeagent.json'), UTF8Encode(Manifest), False) then
      RaiseException('Cannot register native host manifest');
  end;
end;

function InitializeUninstall: Boolean;
begin
  Result := SuppressibleMsgBox('Uninstall SafeAgent only when you are not taking an assessment. Continue?', mbConfirmation, MB_YESNO, IDYES) = IDYES;
end;
