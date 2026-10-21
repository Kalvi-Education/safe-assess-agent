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
OutputBaseFilename=safeagent-{#AgentVersion}-windows-x64-{#ArtifactMode}
UninstallDisplayName=Kalvium SafeAgent
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
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

[Code]
var
  SafetyPage: TInputOptionWizardPage;

procedure InitializeWizard;
begin
  SafetyPage := CreateInputOptionPage(wpWelcome, 'Before installing or repairing',
    'Never change SafeAgent during an assessment.',
    'Finish or leave every active assessment and close Chrome before continuing.', True, False);
  SafetyPage.Add('I have no active assessment and have closed Chrome.');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = SafetyPage.ID then
    Result := SafetyPage.Values[0];
end;

function InitializeSetup: Boolean;
begin
  Result := True;
  if WizardSilent then
    Result := MsgBox('Confirm there is no active assessment and Chrome is closed before installing or repairing SafeAgent.', mbConfirmation, MB_YESNO) = IDYES;
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
  if RegQueryStringValue(HKCU, 'Software\Google\Chrome\NativeMessagingHosts\com.kalvium.safeagent', '', RegisteredManifest) then
    if CompareText(RegisteredManifest, ExpandConstant('{app}\com.kalvium.safeagent.json')) <> 0 then
      Result := 'Existing non-default SafeAgent registration found. Cancel and ask authorized IT to review and uninstall the old installation with Chrome closed before retrying. No files or registration have been moved.';
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
  Result := MsgBox('Uninstall only outside an assessment. Confirm all assessments are finished and Chrome is closed.', mbConfirmation, MB_YESNO) = IDYES;
end;
