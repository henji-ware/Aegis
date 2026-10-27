param([Parameter(Mandatory=$true)][int]$AppProcessId)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true') { throw 'This helper is only for isolated CI runners.' }
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$messages = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../locales/en.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$automation = [System.Windows.Automation.AutomationElement]
$windowCondition = [System.Windows.Automation.PropertyCondition]::new($automation::ProcessIdProperty, $AppProcessId)
$appWindow = $null
for ($attempt = 0; $attempt -lt 120; $attempt++) {
  $appWindow = $automation::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children,$windowCondition)
  if ($appWindow) { break }
  Start-Sleep -Milliseconds 500
}
if (-not $appWindow) { throw 'Native app window is unavailable to UI Automation.' }
function Get-AppNames {
  $names = @()
  $controls = $appWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
  foreach ($control in $controls) { try { if ($control.Current.Name) { $names += $control.Current.Name } } catch {} }
  return $names
}
function Wait-AppText([string]$Expected,[int]$Seconds=60) {
  $until = [DateTime]::UtcNow.AddSeconds($Seconds)
  do {
    if (Get-AppNames | Where-Object { $_.Contains($Expected) }) { return }
    Start-Sleep -Milliseconds 500
  } while ([DateTime]::UtcNow -lt $until)
  Write-Output ((Get-AppNames | Select-Object -First 80) | ConvertTo-Json -Compress)
  throw "Native UI did not show expected text: $Expected"
}
function Invoke-AppButton([string]$Name) {
  $condition = [System.Windows.Automation.AndCondition]::new(
    [System.Windows.Automation.PropertyCondition]::new($automation::ControlTypeProperty,[System.Windows.Automation.ControlType]::Button),
    [System.Windows.Automation.PropertyCondition]::new($automation::NameProperty,$Name)
  )
  $button = $null
  for ($attempt=0;$attempt -lt 60;$attempt++) {
    $button=$appWindow.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$condition)
    if ($button) { break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $button) { throw "Native UI button not found: $Name" }
  $invoke=[System.Windows.Automation.InvokePattern]$button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
  $invoke.Invoke()
}
Wait-AppText ([Environment]::MachineName)
Invoke-AppButton $messages.'Antivírus'
Wait-AppText 'ClamAV 1.5.4'
Invoke-AppButton $messages.'Visão geral'
Invoke-AppButton $messages.'Verificar sistema'
Wait-AppText $messages.'Verificação concluída' 120
Write-Output 'PASS: actual extracted MSI app, Windows accessibility tree, Rust-provided device data, bundled ClamAV version and completed read-only diagnostic. No native security setting was changed.'
