$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true') { throw 'This helper is only for isolated CI runners.' }
$runtimeKeys = @(
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
  'HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
)
function Get-RuntimeVersion {
  foreach ($runtimeKey in $runtimeKeys) {
    $runtimeVersion = Get-ItemPropertyValue -LiteralPath $runtimeKey -Name pv -ErrorAction SilentlyContinue
    if ($runtimeVersion -and $runtimeVersion -ne '0.0.0.0') { return $runtimeVersion }
  }
  return $null
}
$installedRuntime = Get-RuntimeVersion
if ($installedRuntime) { Write-Output "WebView2 runtime already available: $installedRuntime"; exit 0 }
$bootstrapperPath = Join-Path $env:RUNNER_TEMP 'aegis-ci-webview2-bootstrapper.exe'
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $bootstrapperPath
$bootstrapperSignature = Get-AuthenticodeSignature -LiteralPath $bootstrapperPath
if ($bootstrapperSignature.Status -ne 'Valid' -or $bootstrapperSignature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'WebView2 bootstrapper publisher verification failed.' }
$runtimeInstaller = Start-Process -FilePath $bootstrapperPath -ArgumentList '/silent','/install' -Wait -PassThru -WindowStyle Hidden
$installedRuntime = Get-RuntimeVersion
if (-not $installedRuntime) { throw "WebView2 runtime missing after setup (exit $($runtimeInstaller.ExitCode))." }
Write-Output "WebView2 runtime prepared for CI: $installedRuntime"
