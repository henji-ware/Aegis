param([Parameter(Mandatory=$true)][string]$MsiPath)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
if ($env:CI -ne 'true') { throw 'MSI inspection is restricted to isolated CI runners.' }
$resolved = (Resolve-Path -LiteralPath $MsiPath).Path
$installer = $null
$database = $null
$view = $null
try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($resolved, 0))
    $sql = "SELECT ``Property``, ``Value`` FROM ``Property`` WHERE ``Property``='ProductCode' OR ``Property``='ProductVersion' OR ``Property``='ProductName'"
    $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @($sql))
    $null = $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
    $properties = @{}
    while ($true) {
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -eq $record) { break }
        try {
            $key = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
            $value = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(2))
            $properties[$key] = $value
        } finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
    }
    $code = [string]$properties['ProductCode']
    if ($code -notmatch '^\{[A-Fa-f0-9-]{36}\}$') { throw 'The MSI has no valid ProductCode.' }
    $state = [int]$installer.GetType().InvokeMember('ProductState', 'GetProperty', $null, $installer, @($code))
    $location = ''
    $version = ''
    if ($state -eq 5) {
        $location = [string]$installer.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installer, @($code, 'InstallLocation'))
        $version = [string]$installer.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installer, @($code, 'VersionString'))
    }
    [pscustomobject]@{
        productCode = $code
        productName = [string]$properties['ProductName']
        productVersion = [string]$properties['ProductVersion']
        productState = $state
        installLocation = $location
        registeredVersion = $version
    } | ConvertTo-Json -Compress
} finally {
    foreach ($item in @($view, $database, $installer)) {
        if ($null -ne $item) { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($item) }
    }
}
