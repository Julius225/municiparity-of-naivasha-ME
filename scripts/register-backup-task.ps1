param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Time = '02:00',
    [string]$TaskName = 'MunicipalFlow Daily Backup'
)

. (Join-Path $PSScriptRoot 'backup-common.ps1')
$settings = Get-AppSettings -ProjectRoot $ProjectRoot
$backupScript = Join-Path $PSScriptRoot 'backup.ps1'
$powerShell = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $backupScript -PathType Leaf)) { throw 'Backup script was not found.' }
try {
    $taskTime = [datetime]::ParseExact($Time, 'HH:mm', [Globalization.CultureInfo]::InvariantCulture)
} catch {
    throw 'Set -Time using 24-hour HH:mm format, for example 02:00.'
}

$action = New-ScheduledTaskAction -Execute $powerShell -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$backupScript`" -ProjectRoot `"$($settings.Root)`""
$trigger = New-ScheduledTaskTrigger -Daily -At $taskTime
$principal = New-ScheduledTaskPrincipal -UserId (& whoami.exe).Trim() -LogonType S4U -RunLevel Limited
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description 'Creates a private database and evidence backup for MunicipalFlow.'
try {
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
} catch {
    if ($_.Exception.Message -match 'Access is denied|0x80070005') {
        throw 'Windows denied permission to register the scheduled task. Open PowerShell as Administrator and rerun this script.'
    }
    throw
}
Write-Output "Daily backup task registered for $Time. Verify its first run in Windows Task Scheduler."
