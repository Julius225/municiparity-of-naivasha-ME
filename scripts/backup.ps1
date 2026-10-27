param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

. (Join-Path $PSScriptRoot 'backup-common.ps1')
$settings = Get-AppSettings -ProjectRoot $ProjectRoot
if (-not (Test-Path -LiteralPath $settings.Mysqldump -PathType Leaf)) {
    throw "MySQL dump utility not found: $($settings.Mysqldump). Set MYSQLDUMP_PATH in .env."
}

Protect-BackupDirectory -Path $settings.BackupPath
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$workPath = Join-Path $settings.BackupPath ('.working-' + $stamp + '-' + [guid]::NewGuid().ToString('N'))
$archivePath = Join-Path $settings.BackupPath ("municipal-me-$stamp.zip")
$credentialsPath = $null

try {
    New-Item -ItemType Directory -Path $workPath -Force | Out-Null
    $credentialsPath = New-MySqlCredentialsFile -Settings $settings -WorkDirectory $workPath
    $dumpPath = Join-Path $workPath 'database.sql'
    & $settings.Mysqldump "--defaults-extra-file=$credentialsPath" '--single-transaction' '--routines' '--triggers' '--events' '--hex-blob' '--databases' $settings.Database "--result-file=$dumpPath"
    Assert-MySqlExitCode -Operation 'Database backup'
    if (-not (Test-Path -LiteralPath $dumpPath -PathType Leaf) -or (Get-Item -LiteralPath $dumpPath).Length -eq 0) {
        throw 'The database backup file was not created or is empty.'
    }

    $privateCopy = Join-Path $workPath 'private'
    New-Item -ItemType Directory -Path $privateCopy -Force | Out-Null
    if (Test-Path -LiteralPath $settings.PrivatePath -PathType Container) {
        Get-ChildItem -LiteralPath $settings.PrivatePath -Force | Copy-Item -Destination $privateCopy -Recurse -Force
    }

    Remove-Item -LiteralPath $credentialsPath -Force
    $credentialsPath = $null
    Compress-Archive -Path $dumpPath, $privateCopy -DestinationPath $archivePath -CompressionLevel Optimal -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf) -or (Get-Item -LiteralPath $archivePath).Length -eq 0) {
        throw 'The backup archive was not created or is empty.'
    }
    Write-Output "Backup created: $archivePath"
} finally {
    if ($credentialsPath -and (Test-Path -LiteralPath $credentialsPath)) {
        Remove-Item -LiteralPath $credentialsPath -Force
    }
    if (Test-Path -LiteralPath $workPath) {
        Remove-Item -LiteralPath $workPath -Recurse -Force
    }
}
