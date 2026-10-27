param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$ConfirmDatabase
)

. (Join-Path $PSScriptRoot 'backup-common.ps1')
$settings = Get-AppSettings -ProjectRoot $ProjectRoot
$archivePath = (Resolve-Path -LiteralPath $ArchivePath -ErrorAction Stop).Path
if ([System.IO.Path]::GetExtension($archivePath) -ne '.zip') {
    throw 'Restore requires a .zip archive created by scripts\backup.ps1.'
}

$confirmText = "RESTORE $($settings.Database)"
if ($PSBoundParameters.ContainsKey('ConfirmDatabase')) {
    $confirmation = "RESTORE $ConfirmDatabase"
} else {
    $confirmation = Read-Host "This replaces database '$($settings.Database)' and private files. A safety backup will be created. Type '$confirmText' to continue"
}
if ($confirmation -cne $confirmText) {
    throw 'Restore cancelled; the confirmation text did not match.'
}

$backupScript = Join-Path $PSScriptRoot 'backup.ps1'
& $backupScript -ProjectRoot $settings.Root
if ($LASTEXITCODE -ne 0) { throw 'Safety backup failed. Restore was not started.' }

Protect-BackupDirectory -Path $settings.BackupPath
$workPath = Join-Path $settings.BackupPath ('.restore-' + [guid]::NewGuid().ToString('N'))
$credentialsPath = $null
$privateMovedAside = $null
$privateInstalled = $false
$originalConsoleInputEncoding = $null

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        foreach ($entry in $zip.Entries) {
            $entryName = $entry.FullName.Replace('\', '/')
            if ($entryName.StartsWith('/') -or $entryName.Contains(':') -or $entryName -match '(^|/)\.\.(/|$)') {
                throw 'The archive contains an unsafe file path.'
            }
            if ($entryName -ne 'database.sql' -and $entryName -ne 'private/' -and -not $entryName.StartsWith('private/')) {
                throw "Unexpected archive entry: $entryName"
            }
        }
    } finally {
        $zip.Dispose()
    }

    New-Item -ItemType Directory -Path $workPath -Force | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $workPath -Force
    $dumpPath = Join-Path $workPath 'database.sql'
    $privateExtracted = Join-Path $workPath 'private'
    if (-not (Test-Path -LiteralPath $dumpPath -PathType Leaf) -or (Get-Item -LiteralPath $dumpPath).Length -eq 0) {
        throw 'The archive does not contain a valid database.sql file.'
    }
    if (-not (Test-Path -LiteralPath $privateExtracted -PathType Container)) {
        throw 'The archive does not contain the private storage snapshot.'
    }

    $credentialsPath = New-MySqlCredentialsFile -Settings $settings -WorkDirectory $workPath
    $tables = & $settings.Mysql "--defaults-extra-file=$credentialsPath" '--batch' '--skip-column-names' "--database=$($settings.Database)" '--execute=SHOW TABLES'
    Assert-MySqlExitCode -Operation 'Database table listing'
    $tableNames = @($tables | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($tableName in $tableNames) {
        if ($tableName -notmatch '^[A-Za-z0-9_$]+$') { throw 'Database returned a table name that cannot be safely restored.' }
    }
    $dropStatements = @('SET FOREIGN_KEY_CHECKS=0;')
    foreach ($tableName in $tableNames) {
        $dropStatements += "DROP TABLE IF EXISTS ``$tableName``;"
    }
    $dropStatements += 'SET FOREIGN_KEY_CHECKS=1;'
    & $settings.Mysql "--defaults-extra-file=$credentialsPath" "--database=$($settings.Database)" ('--execute=' + ($dropStatements -join ' '))
    Assert-MySqlExitCode -Operation 'Existing table removal'

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $settings.Mysql
    $processInfo.Arguments = "`"--defaults-extra-file=$credentialsPath`" `"-D$($settings.Database)`""
    $processInfo.UseShellExecute = $false
    $processInfo.RedirectStandardInput = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $utf8Encoding = New-Object System.Text.UTF8Encoding($false)
    $standardInputEncodingProperty = $processInfo.PSObject.Properties['StandardInputEncoding']
    if ($standardInputEncodingProperty) {
        $standardInputEncodingProperty.Value = $utf8Encoding
    } else {
        $originalConsoleInputEncoding = [Console]::InputEncoding
        [Console]::InputEncoding = $utf8Encoding
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    if (-not $process.Start()) { throw 'Unable to start the MySQL restore process.' }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $standardInput = $process.StandardInput
    if ($originalConsoleInputEncoding) {
        [Console]::InputEncoding = $originalConsoleInputEncoding
        $originalConsoleInputEncoding = $null
    }
    $reader = [System.IO.StreamReader]::new($dumpPath, [System.Text.Encoding]::UTF8)
    try {
        $buffer = New-Object char[] 65536
        while (($read = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $standardInput.Write($buffer, 0, $read)
        }
    } finally {
        $reader.Dispose()
        $standardInput.Close()
        if ($originalConsoleInputEncoding) {
            [Console]::InputEncoding = $originalConsoleInputEncoding
        }
    }
    $process.WaitForExit()
    $stderrText = $stderrTask.GetAwaiter().GetResult()
    $null = $stdoutTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) {
        throw "Database import failed with exit code $($process.ExitCode): $stderrText"
    }

    $privateParent = Split-Path -Parent $settings.PrivatePath
    New-Item -ItemType Directory -Path $privateParent -Force | Out-Null
    $restorePrivate = Join-Path $privateParent ('.private-restore-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $restorePrivate -Force | Out-Null
    Get-ChildItem -LiteralPath $privateExtracted -Force | Copy-Item -Destination $restorePrivate -Recurse -Force
    if (Test-Path -LiteralPath $settings.PrivatePath) {
        $privateMovedAside = $settings.PrivatePath + '.before-restore-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
        Move-Item -LiteralPath $settings.PrivatePath -Destination $privateMovedAside
    }
    Move-Item -LiteralPath $restorePrivate -Destination $settings.PrivatePath
    $privateInstalled = $true
    Write-Output "Restore completed. Previous private files were preserved at: $privateMovedAside"
} finally {
    if ($originalConsoleInputEncoding) {
        [Console]::InputEncoding = $originalConsoleInputEncoding
    }
    if ($credentialsPath -and (Test-Path -LiteralPath $credentialsPath)) {
        Remove-Item -LiteralPath $credentialsPath -Force
    }
    if (-not $privateInstalled -and $privateMovedAside -and -not (Test-Path -LiteralPath $settings.PrivatePath)) {
        Move-Item -LiteralPath $privateMovedAside -Destination $settings.PrivatePath
    }
    if (Test-Path -LiteralPath $workPath) {
        Remove-Item -LiteralPath $workPath -Recurse -Force
    }
}
