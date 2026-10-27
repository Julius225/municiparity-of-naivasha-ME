Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AppSettings {
    param([string]$ProjectRoot)

    $envPath = Join-Path $ProjectRoot '.env'
    if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
        throw "Application environment file not found: $envPath"
    }
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $envPath) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') {
            $name = $Matches[1]
            $value = $Matches[2]
            if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            $values[$name] = $value
        }
    }

    foreach ($required in @('DB_NAME', 'DB_USER')) {
        if (-not $values.ContainsKey($required) -or [string]::IsNullOrWhiteSpace($values[$required])) {
            throw "Configure $required in the project-root .env file."
        }
    }

    $root = [System.IO.Path]::GetFullPath($ProjectRoot)
    $privatePath = if ($values.ContainsKey('PRIVATE_STORAGE_PATH') -and $values['PRIVATE_STORAGE_PATH'] -ne '') {
        $values['PRIVATE_STORAGE_PATH']
    } else {
        Join-Path $root 'storage\private'
    }
    $backupPath = if ($values.ContainsKey('BACKUP_DIR') -and $values['BACKUP_DIR'] -ne '') {
        $values['BACKUP_DIR']
    } else {
        Join-Path $root 'storage\backups'
    }
    if (-not [System.IO.Path]::IsPathRooted($privatePath)) { $privatePath = Join-Path $root $privatePath }
    if (-not [System.IO.Path]::IsPathRooted($backupPath)) { $backupPath = Join-Path $root $backupPath }
    $privatePath = [System.IO.Path]::GetFullPath($privatePath)
    $backupPath = [System.IO.Path]::GetFullPath($backupPath)
    $publicPath = [System.IO.Path]::GetFullPath((Join-Path $root 'public')).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $publicPrefix = $publicPath + [System.IO.Path]::DirectorySeparatorChar
    if (
        $privatePath.Equals($publicPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        $privatePath.StartsWith($publicPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        $backupPath.Equals($publicPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        $backupPath.StartsWith($publicPrefix, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw 'Private storage and backups must be outside the public web directory.'
    }

    $mysqlRoot = 'C:\xampp\mysql\bin'
    $mysql = if ($values.ContainsKey('MYSQL_PATH') -and $values['MYSQL_PATH'] -ne '') { $values['MYSQL_PATH'] } else { Join-Path $mysqlRoot 'mysql.exe' }
    $mysqldump = if ($values.ContainsKey('MYSQLDUMP_PATH') -and $values['MYSQLDUMP_PATH'] -ne '') { $values['MYSQLDUMP_PATH'] } else { Join-Path $mysqlRoot 'mysqldump.exe' }
    if (-not (Test-Path -LiteralPath $mysql -PathType Leaf)) { throw "MySQL client not found: $mysql. Set MYSQL_PATH in .env." }

    return @{
        Root = $root
        Values = $values
        Database = $values['DB_NAME']
        User = $values['DB_USER']
        Password = if ($values.ContainsKey('DB_PASSWORD')) { $values['DB_PASSWORD'] } else { '' }
        Host = if ($values.ContainsKey('DB_HOST') -and $values['DB_HOST'] -ne '') { $values['DB_HOST'] } else { '127.0.0.1' }
        Port = if ($values.ContainsKey('DB_PORT') -and $values['DB_PORT'] -ne '') { $values['DB_PORT'] } else { '3306' }
        PrivatePath = $privatePath
        BackupPath = $backupPath
        Mysql = $mysql
        Mysqldump = $mysqldump
    }
}

function Protect-BackupDirectory {
    param([string]$Path)

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $identity = (& whoami.exe).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($identity)) {
        throw 'Unable to determine the current Windows account to protect backup files.'
    }
    & icacls.exe $Path /inheritance:r /grant:r "${identity}:(OI)(CI)(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to restrict backup directory access. Check its Windows permissions.'
    }
}

function New-MySqlCredentialsFile {
    param(
        [hashtable]$Settings,
        [string]$WorkDirectory
    )

    $path = Join-Path $WorkDirectory 'mysql-client.cnf'
    $escape = {
        param([string]$Value)
        return $Value.Replace('\', '\\').Replace('"', '\"')
    }
    $contents = "[client]`r`nuser=`"$(& $escape $Settings.User)`"`r`npassword=`"$(& $escape $Settings.Password)`"`r`nhost=`"$(& $escape $Settings.Host)`"`r`nport=$($Settings.Port)`r`n"
    [System.IO.File]::WriteAllText($path, $contents, [System.Text.Encoding]::ASCII)
    $identity = (& whoami.exe).Trim()
    & icacls.exe $path /inheritance:r /grant:r "${identity}:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        throw 'Unable to protect temporary MySQL credentials.'
    }
    return $path
}

function Assert-MySqlExitCode {
    param([string]$Operation)
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with MySQL exit code $LASTEXITCODE."
    }
}
