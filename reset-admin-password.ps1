#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeFile = Join-Path $ScriptDir 'docker-compose.yml'
$EnvFile     = Join-Path $ScriptDir '.env'

if (Test-Path $EnvFile) {
    Get-Content $EnvFile | Where-Object { $_ -match '^\s*[^#\s]' -and $_ -match '=' } | ForEach-Object {
        $idx   = $_.IndexOf('=')
        $key   = $_.Substring(0, $idx).Trim()
        $value = $_.Substring($idx + 1).Trim()
        [System.Environment]::SetEnvironmentVariable($key, $value, 'Process')
    }
}

$TargetUser = if ($args.Count -gt 0) { $args[0] } else { 'admin' }

function Test-Password {
    param([string]$p)
    if ($p.Length -lt 12 -or $p.Length -gt 20) {
        Write-Host "  Password must be 12-20 characters (got $($p.Length))" -ForegroundColor Red
        return $false
    }
    if ($p -notmatch '[a-z]') { Write-Host '  Must contain a lowercase letter' -ForegroundColor Red; return $false }
    if ($p -notmatch '[A-Z]') { Write-Host '  Must contain an uppercase letter' -ForegroundColor Red; return $false }
    if ($p -notmatch '[0-9]') { Write-Host '  Must contain a number'            -ForegroundColor Red; return $false }
    if ($p -notmatch '[^a-zA-Z0-9]') { Write-Host '  Must contain a special character' -ForegroundColor Red; return $false }
    return $true
}

Write-Host '=== Admin Password Reset ==='
Write-Host "Target user: $TargetUser"
Write-Host ''

$NewPass = $null
while ($true) {
    $sec1 = Read-Host 'New password'     -AsSecureString
    $sec2 = Read-Host 'Confirm password' -AsSecureString

    $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec1)
    $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec2)
    try {
        $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
        $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
    }

    if ($plain1 -ne $plain2) {
        Write-Host 'Passwords do not match. Try again.' -ForegroundColor Red
        continue
    }

    if (Test-Password $plain1) {
        $NewPass = $plain1
        break
    }
    Write-Host 'Try again.' -ForegroundColor Red
}

$running = docker compose -f $ComposeFile ps --status running --services 2>$null
if ($running -notmatch '(?m)^backend$') {
    Write-Error 'Error: backend service is not running. Start with: docker compose up -d'
    exit 1
}

Write-Host 'Resetting password...'

$js = @'
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');

const { NEW_PASS, TARGET_USER, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD } = process.env;

(async () => {
    const hash = await bcrypt.hash(NEW_PASS, 12);
    const pool = await mysql.createPool({
        host: DB_HOST,
        port: Number(DB_PORT) || 3306,
        database: DB_NAME,
        user: DB_USER,
        password: DB_PASSWORD,
    });
    const [result] = await pool.execute(
        'UPDATE app_users SET password_hash=?, must_change_password=1 WHERE username=? AND is_admin=1',
        [hash, TARGET_USER]
    );
    await pool.end();
    if (result.affectedRows === 0) {
        console.error(`No admin user found with username: ${TARGET_USER}`);
        process.exit(1);
    }
    console.log(`Password reset for '${TARGET_USER}'. User must change password on next login.`);
})().catch(e => { console.error(e.message); process.exit(1); });
'@

$js | docker compose -f $ComposeFile exec -i `
    -e "NEW_PASS=$NewPass" `
    -e "TARGET_USER=$TargetUser" `
    backend node -
