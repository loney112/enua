param(
    [string] $RaffleSecret = "replace-with-some-secret",
    [string] $PythonExe = "$PSScriptRoot\.venv\Scripts\python.exe",
    [string] $AppFile = "$PSScriptRoot\app.py",
    [switch] $CreateAdmin,
    [string] $AdminUser = "admin",
    [string] $AdminPassword = "",
    [switch] $PersistAdmin  # if set, will persist ADMIN_USER and ADMIN_PW_HASH to user env vars
)

# Set the RAFFLE_SECRET for this PowerShell session
$env:RAFFLE_SECRET = $RaffleSecret
Write-Host "RAFFLE_SECRET set for this session (not persisted)."

# Optionally create admin credentials, show them in the terminal and set session env vars
if ($CreateAdmin) {
    # Generate a random password if none provided
    if ([string]::IsNullOrEmpty($AdminPassword)) {
        $bytes = New-Object byte[] 12
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $raw = [Convert]::ToBase64String($bytes) -replace '[+/=]', ''
        $AdminPassword = $raw.Substring(0, [Math]::Min(16, $raw.Length))
    }

    Write-Host "Generating ADMIN_PW_HASH for user '$AdminUser'..."

    if (-Not (Test-Path $PythonExe)) {
        Write-Error "Python executable not found at: $PythonExe. Cannot generate password hash."
        exit 1
    }

    # Use the project's Python + Werkzeug to generate a password hash
    try {
        $hash = & $PythonExe -c "import sys; from werkzeug.security import generate_password_hash; print(generate_password_hash(sys.argv[1]))" $AdminPassword 2>&1
    } catch {
        Write-Error "Failed to generate password hash: $_"
        exit 1
    }

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($hash)) {
        Write-Error "Python returned an error while generating the hash:`n$hash"
        exit 1
    }

    # Trim newline(s)
    $hash = $hash -replace "\r|\n", ""

    # Set session env vars
    $env:ADMIN_USER = $AdminUser
    $env:ADMIN_PW_HASH = $hash

    # Verify the generated hash matches the plaintext password using the project's Python
    Write-Host "Verifying generated hash..."
    try {
        $verify = & $PythonExe -c "import sys; from werkzeug.security import check_password_hash; h=sys.argv[1]; p=sys.argv[2]; print(check_password_hash(h,p))" $hash $AdminPassword 2>&1
    } catch {
        Write-Error "Failed to verify password hash: $_"
        exit 1
    }
    $verify = $verify -replace "\r|\n", ""
    Write-Host "Password verification result: $verify"
    if ($verify -ne 'True') {
        Write-Warning "Verification failed: the generated hash does not validate the password. Stopping to avoid launching with mismatched credentials."
        exit 1
    }

    Write-Host "Admin credentials for this session (not persisted):"
    Write-Host "  ADMIN_USER = $AdminUser"
    Write-Host "  ADMIN_PASSWORD = $AdminPassword"
    Write-Host "  ADMIN_PW_HASH (stored in env) = $hash"

    if ($PersistAdmin) {
        Write-Host "Persisting ADMIN_USER and ADMIN_PW_HASH to user environment variables..."
        [System.Environment]::SetEnvironmentVariable('ADMIN_USER',$AdminUser,'User')
        [System.Environment]::SetEnvironmentVariable('ADMIN_PW_HASH',$hash,'User')
        Write-Host "Persisted. Open a new shell to see persisted values.";
    }
}

# Ensure path strings with spaces are handled and run Python
if (-Not (Test-Path $PythonExe)) {
    Write-Error "Python executable not found at: $PythonExe"
    Write-Host "Edit the script or pass -PythonExe with the correct path.";
    exit 1
}

Write-Host "Starting app: $AppFile using $PythonExe"
& $PythonExe $AppFile
