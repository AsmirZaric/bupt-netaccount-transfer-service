param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('thumbprint', 'check_trust', 'install_trust',
                 'kill_all', 'status_running')]
    [string]$Action
)

$ErrorActionPreference = 'Stop'
$caFile = "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"

# ----- Resolve DATA_DIR (must match shared/_paths.py exactly) -----
# Override base via $env:ATRUST_VPN_DATA; default to
# %APPDATA%\atrust-vpn on Windows.
if ($env:ATRUST_VPN_DATA) {
    $dataDir = $env:ATRUST_VPN_DATA
} elseif ($env:APPDATA) {
    $dataDir = Join-Path $env:APPDATA 'atrust-vpn'
} else {
    $dataDir = Join-Path $env:USERPROFILE '.atrust-vpn'
}
$stateDir = Join-Path $dataDir 'state'
$logsDir  = Join-Path $dataDir 'logs'

function Get-CaCert {
    if (-not (Test-Path -LiteralPath $caFile)) {
        throw "CA file missing: $caFile"
    }
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $caFile
}

switch ($Action) {

    'thumbprint' {
        # Bare SHA-1 thumbprint (uppercase hex), one line, no decoration.
        Write-Output (Get-CaCert).Thumbprint
    }

    'check_trust' {
        $tp = (Get-CaCert).Thumbprint
        $found = Get-ChildItem -Path Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
                 Where-Object { $_.Thumbprint -eq $tp }
        if ($found) { Write-Output 'yes' } else { Write-Output 'no' }
    }

    'install_trust' {
        $cert = Get-CaCert
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($cert)
        $store.Close()
        Write-Output 'installed'
    }

    'kill_all' {
        $killed = 0
        Get-CimInstance Win32_Process | Where-Object {
            ($_.Name -eq 'python.exe' -and (
                $_.CommandLine -like '*mitm_capture.py*' -or
                $_.CommandLine -like '*otp_poller.py*'   -or
                $_.CommandLine -like '*atrust_setup.py*' -or
                $_.CommandLine -like '*mitmdump.exe*'
            ))
        } | ForEach-Object {
            try {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
                $killed++
            } catch {}
        }
        # Nuke any orphaned tail/grep/sed pipeline left over from a previous
        # test run's `tail -f .../a.log | grep | sed` subshell. They become
        # orphans of init when our bash subshell exits but keep tailing the
        # same log -- next run's tail joins them and OTP lines print multiple
        # times. We match on the log filenames inside DATA_DIR/logs.
        Get-CimInstance Win32_Process | Where-Object {
            (($_.Name -eq 'tail.exe') -or ($_.Name -eq 'grep.exe') -or ($_.Name -eq 'sed.exe')) -and
            ($_.CommandLine -like '*\a.log*' -or
             $_.CommandLine -like '*\b.log*' -or
             $_.CommandLine -like '*\setup.log*' -or
             $_.CommandLine -like '*\mitm.log*')
        } | ForEach-Object {
            try {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
                $killed++
            } catch {}
        }
        # Clean up PID + capture-flag files in the state dir.
        foreach ($f in @('a.pid', 'b.pid', 'setup.pid', 'capture.flag')) {
            Remove-Item -LiteralPath (Join-Path $stateDir $f) -ErrorAction SilentlyContinue
        }
        # Restore HKCU proxy from backup, if backup file present.
        $backup = Join-Path $stateDir 'proxy_backup.json'
        if (Test-Path -LiteralPath $backup) {
            try {
                $b = Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
                $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
                Set-ItemProperty $key -Name ProxyEnable -Value ([int]$b.ProxyEnable)
                if ($b.PSObject.Properties['ProxyServer'])   { Set-ItemProperty $key -Name ProxyServer   -Value ([string]$b.ProxyServer)   }
                if ($b.PSObject.Properties['ProxyOverride']) { Set-ItemProperty $key -Name ProxyOverride -Value ([string]$b.ProxyOverride) }
                if ($b.PSObject.Properties['AutoConfigURL']) { Set-ItemProperty $key -Name AutoConfigURL -Value ([string]$b.AutoConfigURL) }
            } catch {}
        }
        Write-Output $killed
    }

    'status_running' {
        $rows = @()
        foreach ($cmdMatch in @('mitm_capture.py', 'otp_poller.py', 'atrust_setup.py', 'mitmdump.exe')) {
            $matches = Get-CimInstance Win32_Process | Where-Object {
                $_.Name -eq 'python.exe' -and $_.CommandLine -like "*$cmdMatch*"
            }
            foreach ($m in $matches) {
                $rows += [pscustomobject]@{
                    Pid  = $m.ProcessId
                    Kind = $cmdMatch
                }
            }
        }
        if ($rows.Count -eq 0) {
            Write-Output 'none'
        } else {
            $rows | ForEach-Object { Write-Output ("{0} {1}" -f $_.Pid, $_.Kind) }
        }
    }
}
