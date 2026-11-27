# Starts the live web console on a Windows PC, in one command. Run it from anywhere:
#   .\scripts\start-console.ps1
# It finds the repo from its own location, frees port 8000 if an old console is still running, checks that the
# bot tunnel is open, and asks for the secrets at hidden prompts. Nothing is written to a file: the secrets live
# only in this process's environment. Open the tunnels first with .\scripts\lab\start-tunnels.ps1.
#   Hidden prompt 1: the bot's API_SECRET (at least 32 characters).
#   Hidden prompt 2: the read-only Splunk token for the Hunt page. Press Enter to skip it (Hunt then stays off).
#   Hidden prompts 3 and 4: the AbuseIPDB and VirusTotal keys for the IP reputation lookup. Press Enter to skip each
#   (the lookup then shows "No threat-intel API keys configured"). They are the same keys as in the bot's .env.
$ErrorActionPreference = "Stop"
$repo   = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "No virtual environment at $python. Create it as described in docs/live-lab.md." }
Set-Location $repo

# 1. Free port 8000 if an old console is still listening there.
Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "Stopping the old console (process $($_.OwningProcess))."
    Stop-Process -Id $_.OwningProcess -Force
}

# 2. The bot tunnel must be open, or the console starts but shows Incidents offline.
if (-not (Test-NetConnection 127.0.0.1 -Port 18765 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
    throw "Port 18765 is not open. Run .\scripts\lab\start-tunnels.ps1 and enter the soc-siem password in each window."
}

# 3. Secrets, typed at hidden prompts.
$secure = Read-Host "Bot API_SECRET (hidden)" -AsSecureString
$env:SOC_BOT_API_SECRET = [System.Net.NetworkCredential]::new("", $secure).Password
if ($env:SOC_BOT_API_SECRET.Length -lt 32) { throw "That is shorter than 32 characters; it is not the bot's API_SECRET." }

$tok = Read-Host "Splunk read-only token (hidden, Enter to skip)" -AsSecureString
$token = [System.Net.NetworkCredential]::new("", $tok).Password
if ($token) {
    if ($token.Length -lt 100) { throw "That is too short to be a Splunk token (about 500 characters)." }
    $env:SPLUNK_TOKEN = $token
    $env:SPLUNK_URL = "https://127.0.0.1:18089"
    $env:SPLUNK_VERIFY_TLS = "false"
}

foreach ($key in @(@("ABUSEIPDB_API_KEY", "AbuseIPDB API key"), @("VIRUSTOTAL_API_KEY", "VirusTotal API key"))) {
    $s = Read-Host "$($key[1]) (hidden, Enter to skip)" -AsSecureString
    $v = [System.Net.NetworkCredential]::new("", $s).Password
    if ($v) { Set-Item -Path "Env:$($key[0])" -Value $v }
}

# 4. Settings for the live lab.
$env:SOC_BOT_API_URL = "http://127.0.0.1:18765"
$env:SOC_BOT_MOCK = "false"
$env:AI_BACKEND = "claude_code"
if (-not $env:AI_COMMAND) { $env:AI_COMMAND = "claude" }
$env:SOC_WEB_HOST = "127.0.0.1"
$env:SOC_WEB_PORT = "8000"
$env:SOC_WEB_SECURE_COOKIES = "false"      # plain HTTP on localhost
$env:SOC_WEB_SECRET_KEY = & $python -c "import secrets; print(secrets.token_hex(32))"

Write-Host "Console starting at http://127.0.0.1:8000 (Ctrl+C stops it)."
& $python -m soc_web
