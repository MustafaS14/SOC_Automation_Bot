# Example launcher for the live web console on a Windows PC. Copy it, edit the two paths below, and run it
# from your own terminal. See docs/live-lab.md.
#   .\run-live.ps1 adduser   creates your account (asks for a username and a password)
#   .\run-live.ps1           starts the console
# The API secret is asked for at a hidden prompt and lives only in this process's environment.
# Nothing is written to a file. The SSH tunnel must already be open:
#   ssh -N -L 18765:172.18.0.1:8765 soc-siem@192.168.56.10
$ErrorActionPreference = "Stop"
$repo   = "C:\path\to\SOC_Automation_Bot"          # edit: your clone
$claude = "claude"                                  # edit: full path to claude.exe if it is not on PATH
Set-Location $repo

$secure = Read-Host "SOC_BOT_API_SECRET (hidden)" -AsSecureString
$env:SOC_BOT_API_SECRET = [System.Net.NetworkCredential]::new("", $secure).Password
if ($env:SOC_BOT_API_SECRET.Length -lt 32) { throw "That is shorter than 32 characters; it is not the bot's API_SECRET." }

$env:AI_COMMAND = $claude
$env:SOC_BOT_MOCK = "false"
$env:SOC_BOT_API_URL = "http://127.0.0.1:18765"
$env:AI_BACKEND = "claude_code"
$env:SOC_WEB_HOST = "127.0.0.1"
$env:SOC_WEB_PORT = "8000"
$env:SOC_WEB_SECURE_COOKIES = "false"               # plain HTTP on localhost
$env:SOC_WEB_SECRET_KEY = & "$repo\.venv\Scripts\python.exe" -c "import secrets; print(secrets.token_hex(32))"

if ($args -contains "adduser") {
    $name = Read-Host "Username for your account"
    & "$repo\.venv\Scripts\python.exe" -m soc_web user add $name --tier admin   # asks for the password itself
    return
}
& "$repo\.venv\Scripts\python.exe" -m soc_web
