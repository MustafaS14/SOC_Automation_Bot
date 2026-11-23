# Opens the two SSH tunnels the console needs, each in its own window. Leave both windows open.
#   18765 -> the bot API on soc-siem        18089 -> the Splunk management port on soc-siem
# Run from PowerShell:  .\scripts\lab\start-tunnels.ps1
$siem = "soc-siem@192.168.56.10"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "ssh -N -L 18765:172.18.0.1:8765 $siem"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "ssh -N -L 18089:localhost:8089 $siem"
Write-Host "Two windows opened. Enter the SSH password in each, then check:"
Write-Host "  Test-NetConnection 127.0.0.1 -Port 18765"
Write-Host "  Test-NetConnection 127.0.0.1 -Port 18089"
