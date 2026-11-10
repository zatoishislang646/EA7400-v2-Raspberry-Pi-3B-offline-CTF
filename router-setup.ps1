# Windows PowerShell 5.1+ helper for STOCK Linksys firmware.
# This script does NOT log in, change router settings, or flash firmware.
[CmdletBinding()]
param(
    [string]$CurrentRouter = '192.168.1.1',
    [switch]$Open,
    [switch]$Check
)
$ErrorActionPreference = 'Stop'
$parsed = $null
if (-not [System.Net.IPAddress]::TryParse($CurrentRouter, [ref]$parsed) -or
    $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'CurrentRouter must be a numeric IPv4 address.'
}

function Test-LabPort([string]$Address, [int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($Address, $Port)
        if (-not $task.Wait(2000)) { return $false }
        return $client.Connected
    } catch { return $false }
    finally { $client.Dispose() }
}

if ($Check) {
    foreach ($target in @(
        @{Address='192.168.77.1'; Port=80; Label='Router HTTP (HTTPS-only firmware may fail this)'},
        @{Address='192.168.77.10'; Port=8080; Label='CTF web'},
        @{Address='192.168.77.10'; Port=53; Label='CTF DNS TCP'},
        @{Address='192.168.77.10'; Port=31337; Label='CTF banner'}
    )) {
        $ok = Test-LabPort $target.Address $target.Port
        Write-Host ('{0}: {1}' -f $target.Label, $(if ($ok) {'reachable'} else {'not reachable'}))
    }
    if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
        Write-Host "`nActive default routes (review for unintended uplinks):"
        Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Format-Table InterfaceAlias, NextHop, RouteMetric -AutoSize
        Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
            Format-Table InterfaceAlias, NextHop, RouteMetric -AutoSize
    }
    Write-Warning 'Reachability is not proof of isolation. Physically inspect WAN and every cable; disable other adapters, hotspots, VPNs, and connection sharing.'
    exit
}

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $bytes = New-Object byte[] 18
    $rng.GetBytes($bytes)
    $wifiPass = [Convert]::ToBase64String($bytes)
    $rng.GetBytes($bytes)
    $adminPass = [Convert]::ToBase64String($bytes)
} finally { $rng.Dispose() }

Write-Host @"
STOCK LINKSYS EA7400 v2 - OFFLINE CTF CONFIGURATION
This helper prints a checklist. It cannot execute a shell script on stock firmware.
Review/read the router firmware's own inline help: exact labels vary by version.

1. Back up router settings. Keep this router dedicated to the lab.
2. Yellow Internet/WAN port: EMPTY. No home LAN uplink on any blue LAN port.
3. Connect the management computer and Pi to blue LAN ports.
4. Open the CURRENT local router address: http://$CurrentRouter/
   Use local router-password login, not a cloud account. Never disable your PC firewall.
5. Connectivity > Local Network (or equivalent):
   Router IPv4: 192.168.77.1, netmask 255.255.255.0.
   DHCP: ON; starting IPv4 192.168.77.100; maximum users 50.
   Pi will be STATIC at 192.168.77.10; this lies outside that DHCP pool.
   DHCP DNS may remain default. The DNS challenge queries the Pi directly.
6. Wireless: WPA2-Personal/AES, lab-only SSIDs CTF-LAB-24 and CTF-LAB-5.
   Generated lab Wi-Fi password: $wifiPass
   Do not reuse a home/work password. Disable WPS, guest network, and repeater/uplink modes.
7. Set a DIFFERENT strong administrator password:
   Generated router-admin password: $adminPass
   Disable remote administration, UPnP, DMZ and all port forwards.
   Disable IPv6 routing if offered. Leave the router firewall ON.
8. Save/apply. The session will disconnect. Rejoin lab Wi-Fi or renew the wired lease.
   New local management address: http://192.168.77.1/
9. Finish Pi installation from its keyboard/console. Run this helper with -Check.

Generated passwords are displayed, not stored by this script. Save them in your password manager.
Unplug other client uplinks: Wi-Fi to a home network, phone hotspots, VPNs, USB modems.
All players share one LAN; the router and other players are OUT OF SCOPE.
This setup is an isolated CTF arena, not an exercise in exploiting the router firmware.
"@
if ($Open) { Start-Process ('http://{0}/' -f $CurrentRouter) }
