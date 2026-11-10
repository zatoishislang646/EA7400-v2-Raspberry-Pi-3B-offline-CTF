# EA7400 v2 + Raspberry Pi 3B+ offline CTF

**Use the Linksys as a dedicated, physically isolated AP/switch and the Pi as the challenge host. No firmware flashing, Docker, downloaded vulnerable VM, or public exposure is required.** This kit creates five small challenges and generates fresh random flags for each installation.

## Important limitation: stock router firmware

A stock EA7400 v2 does not expose a supported user scripting shell. There is therefore **no honest, supported “run this on the router” script** in this kit. `router-setup.ps1` runs on a Windows management computer, generates two distinct passwords, prints the configuration checklist, optionally opens the local router UI, and can check lab reachability. You apply the router settings once in that UI. The Pi setup is automated.

Do not use an EA7400 v1, EA7500, or other revision's firmware image. The hardware reference distinguishes the Qualcomm-based EA7400 v1 from the MediaTek-based v2; its OpenWrt installation section describes the v1, not proof of v2 compatibility. This kit does not establish v2 OpenWrt support. If your router already runs a different firmware, verify its exact board/image and recovery procedure independently; this installer does not configure that firmware or bootloader.

This is a CTF hosted **behind** the router, not a router-firmware exploitation lab. The router, management UI, SSH service, other players, and all non-Pi addresses are out of challenge scope.

## Contents

- `router-setup.ps1`: stock-router management helper; does not change router or PC settings.
- `pi-setup.py`: privileged Pi installer, status, flag rotation, firewall loader, and uninstall.
- `arena.py`: Python-standard-library web, authoritative DNS, and TCP challenge services.
- `tests.py`: unprivileged loopback application tests and mocked provisioning tests.
- `ORGANIZER.md`: spoilers, solutions, containment boundaries, verification commands.
- `VALIDATION.md`: exact author-side test evidence and limitations.

## Hardware and OS

- Dedicated Linksys EA7400 **v2**, not your current home/work gateway.
- Pi 3B+ with Raspberry Pi OS **Bookworm or later**, NetworkManager already active, onboard interface `eth0`. Both 32-bit and 64-bit OS are suitable; this kit uses no architecture-specific binaries.
- A spare microSD card, reliable Pi-rated power supply, two Ethernet cables, and preferably a Pi keyboard/display or serial console. Back up the card or use a fresh image. The script will refuse a non-Pi, legacy dhcpcd setup, active competing firewall/Docker, or existing nftables rules.
- Enable SSH and set a unique organizer account password/key in Raspberry Pi Imager if you want SSH administration. Do not use `pi`/`raspberry`, passwordless root, or player accounts on the host.
- Windows management computer for the helper. On macOS/Linux, simply follow its printed checklist below; the helper is not necessary.

## Network design

```text
                    EMPTY yellow WAN/Internet port
                                  X
                      Linksys EA7400 v2
                management IP 192.168.77.1/24
         WPA2/AES CTF-LAB-24 / CTF-LAB-5; DHCP .100-.149
                       blue LAN ports
                      /              \
            Pi eth0 /                \ wired player or organizer
  192.168.77.10/24, no gateway         Wi-Fi players also on same LAN
```

**Never connect any router LAN port to your household/work network.** WAN disconnect alone is insufficient if another LAN port is an uplink. The Pi Wi-Fi is turned off, and its firewall rejects non-loopback/non-eth0 traffic, IPv6, forwarding, and output outside the lab subnet. Players must also disable other uplinks, hotspot/VPN connections, bridge adapters, Internet Connection Sharing, and USB modems. Choose another subnet if `192.168.77.0/24` conflicts with any retained interface; this kit has a fixed subnet, so disconnect the conflict rather than editing only one file.

The router's ordinary DHCP service stays enabled. The Pi uses a static address outside its pool. Clients may receive the router as their default gateway; it leads nowhere with WAN and every other uplink disconnected. This does **not** make the router a trustworthy containment boundary if a cable is reattached. The Pi does not need a gateway or recursive DNS after provisioning.

## Quick start

### 1. Prepare the Pi while still online

Copy this entire extracted directory to the Pi. Review the scripts before running them with root privileges. Run at the Pi console or over your normal, private organizer SSH session:

```bash
cd ~/ctf-kit
sudo python3 pi-setup.py prepare
```

This checks the host and runs `apt-get update` and installs `python3`, `nftables`, and `curl`. It does **not** start challenges or reconfigure networking. Install any optional organizer diagnostic tools (`dnsutils`, `netcat-openbsd`, `nmap`, `tcpdump`) now, if desired. Internet package repositories must be working during this step. The vulnerable services should never run while connected to the Internet.

### 2. Isolate and configure the stock router

Back up the router's existing settings in its supported UI. Disconnect the yellow WAN cable and **all** external LAN uplinks. Connect the management computer and Pi to blue LAN ports. If the router is new, use its supported local setup flow; do not disable your computer firewall or connect the challenge network to the Internet to get past a setup screen.

Windows PowerShell, from the extracted directory:

```powershell
# This process-only bypass does not change the persistent execution policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\router-setup.ps1 -Open
# If its current address is not the factory default:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\router-setup.ps1 -CurrentRouter 192.168.2.1 -Open
```

Do not run the helper again just to retrieve a password: each normal run generates new suggestions; it does not know which passwords you actually saved. Save applied credentials in your password manager.

Apply these settings in the local router UI; labels vary by firmware, so consult its inline help:

- Connectivity / Local Network: router `192.168.77.1`, mask `255.255.255.0`.
- DHCP enabled, start `192.168.77.100`, maximum users **50** (`.100` through `.149`, inclusive).
- Wireless: WPA2-Personal with AES and separate lab SSIDs `CTF-LAB-24` and `CTF-LAB-5`. Use the helper's generated lab password, not a reused credential.
- Distinct administrator password, WPS off, guest network off, UPnP off, no DMZ or port forwards, no remote administration or wireless uplink/repeater. Disable IPv6 routing if the UI offers it. Keep the router firewall enabled.
- Leave DHCP DNS at its default. DNS challenges query the Pi explicitly and do not depend on router DNS forwarding. Do not make the Pi the household DNS server.

Save/apply, then reconnect or renew the computer's DHCP lease. The new router URL is `http://192.168.77.1/` (use HTTPS instead if your installed firmware supports/requires it). Use a local router-password login rather than cloud remote management. The WAN warning/light is expected for this offline lab.

### 3. Install and cut over the Pi

Prefer the Pi's local keyboard/display, because its old network address will go away. Disconnect any normal-network Ethernet path and use only the lab router LAN cable. After confirming physical isolation:

```bash
cd ~/ctf-kit
sudo python3 pi-setup.py install --isolated
```

The installer records prior Ethernet autoconnect settings, active Ethernet UUID, Wi-Fi radio state, nftables service state, and forwarding sysctls. It creates a restricted service account, random flags, units and a static NetworkManager profile. Cutover starts **immediately** through a persistent systemd oneshot: it applies the firewall, turns Wi-Fi off, disables previous Ethernet profiles' autoconnect, activates the lab profile, and starts the arena. Application startup waits until all four listeners are bound before reporting ready. A root-only pending marker makes an interrupted cutover retry at the next boot; remain physically isolated during recovery.

If you deliberately choose to do this over SSH:

```bash
sudo python3 pi-setup.py install --isolated --allow-ssh-disconnect
```

Your session will disconnect. Reconnect from a lab-only client to your existing organizer account at `192.168.77.10`; keep a console available in case networking fails. Do not pass `--isolated` while still attached to a normal LAN: it is a human confirmation, not a cable sensor.

### 4. Verify and play

Wait for the cutover command to complete at the console (or reconnect after an explicit SSH cutover), then open:

```text
http://192.168.77.10:8080/
```

At the Pi console:

```bash
sudo python3 /usr/local/sbin/ctf-pi-setup status
```

On the Windows management computer:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\router-setup.ps1 -Check
```

The expected exposed ports on the Pi are TCP 8080, TCP 31337, UDP/TCP 53, plus TCP 22 only if you separately enabled SSH. An unreachable router port 80 may just mean HTTPS-only management; it is not automatically a failed lab.

Do the additional isolation and reboot checks in `ORGANIZER.md` **before inviting players**. No script can prove that the WAN port is physically empty or that a player has no secondary uplink.

## Daily operation

The service and firewall are enabled at boot. NetworkManager restores the static lab connection; its Wi-Fi radio-off state is persisted. The five flags survive reboot and are shared by this arena instance. `/submit` validates flags and reports challenge/points; there are **no player accounts, persisted scoreboard, ranking, or anti-sharing system**. Record each player's solved challenges separately and count each once. This avoids a heavyweight CTFd/Docker stack on a 1-GB Pi.

```bash
# Stop/restart only the application; keep isolation in place.
sudo systemctl stop ctf-lab
sudo systemctl start ctf-lab

# Generate fresh flags between events; invalidates every previous flag.
sudo python3 /usr/local/sbin/ctf-pi-setup rotate-flags

# Read generated flags as organizer; don't hand this file to players.
sudo python3 -m json.tool /var/lib/ctf-lab/flags.json

# Logs; application deliberately does not retain access logs or submitted flags.
sudo journalctl -u ctf-lab -u ctf-lab-firewall -u ctf-lab-cutover --no-pager
```

## Recovery / removal

Use the Pi console, not an SSH connection you cannot afford to lose:

```bash
sudo python3 /usr/local/sbin/ctf-pi-setup uninstall --restore-network
```

If installation failed before copying the installed helper, use the original bundle:

```bash
cd ~/ctf-kit
sudo python3 pi-setup.py uninstall --restore-network
```

Removal cancels the pending cutover, stops/disables the vulnerable arena, removes only the kit's nftables table, removes its connection/profile/files/account, restores saved settings and attempts to reactivate the original Ethernet UUID. It intentionally leaves apt packages and does not undo package updates or router UI changes. Deleted/externally changed original profiles cannot be reconstructed. Do not reconnect the Pi to normal networks until the arena is stopped and removal succeeded. Retain your SD image backup for complete recovery.

The router remains configured as a lab AP; restore its UI backup separately, with the vulnerable Pi disconnected. Removal is not a router reset.

## Capacity and limitations

The app is designed for a small classroom/lab, not a public competition. Its independent pools allow at most 16 HTTP handlers, 8 UDP DNS handlers, 4 TCP DNS handlers, and 4 banner handlers, so HTTP exhaustion does not consume DNS/banner slots. HTTP request bodies are limited to 4096 bytes, URLs to 8192 bytes, and connected sockets use 5-second inactivity timeouts plus a 10-second absolute connection deadline. The service has a 160-MB memory limit, 96-task limit (including deadline timers), 256-file-descriptor limit, and 75% CPU quota (roughly 0.75 of one core, not 75% of all four cores). These are guardrails, **not a tested concurrency/SLA claim** or comprehensive DoS protection. Start with a few players and monitor `systemd-cgtop`, `free -h`, and journal logs.

Use Ethernet for the Pi; Wi-Fi is only for players. Do not treat nominal router gigabit ports as guaranteed Pi3B+ throughput: this kit is control/request traffic, not a bandwidth exercise. The app has no intentional command execution, unsafe deserialization, arbitrary filesystem read, or kernel exploit. It is neither a VM sandbox nor a secure place to run untrusted participant binaries.

## References

- Linksys EA7400 user guide: physical WAN/LAN distinctions, local management, and configuration categories: https://downloads.linksys.com/downloads/userguide/EA7400-MiniUG_EN_20160208_1534PST.pdf
- Revision-aware hardware reference (third party; distinguish v1 support discussion from v2): https://techinfodepot.shoutwiki.com/wiki/Linksys_EA7400

These sources do not establish a safe EA7400 **v2** flashing procedure. The stock path deliberately avoids that risk.
