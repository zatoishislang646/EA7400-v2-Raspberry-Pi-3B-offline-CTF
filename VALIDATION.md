# Validation evidence and deployment limits

## Checks completed on 2026-11-10

- **23 tests passed** on Linux x86-64 using command-line Python **3.12.14**. The final full run completed in 15.690 seconds. `TEST-RESULTS.txt` contains that test output.
- Real, unprivileged loopback listeners exercised HTTP, UDP DNS, TCP DNS, and the banner protocol on temporary high ports. All five challenge solutions and the flag validator were checked.
- Tests covered bad login/SQL syntax, blocked injected SQLite functions, Unicode/malformed input, integer-only IDOR lookup, denied filesystem paths, request-body bounds, DNS malformed/fuzz input, non-recursion/NXDOMAIN/NODATA, persistent flag generation, and overwrite refusal.
- A slow trickled HTTP connection was terminated by the absolute connection deadline; filling the HTTP handler pool did not prevent a UDP DNS answer. Subsequent normal HTTP requests recovered without server traceback logs.
- **Installer tests used mocks, never real privileged commands.** They checked saved UUID-specific settings, firewall replacement transaction structure/order, explicit confirmations, stop-failure abort before removing isolation, atomic-state failure preservation, flag-generation failure preservation, persistent cutover retry/readiness configuration, and creation-intent/pending-marker ordering in a complete mocked install.
- All three Python source files parsed successfully. The independent warm Python parser had a different interpreter than the command-line tests; the test version above is the actual subprocess runtime.
- The PowerShell helper passed the attached Windows machine's built-in PowerShell parser with zero syntax errors. **Only `Parser.ParseInput()` ran; the helper itself did not run, no router login occurred, and no adapter/router settings changed.**
- The final three generated systemd units passed `systemd-analyze verify`. The authoring container does not have NetworkManager installed, so verification used **validation-only placeholder NetworkManager/online-wait units**. Those placeholders are not included in the deployment bundle. This is unit syntax/dependency-shape evidence, not a Pi boot test.
- An independent read-only review identified recovery, startup, SQL-resource, request-deadline, and egress issues. The implementation was revised and regression-tested. A follow-up review found no additional serious blocker in the revised server/applied-state boot path; its two final recovery findings were addressed with cutover retries and durable user-creation intent. This is not a comprehensive security certification.

## Not verified on actual devices

No EA7400 v2 or Raspberry Pi was available to the authoring session. Consequently:

- The Pi installer was **not** executed against real NetworkManager, nftables kernel hooks, users/groups, apt, or a Pi SD card.
- nftables kernel loading/packet containment, actual Raspberry Pi OS boot ordering, carrier-delay recovery, account creation/deletion, power-loss behavior, and real rollback must be checked locally using `ORGANIZER.md`.
- Router UI settings, firmware-specific labels, Wi-Fi behavior, DHCP allocation, and WAN/LAN cable isolation were not tested on the device.
- PowerShell reachability probes/browser opening were not executed; only parser syntax was checked.
- ARM throughput, memory peaks, player-count capacity, and denial-of-service resistance have not been benchmarked. The resource limits are conservative design choices, not measured guarantees.
- No firmware image was downloaded or flashed. EA7400 **v2** third-party firmware support was not established.

Use a dedicated fresh Pi image, keep physical isolation in place, and complete the hardware/reboot/recovery checklist before inviting players. The router needs a one-time manual stock-firmware configuration; there is no supported router-side shell script in this kit.

## Reproduce the nonprivileged tests

On any Linux host with Python 3.11 or newer, from the bundle directory:

```bash
python3 -B tests.py
```

Tests bind loopback only, generate temporary random flags, and do not run the installer with root privileges. Do **not** run `pi-setup.py install` on a general workstation as a test: it is intended to modify a dedicated, physically isolated Pi.
