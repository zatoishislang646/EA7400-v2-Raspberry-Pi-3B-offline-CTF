#!/usr/bin/env python3
"""Provision a dedicated Raspberry Pi OS (NetworkManager) host. Run with sudo."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path('/etc/ctf-lab')
APP = Path('/opt/ctf-lab')
DATA = Path('/var/lib/ctf-lab')
SELF = Path('/usr/local/sbin/ctf-pi-setup')
UNITS = Path('/etc/systemd/system')
STATE = ROOT / 'state.json'
LAB_ID = 'ctf-lab'
LAB_IP = '192.168.77.10'
SYSCTL_FILE = Path('/etc/sysctl.d/90-ctf-lab.conf')
SYSCTL = {'net.ipv4.ip_forward': '0', 'net.ipv6.conf.all.forwarding': '0'}

FIREWALL = '''table inet ctf_lab {
  chain input {
    type filter hook input priority -20; policy drop;
    iifname "lo" accept
    iifname != "eth0" drop
    meta nfproto ipv6 drop
    ct state invalid drop
    ct state established,related accept
    ip saddr 192.168.77.0/24 tcp dport { 22, 53, 8080, 31337 } accept
    ip saddr 192.168.77.0/24 udp dport 53 accept
    ip saddr 192.168.77.0/24 ip protocol icmp accept
  }
  chain forward {
    type filter hook forward priority -20; policy drop;
  }
  chain output {
    type filter hook output priority -20; policy drop;
    oifname "lo" accept
    oifname "eth0" ip daddr 192.168.77.0/24 ct state established,related accept
  }
}
'''
FIREWALL_UNIT = '''[Unit]
Description=Offline CTF host firewall
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target NetworkManager.service ctf-lab.service
Wants=network-pre.target
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/ctf-pi-setup firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
'''
APP_UNIT = '''[Unit]
Description=Offline Raspberry Pi CTF arena
After=network-online.target NetworkManager-wait-online.service ctf-lab-firewall.service
Wants=network-online.target NetworkManager-wait-online.service
Requires=ctf-lab-firewall.service
StartLimitIntervalSec=0

[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=45
User=ctf-lab
Group=ctf-lab
WorkingDirectory=/opt/ctf-lab
ExecStart=/usr/bin/python3 -B /opt/ctf-lab/arena.py --flags /var/lib/ctf-lab/flags.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/opt/ctf-lab /var/lib/ctf-lab
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_UNIX
UMask=0027
MemoryMax=160M
TasksMax=96
LimitNOFILE=256
CPUQuota=75%

[Install]
WantedBy=multi-user.target
'''
CUTOVER_UNIT = '''[Unit]
Description=Complete pending offline CTF network cutover
After=NetworkManager.service
Requires=NetworkManager.service
ConditionPathExists=/etc/ctf-lab/pending
StartLimitIntervalSec=0

[Service]
Type=oneshot
TimeoutStartSec=180
Restart=on-failure
RestartSec=5
ExecStart=/usr/bin/python3 /usr/local/sbin/ctf-pi-setup apply

[Install]
WantedBy=multi-user.target
'''


def run(*args, check=True, capture=False, input=None):
    result = subprocess.run(args, check=check, text=True, input=input,
                            env={**os.environ, 'LC_ALL': 'C'},
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else result.returncode


def output(*args):
    return run(*args, capture=True)


def active(unit):
    return run('systemctl', 'is-active', '--quiet', unit, check=False) == 0


def enabled(unit):
    return run('systemctl', 'is-enabled', '--quiet', unit, check=False) == 0


def write(path, content, mode=0o644):
    # Same-directory atomic replacement; never truncate the only recovery copy.
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def require_pi():
    model = Path('/proc/device-tree/model')
    if not model.exists() or 'Raspberry Pi' not in model.read_text():
        raise RuntimeError('Use a dedicated Raspberry Pi; this is not a general workstation installer.')
    if not Path('/etc/debian_version').exists() or int(Path('/etc/debian_version').read_text().split('.')[0]) < 12:
        raise RuntimeError('Use Raspberry Pi OS Bookworm/Debian 12 or later (32-bit or 64-bit).')
    if sys.version_info < (3, 11):
        raise RuntimeError('Python 3.11+ is required for bounded SQLite queries.')
    if not shutil.which('nmcli') or not active('NetworkManager.service'):
        raise RuntimeError('NetworkManager must already manage this Pi. Legacy dhcpcd systems are not supported.')
    if not Path('/sys/class/net/eth0').exists():
        raise RuntimeError('Expected the onboard Ethernet interface eth0.')
    if output('nmcli', '-g', 'GENERAL.NM-MANAGED', 'device', 'show', 'eth0') != 'yes':
        raise RuntimeError('NetworkManager is active but does not manage eth0.')


def load_state():
    return json.loads(STATE.read_text())


def firewall():
    # One transaction: replace OUR table only, never flush unrelated rules.
    exists = run('nft', 'list', 'table', 'inet', 'ctf_lab', capture=True, check=False)
    delete = 'delete table inet ctf_lab\n' if exists else ''
    config = delete + (ROOT / 'firewall.nft').read_text()
    run('nft', '--check', '-f', '-', input=config)
    run('nft', '-f', '-', input=config)


def prepare():
    require_pi()
    if STATE.exists():
        raise RuntimeError('Already installed. Uninstall before reconnecting this deliberately vulnerable host to the Internet.')
    run('apt-get', 'update')
    run('apt-get', 'install', '-y', 'python3', 'nftables', 'curl')
    print('Dependencies installed. Disconnect from normal networks; leave the router WAN empty. Then run install --isolated at the Pi console.')


def snapshot():
    connections = []
    for uuid in output('nmcli', '-g', 'UUID', 'connection', 'show').splitlines():
        kind = output('nmcli', '-g', 'connection.type', 'connection', 'show', uuid)
        if kind == '802-3-ethernet':
            connections.append({'uuid': uuid, 'autoconnect': output('nmcli', '-g', 'connection.autoconnect', 'connection', 'show', uuid)})
    current = output('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', 'eth0')
    return {'phase': 'prepared', 'ethernet_connections': connections, 'active_eth_uuid': current,
            'wifi': output('nmcli', 'radio', 'wifi'),
            'nftables_enabled': enabled('nftables.service'),
            'nftables_active': active('nftables.service'),
            'sysctl': {key: output('sysctl', '-n', key) for key in SYSCTL},
            'created_user': False, 'lab_uuid': None}


def save_state(state):
    write(STATE, json.dumps(state, indent=2) + '\n', 0o600)


def install(args):
    require_pi()
    if not args.isolated:
        raise RuntimeError('Pass --isolated ONLY after unplugging WAN, all household-network cables, and other uplinks. This changes network and firewall settings.')
    if os.environ.get('SSH_CONNECTION') and not args.allow_ssh_disconnect:
        raise RuntimeError('Use HDMI/keyboard or serial console. To accept an SSH disconnect explicitly, add --allow-ssh-disconnect.')
    if STATE.exists():
        raise RuntimeError('Already installed (or partial install). Use status, rotate-flags, or uninstall; do not reinstall over state.')
    source = Path(__file__).resolve().parent / 'arena.py'
    if not source.is_file():
        raise RuntimeError('Keep arena.py beside pi-setup.py.')
    for cmd in ('nft', 'python3', 'nmcli', 'systemctl', 'sysctl', 'useradd'):
        if not shutil.which(cmd):
            raise RuntimeError(f'Missing {cmd}; run prepare while still online.')
    if output('nft', 'list', 'ruleset'):
        raise RuntimeError('Existing nftables rules found. Use a clean, dedicated Pi; installer will not overwrite another firewall.')
    for unit in ('ufw.service', 'firewalld.service', 'docker.service', 'dhcpcd.service'):
        if active(unit):
            raise RuntimeError(f'{unit} is active; use a clean NetworkManager-based image.')
    for path in (ROOT, APP, DATA, SELF, UNITS / 'ctf-lab.service', UNITS / 'ctf-lab-firewall.service', UNITS / 'ctf-lab-cutover.service', SYSCTL_FILE):
        if path.exists():
            raise RuntimeError(f'Refusing to overwrite pre-existing path: {path}')
    if LAB_ID in output('nmcli', '-t', '-f', 'NAME', 'connection', 'show').splitlines():
        raise RuntimeError('NetworkManager already has a ctf-lab connection.')
    state = snapshot()
    ROOT.mkdir(mode=0o700)
    save_state(state)
    try:
        if run('getent', 'passwd', 'ctf-lab', check=False, capture=True) or run('getent', 'group', 'ctf-lab', check=False, capture=True):
            raise RuntimeError('Pre-existing ctf-lab user/group; refusing to reuse it.')
        # Record ownership intent first so a crash during useradd can be reconciled.
        state['created_user'] = True
        save_state(state)
        run('useradd', '--system', '--user-group', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', 'ctf-lab')
        APP.mkdir(mode=0o755)
        DATA.mkdir(mode=0o750)
        run('chown', 'root:ctf-lab', str(DATA))
        shutil.copyfile(source, APP / 'arena.py')
        (APP / 'arena.py').chmod(0o644)
        shutil.copyfile(Path(__file__).resolve(), SELF)
        SELF.chmod(0o700)
        run('python3', '-B', str(APP / 'arena.py'), '--flags', str(DATA / 'flags.json'), '--generate')
        run('chown', 'root:ctf-lab', str(DATA / 'flags.json'))
        write(ROOT / 'firewall.nft', FIREWALL, 0o600)
        write(UNITS / 'ctf-lab.service', APP_UNIT)
        write(UNITS / 'ctf-lab-firewall.service', FIREWALL_UNIT)
        write(UNITS / 'ctf-lab-cutover.service', CUTOVER_UNIT)
        write(SYSCTL_FILE, ''.join(f'{k}={v}\n' for k, v in SYSCTL.items()))
        run('nmcli', 'connection', 'add', 'type', 'ethernet', 'con-name', LAB_ID, 'ifname', 'eth0',
            'ipv4.method', 'manual', 'ipv4.addresses', LAB_IP + '/24',
            'ipv4.never-default', 'yes', 'ipv4.ignore-auto-dns', 'yes', 'ipv6.method', 'disabled',
            'connection.autoconnect', 'no', 'connection.autoconnect-priority', '1000')
        state['lab_uuid'] = output('nmcli', '-g', 'connection.uuid', 'connection', 'show', LAB_ID)
        save_state(state)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', 'ctf-lab-cutover.service')
        state['phase'] = 'pending'
        save_state(state)
        write(ROOT / 'pending', 'Pending cutover; physical isolation must remain in place.\n', 0o600)
        print('Applying network cutover NOW. SSH will disconnect. Keep the Pi physically isolated.', flush=True)
        run('systemctl', 'start', 'ctf-lab-cutover.service')
        print('Cutover completed and all application listeners reported ready. Portal: http://192.168.77.10:8080/')
        print('At the console, rollback: sudo python3 /usr/local/sbin/ctf-pi-setup uninstall --restore-network')
    except BaseException:
        print('Partial install preserved for recovery. Run: sudo python3 pi-setup.py uninstall --restore-network', file=sys.stderr)
        raise


def apply():
    state = load_state()
    run('systemctl', 'disable', '--now', 'nftables.service', check=False)
    for key, value in SYSCTL.items():
        run('sysctl', '-w', key + '=' + value)
    run('systemctl', 'enable', '--now', 'ctf-lab-firewall.service')
    # Force reload too, including the case where a previous apply left the oneshot active.
    firewall()
    run('nmcli', 'radio', 'wifi', 'off')
    for connection in state['ethernet_connections']:
        run('nmcli', 'connection', 'modify', connection['uuid'], 'connection.autoconnect', 'no')
    run('nmcli', 'connection', 'modify', state['lab_uuid'], 'connection.autoconnect', 'yes')
    run('nmcli', 'connection', 'up', state['lab_uuid'])
    run('systemctl', 'enable', '--now', 'ctf-lab.service')
    state['phase'] = 'applied'
    save_state(state)
    (ROOT / 'pending').unlink(missing_ok=True)


def status():
    for command in (('systemctl', '--no-pager', '--full', 'status', 'ctf-lab.service', 'ctf-lab-firewall.service'),
                    ('ip', '-4', 'address', 'show', 'dev', 'eth0'), ('ip', '-4', 'route'),
                    ('nmcli', 'radio', 'wifi'), ('nft', 'list', 'table', 'inet', 'ctf_lab')):
        run(*command, check=False)
    run('curl', '--max-time', '3', '--noproxy', '*', '-fsS', 'http://' + LAB_IP + ':8080/health', check=False)
    print('\nA host check cannot prove the router WAN cable is unplugged or that players have no other uplinks.')


def rotate():
    load_state()
    # Generate and set permissions BEFORE touching the current service/flags.
    with tempfile.TemporaryDirectory(prefix='.rotate-', dir=DATA) as temporary:
        replacement = Path(temporary) / 'flags.json'
        run('python3', '-B', str(APP / 'arena.py'), '--flags', str(replacement), '--generate')
        run('chown', 'root:ctf-lab', str(replacement))
        with replacement.open('rb') as stream:
            os.fsync(stream.fileno())
        stop_checked('ctf-lab.service')
        os.replace(replacement, DATA / 'flags.json')
        directory = os.open(DATA, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    run('systemctl', 'start', 'ctf-lab.service')
    print('All five flags rotated. Previous flags are now invalid.')


def stop_checked(unit):
    if output('systemctl', 'show', '--property=LoadState', '--value', unit) == 'not-found':
        return False  # A genuinely absent unit is expected during partial-install recovery.
    run('systemctl', 'stop', unit)
    state = output('systemctl', 'show', '--property=ActiveState', '--value', unit)
    if state not in ('inactive', 'failed'):
        raise RuntimeError(f'{unit} did not stop; isolation and recovery state must remain in place.')
    return True


def uninstall(args):
    if not args.restore_network:
        raise RuntimeError('Pass --restore-network to confirm removal of the arena and restoration of previous Ethernet/Wi-Fi settings; use the Pi console.')
    state = load_state()
    # Any stop failure ABORTS before changing the firewall or networking.
    for unit in ('ctf-lab-cutover.service', 'ctf-lab.service', 'ctf-lab-firewall.service'):
        if stop_checked(unit):
            run('systemctl', 'disable', unit)
    known = output('nmcli', '-g', 'UUID', 'connection', 'show').splitlines()
    if state.get('lab_uuid') and state['lab_uuid'] in known:
        run('nmcli', 'connection', 'delete', state['lab_uuid'])
    elif not state.get('lab_uuid') and LAB_ID in output('nmcli', '-t', '-f', 'NAME', 'connection', 'show').splitlines():
        run('nmcli', 'connection', 'delete', LAB_ID)
    for connection in state['ethernet_connections']:
        run('nmcli', 'connection', 'modify', connection['uuid'], 'connection.autoconnect', connection['autoconnect'])
    for key, value in state['sysctl'].items():
        run('sysctl', '-w', key + '=' + value)
    if run('nft', 'list', 'table', 'inet', 'ctf_lab', capture=True, check=False):
        run('nft', 'delete', 'table', 'inet', 'ctf_lab')
    if state['nftables_enabled']:
        run('systemctl', 'enable', 'nftables.service')
    if state['nftables_active']:
        run('systemctl', 'start', 'nftables.service')
    run('nmcli', 'radio', 'wifi', 'on' if state['wifi'] == 'enabled' else 'off')
    current = state['active_eth_uuid']
    if current and current != '--':
        run('nmcli', 'connection', 'up', current)
    for path in (UNITS / 'ctf-lab.service', UNITS / 'ctf-lab-firewall.service', UNITS / 'ctf-lab-cutover.service', SYSCTL_FILE):
        path.unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    for path in (APP, DATA):
        if path.exists():
            shutil.rmtree(path)
    if state.get('created_user'):
        if run('getent', 'passwd', 'ctf-lab', capture=True, check=False):
            run('userdel', 'ctf-lab')
        if run('getent', 'group', 'ctf-lab', capture=True, check=False):
            run('groupdel', 'ctf-lab')
    SELF.unlink(missing_ok=True)
    shutil.rmtree(ROOT)  # Recovery state is deleted LAST, only after checked restoration.
    print('Arena removed; saved network settings restored. Installed apt packages were left in place. Router configuration is unchanged.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'install', 'apply', 'firewall', 'status', 'rotate-flags', 'uninstall'))
    parser.add_argument('--isolated', action='store_true')
    parser.add_argument('--allow-ssh-disconnect', action='store_true')
    parser.add_argument('--restore-network', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo; no changes made.')
    try:
        if args.command == 'prepare':
            prepare()
        elif args.command == 'install':
            install(args)
        elif args.command == 'uninstall':
            uninstall(args)
        else:
            {'apply': apply, 'firewall': firewall, 'status': status, 'rotate-flags': rotate}[args.command]()
    except (RuntimeError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        if STATE.exists():
            print('Inspect: journalctl -u ctf-lab-cutover -u ctf-lab -u ctf-lab-firewall --no-pager', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
