#!/usr/bin/env python3
"""Unprivileged tests: real loopback services plus mocked installer operations."""
import codecs
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener, Request

BASE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, BASE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

arena = load('arena', 'arena.py')
setup = load('setup', 'pi-setup.py')


def dns_query(name, qtype=16):
    labels = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    return struct.pack('!6H', 1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', qtype, 1)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class DNSUnit(unittest.TestCase):
    def setUp(self):
        arena.FLAGS = arena.make_flags()

    def test_authoritative_txt(self):
        response = arena.dns_reply(dns_query('vault.ctf.lan'))
        header = struct.unpack('!6H', response[:12])
        self.assertEqual(header[0], 1234)
        self.assertEqual(header[3], 1)
        self.assertTrue(header[1] & 0x0400)
        self.assertFalse(header[1] & 0x0080)
        self.assertIn(arena.FLAGS['dns'].encode(), response)
        self.assertLessEqual(len(response), 512)

    def test_a_nodata_and_nxdomain(self):
        self.assertTrue(arena.dns_reply(dns_query('arena.ctf.lan', 1)).endswith(socket.inet_aton(arena.ARENA_IP)))
        response = arena.dns_reply(dns_query('arena.ctf.lan', 28))
        self.assertEqual(struct.unpack('!6H', response[:12])[3], 0)
        self.assertEqual(response[3] & 15, 0)
        self.assertEqual(arena.dns_reply(dns_query('outside.example'))[3] & 15, 3)

    def test_malformed_and_fuzz(self):
        self.assertIsNone(arena.dns_reply(b'bad'))
        self.assertIsNone(arena.dns_reply(struct.pack('!6H', 1, 0, 1, 0, 0, 0) + b'\xc0\x0c\x00\x01\x00\x01'))
        for size in range(600):
            result = arena.dns_reply(os.urandom(size))
            self.assertTrue(result is None or isinstance(result, bytes))


class LiveArena(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.flagfile = Path(cls.temp.name) / 'flags.json'
        subprocess.run([sys.executable, str(BASE / 'arena.py'), '--flags', str(cls.flagfile), '--generate'], check=True)
        cls.flags = json.loads(cls.flagfile.read_text())
        cls.http, cls.dns, cls.tcp = free_port(), free_port(), free_port()
        cls.opener = build_opener(ProxyHandler({}))
        cls.logfile = Path(cls.temp.name) / 'server-stderr.log'
        cls.stderr_file = cls.logfile.open('w')
        cls.process = subprocess.Popen([sys.executable, '-B', str(BASE / 'arena.py'), '--flags', str(cls.flagfile),
                                      '--bind', '127.0.0.1', '--http-port', str(cls.http), '--dns-port', str(cls.dns), '--tcp-port', str(cls.tcp)],
                                     stdout=subprocess.DEVNULL, stderr=cls.stderr_file, text=True)
        for _ in range(100):
            if cls.process.poll() is not None:
                raise RuntimeError(cls.logfile.read_text())
            try:
                with cls.opener.open(f'http://127.0.0.1:{cls.http}/health', timeout=1) as response:
                    if response.status == 200:
                        return
            except OSError:
                time.sleep(0.03)
        raise RuntimeError('server did not become ready')

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        try:
            cls.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            cls.process.kill()
            cls.process.wait()
            raise
        cls.stderr_file.close()
        errors = cls.logfile.read_text()
        cls.temp.cleanup()
        if errors:
            raise AssertionError('Unexpected server errors:\n' + errors)

    def request(self, path, data=None, content_type=None):
        req = Request(f'http://127.0.0.1:{self.http}{path}', data=data,
                      headers={'Content-Type': content_type or 'application/x-www-form-urlencoded'} if data is not None else {})
        try:
            response = self.opener.open(req, timeout=3)
        except HTTPError as exc:
            response = exc
        with response:
            return response.code, response.read()

    def test_discovery_and_scope(self):
        code, home = self.request('/')
        self.assertEqual(code, 200)
        self.assertIn(b'OUT OF SCOPE', home)
        self.assertIn(b'/maintenance/notes.txt', self.request('/robots.txt')[1])
        self.assertIn(self.flags['discovery'].encode(), self.request('/maintenance/notes.txt')[1])

    def test_sqli_and_bad_login(self):
        self.assertEqual(self.request('/login', urlencode({'username':'admin', 'password':'wrong'}).encode())[0], 403)
        code, body = self.request('/login', urlencode({'username':"' OR 1=1-- ", 'password':'x'}).encode())
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)['flag'], self.flags['sqli'])
        self.assertEqual(self.request('/login', urlencode({'username':"'", 'password':'x'}).encode())[0], 400)

    def test_idor_and_no_filesystem_traversal(self):
        self.assertEqual(self.request('/api/record?id=1')[0], 200)
        self.assertEqual(json.loads(self.request('/api/record?id=42')[1])['flag'], self.flags['idor'])
        self.assertEqual(self.request('/api/record?id=../etc/passwd')[0], 400)
        self.assertEqual(self.request('/../../etc/passwd')[0], 404)

    def test_submission_and_body_bounds(self):
        for name, flag in self.flags.items():
            code, body = self.request('/submit', json.dumps({'flag': flag}).encode(), 'application/json')
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body)['challenge'], name)
        self.assertEqual(self.request('/submit', b'flag=incorrect')[0], 400)
        self.assertEqual(self.request('/submit', b'{}', 'application/json')[0], 400)
        self.assertEqual(self.request('/submit', b'[]', 'application/json')[0], 400)
        self.assertEqual(self.request('/submit', b'not-json', 'application/json')[0], 400)
        self.assertEqual(self.request('/submit', json.dumps({'flag':'\u2603'}).encode(), 'application/json')[0], 400)
        self.assertEqual(self.request('/submit', b'x' * 5000)[0], 413)

    def test_dns_udp_tcp(self):
        query = dns_query('vault.ctf.lan')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(query, ('127.0.0.1', self.dns))
            udp = sock.recv(4096)
        with socket.create_connection(('127.0.0.1', self.dns), timeout=3) as sock:
            sock.sendall(struct.pack('!H', len(query)) + query)
            size = struct.unpack('!H', arena.read_exact(sock, 2))[0]
            tcp = arena.read_exact(sock, size)
        self.assertEqual(udp, tcp)
        self.assertIn(self.flags['dns'].encode(), udp)

    def test_encoding_tcp(self):
        with socket.create_connection(('127.0.0.1', self.tcp), timeout=3) as sock:
            body = bytearray()
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                body.extend(data)
        decoded = codecs.decode(body.decode().splitlines()[1], 'rot_13')
        self.assertEqual(decoded, self.flags['encoding'])

    def test_malformed_post_unicode_and_sql_limits(self):
        self.assertEqual(self.request('/submit', b'{"flag":"\\ud800"}', 'application/json')[0], 400)
        self.assertEqual(self.request('/login', b'{"username":"\\ud800","password":"x"}', 'application/json')[0], 400)
        payload = "' OR length(randomblob(1000000))>0-- "
        self.assertEqual(self.request('/login', urlencode({'username':payload, 'password':'x'}).encode())[0], 400)

    def test_http_exhaustion_does_not_starve_dns(self):
        sockets = []
        try:
            for _ in range(16):
                sock = socket.create_connection(('127.0.0.1', self.http), timeout=2)
                sock.sendall(b'GET / HTTP/1.0\r\nX-Incomplete: ')
                sockets.append(sock)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(dns_query('vault.ctf.lan'), ('127.0.0.1', self.dns))
                self.assertIn(self.flags['dns'].encode(), sock.recv(4096))
        finally:
            for sock in sockets:
                sock.close()

    def test_absolute_connection_deadline(self):
        with socket.create_connection(('127.0.0.1', self.http), timeout=2) as sock:
            sock.sendall(b'GET / HTTP/1.0\r\nX-Incomplete: ')
            started = time.monotonic()
            for _ in range(6):
                time.sleep(2)
                try:
                    sock.sendall(b'x')
                except OSError:
                    break
            sock.settimeout(1)
            self.assertEqual(sock.recv(4096), b'')
            self.assertLess(time.monotonic() - started, 14)

    def test_generation_refuses_overwrite(self):
        process = subprocess.run([sys.executable, str(BASE / 'arena.py'), '--flags', str(self.flagfile), '--generate'],
                                 capture_output=True)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(json.loads(self.flagfile.read_text()), self.flags)


class InstallerMocks(unittest.TestCase):
    def test_snapshot_uses_uuid_specific_properties(self):
        def output(*args):
            table = {
                ('nmcli','-g','UUID','connection','show'): 'u1\nu2',
                ('nmcli','-g','connection.type','connection','show','u1'): '802-3-ethernet',
                ('nmcli','-g','connection.type','connection','show','u2'): '802-11-wireless',
                ('nmcli','-g','connection.autoconnect','connection','show','u1'): 'yes',
                ('nmcli','-g','GENERAL.CON-UUID','device','show','eth0'): 'u1',
                ('nmcli','radio','wifi'): 'enabled',
                ('sysctl','-n','net.ipv4.ip_forward'): '0',
                ('sysctl','-n','net.ipv6.conf.all.forwarding'): '0',
            }
            return table[args]
        with patch.object(setup, 'output', side_effect=output), patch.object(setup, 'active', return_value=False), patch.object(setup, 'enabled', return_value=False):
            state = setup.snapshot()
        self.assertEqual(state['ethernet_connections'], [{'uuid':'u1', 'autoconnect':'yes'}])
        self.assertEqual(state['active_eth_uuid'], 'u1')

    def test_firewall_transaction_not_global_flush(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'firewall.nft').write_text(setup.FIREWALL)
            calls = []
            def run(*args, **kwargs):
                calls.append((args, kwargs))
                return 'table inet ctf_lab {}' if args[:3] == ('nft','list','table') else 0
            with patch.object(setup, 'ROOT', root), patch.object(setup, 'run', side_effect=run):
                setup.firewall()
            transaction = calls[-1][1]['input']
            self.assertTrue(transaction.startswith('delete table inet ctf_lab\n'))
            self.assertNotIn('flush ruleset', transaction)
            self.assertIn('policy drop', transaction)
            self.assertIn('iifname != "eth0" drop', transaction)
            self.assertIn('meta nfproto ipv6 drop', transaction)

    def test_apply_firewall_precedes_network_and_arena(self):
        calls = []
        state = {'ethernet_connections':[{'uuid':'old','autoconnect':'yes'}], 'lab_uuid':'new'}
        with tempfile.TemporaryDirectory() as temporary, patch.object(setup, 'ROOT', Path(temporary)), patch.object(setup, 'save_state'), patch.object(setup, 'load_state', return_value=state), patch.object(setup, 'firewall', side_effect=lambda: calls.append(('firewall',))), patch.object(setup, 'run', side_effect=lambda *a, **kw: calls.append(a)):
            setup.apply()
        self.assertLess(calls.index(('firewall',)), calls.index(('nmcli','connection','up','new')))
        self.assertLess(calls.index(('nmcli','radio','wifi','off')), calls.index(('systemctl','enable','--now','ctf-lab.service')))

    def test_stop_failure_preserves_isolation(self):
        class Args:
            restore_network = True
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            if args[:2] == ('systemctl', 'stop'):
                raise subprocess.CalledProcessError(1, args)
            return 0
        with patch.object(setup, 'load_state', return_value={}), patch.object(setup, 'output', return_value='loaded'), patch.object(setup, 'run', side_effect=run):
            with self.assertRaises(subprocess.CalledProcessError):
                setup.uninstall(Args())
        self.assertTrue(all(args[0] == 'systemctl' for args in calls))

    def test_atomic_state_failure_preserves_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'state.json'
            setup.write(path, '{"original":true}', 0o600)
            with patch.object(setup.os, 'replace', side_effect=OSError('simulated disk failure')):
                with self.assertRaises(OSError):
                    setup.write(path, '{"replacement":true}', 0o600)
            self.assertEqual(path.read_text(), '{"original":true}')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(temporary).iterdir()), [path])

    def test_failed_flag_generation_keeps_old_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            flags = data / 'flags.json'
            flags.write_text('original flags')
            with patch.object(setup, 'DATA', data), patch.object(setup, 'load_state'), patch.object(setup, 'stop_checked') as stop, patch.object(setup, 'run', side_effect=subprocess.CalledProcessError(1, ['python3'])):
                with self.assertRaises(subprocess.CalledProcessError):
                    setup.rotate()
            self.assertEqual(flags.read_text(), 'original flags')
            stop.assert_not_called()

    def test_persistent_cutover_and_ready_unit(self):
        self.assertIn('ConditionPathExists=/etc/ctf-lab/pending', setup.CUTOVER_UNIT)
        self.assertIn('WantedBy=multi-user.target', setup.CUTOVER_UNIT)
        self.assertIn('Restart=on-failure', setup.CUTOVER_UNIT)
        self.assertIn('StartLimitIntervalSec=0', setup.CUTOVER_UNIT)
        self.assertIn('Type=notify', setup.APP_UNIT)
        self.assertIn('StartLimitIntervalSec=0', setup.APP_UNIT)
        self.assertIn('NetworkManager-wait-online.service', setup.APP_UNIT)

    def test_malformed_url_returns_400(self):
        class Probe:
            path = '//[invalid'
            def send_body(self, code, body):
                self.code = code
        probe = Probe()
        self.assertIsNone(arena.Web.route(probe))
        self.assertEqual(probe.code, 400)

    def test_mocked_install_records_intent_and_enables_before_marker(self):
        class Args:
            isolated = True
            allow_ssh_disconnect = True
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, app, data = base / 'etc', base / 'app', base / 'data'
            units = base / 'units'
            units.mkdir()
            state = {'phase':'prepared', 'created_user':False, 'lab_uuid':None}
            events = []
            def run(*args, **kwargs):
                events.append(args)
                if args[0] == 'getent':
                    return ''
                if args[0] == 'useradd':
                    self.assertTrue(json.loads((root / 'state.json').read_text())['created_user'])
                if args[:3] == ('systemctl','enable','ctf-lab-cutover.service'):
                    self.assertFalse((root / 'pending').exists())
                if args[:3] == ('systemctl','start','ctf-lab-cutover.service'):
                    self.assertTrue((root / 'pending').exists())
                return 0
            def output(*args):
                if args[:3] == ('nmcli','-g','connection.uuid'):
                    return 'new-uuid'
                return ''
            with patch.multiple(setup, ROOT=root, APP=app, DATA=data, STATE=root/'state.json', SELF=base/'installed-helper', UNITS=units, SYSCTL_FILE=base/'sysctl.conf'), patch.object(setup, 'require_pi'), patch.object(setup, 'snapshot', return_value=state), patch.object(setup, 'run', side_effect=run), patch.object(setup, 'output', side_effect=output), patch.object(setup, 'active', return_value=False), patch.object(setup.shutil, 'which', return_value='/mock/binary'):
                setup.install(Args())
            self.assertEqual(json.loads((root / 'state.json').read_text())['phase'], 'pending')
            self.assertTrue((units / 'ctf-lab-cutover.service').is_file())
            self.assertTrue((app / 'arena.py').is_file())

    def test_required_confirmations(self):
        class Args:
            isolated = False
            allow_ssh_disconnect = False
            restore_network = False
        with patch.object(setup, 'require_pi'):
            with self.assertRaisesRegex(RuntimeError, '--isolated'):
                setup.install(Args())
        with self.assertRaisesRegex(RuntimeError, '--restore-network'):
            setup.uninstall(Args())


if __name__ == '__main__':
    unittest.main(verbosity=2)
