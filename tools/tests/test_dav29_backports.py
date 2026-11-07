#!/usr/bin/env python3
"""Run native regression cases against the C functions used by these backports."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(path, signature):
    source = (ROOT / path).read_text()
    start = source.index(signature)
    end = source.index('\n}\n', start) + 3
    return source[start:end]


COMMON = '''
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
'''


def run_case(directory, name, body, defines=()):
    source = directory / (name + '.c')
    binary = directory / name
    source.write_text(COMMON + body)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-g', *defines,
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    print('PASS', name, flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix='dav29-regression-') as tmp:
        directory = Path(tmp)
        mac = function('release/src/router/shared/misc.c',
                       'int isValidMacAddress(const char* mac)')
        run_case(directory, 'mac-validation', mac + r'''
int main(void) {
    const char *valid[] = {"001122aabbCC", "00:11:22:aa:bb:cc", "00-11-22-aa-bb-cc"};
    const char *invalid[] = {"", "A\":A:BB:CC:DD:EE:FF", "AABBCCDDEEFF:payload",
                            "00:11:22:33:44", "00:11:22:33:44:55:66", "\xff"};
    assert(!isValidMacAddress(NULL));
    for (size_t i = 0; i < sizeof(valid)/sizeof(valid[0]); i++) assert(isValidMacAddress(valid[i]));
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) assert(!isValidMacAddress(invalid[i]));
    return 0;
}
''')
        quote = function('release/src/router/wget/src/convert.c',
                         'char *\nhtml_quote_string (')
        run_case(directory, 'wget-html-entities', '''
#define DEBUGP(x) ((void)0)
#define INT_ADD_OK(a,b,r) (!__builtin_add_overflow((a),(b),(r)))
#define xmalloc malloc
''' + quote + r'''
int main(void) {
    const char *in[] = {"", "abc", "&", "<", ">", "\"", " ", "a&< >\"z"};
    const char *out[] = {"", "abc", "&amp;", "&lt;", "&gt;", "&quot;", "&#32;", "a&amp;&lt;&#32;&gt;&quot;z"};
    for (size_t i = 0; i < sizeof(in)/sizeof(in[0]); i++) {
        char *s = html_quote_string(in[i]); assert(s); assert(!strcmp(s, out[i])); free(s);
    }
    char input[1025]; memset(input, '&', 1024); input[1024] = 0;
    char *s = html_quote_string(input); assert(strlen(s) == 5120);
    for (size_t i = 0; i < 5120; i += 5) assert(!memcmp(s+i, "&amp;", 5));
    free(s); return 0;
}
''')
        ranges = function('release/src/router/wget/src/http.c',
                          'static bool\nparse_content_range (')
        run_case(directory, 'wget-http-ranges', '''
typedef int64_t wgint;
#define c_isdigit(c) ((c) >= '0' && (c) <= '9')
#define c_isspace(c) ((c) == ' ' || ((c) >= '\\t' && (c) <= '\\r'))
''' + ranges + r'''
int main(void) {
    wgint first, last, total;
    assert(parse_content_range("bytes 0-99/100", &first, &last, &total));
    assert(first == 0 && last == 99 && total == 100);
    assert(parse_content_range("bytes 3000000000-3999999999/5000000000", &first, &last, &total));
    assert(first == INT64_C(3000000000) && last == INT64_C(3999999999) && total == INT64_C(5000000000));
    assert(parse_content_range("bytes 0-9/*", &first, &last, &total) && total == -1);
    assert(!parse_content_range("bytes 9223372036854775808-9223372036854775809/*", &first, &last, &total));
    assert(!parse_content_range("bytes 10-9/100", &first, &last, &total));
    assert(!parse_content_range("bytes 0-99/99", &first, &last, &total));
    return 0;
}
''')
        routes = function('release/src/router/libovpn/amvpn_routing.c',
                          'void amvpn_set_all_routing_rules(void)')
        harness = '''
#define WG_CLIENT_MAX 3
#define OVPN_CLIENT_MAX 2
#define VPNDIR_PROTO_WIREGUARD 1
#define VPNDIR_PROTO_OPENVPN 2
static int events[20], count;
static void amvpn_set_kilswitch_rules_all(void) { events[count++] = 10; }
static void amvpn_set_wan_routing_rules(void) { events[count++] = 20; }
#ifdef RTCONFIG_WIREGUARD
static void amvpn_refresh_wg_bypass_rules(void) { events[count++] = 30; }
#endif
static void amvpn_set_routing_rules(int unit, int proto) { events[count++] = proto*100 + unit; }
''' + routes + '''
int main(void) {
#ifdef RTCONFIG_WIREGUARD
    int expected[] = {10,20,103,102,101,30,202,201};
#else
    int expected[] = {10,20,202,201};
#endif
    amvpn_set_all_routing_rules();
    assert(count == (int)(sizeof(expected)/sizeof(expected[0])));
    assert(!memcmp(events, expected, sizeof(expected))); return 0;
}
'''
        run_case(directory, 'vpn-routing-with-wireguard', harness,
                 ['-DRTCONFIG_WIREGUARD', '-DRTCONFIG_HND_ROUTER_BE_4916'])
        run_case(directory, 'vpn-routing-openvpn-only', harness)


if __name__ == '__main__':
    main()
