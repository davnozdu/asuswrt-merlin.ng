/*
 * snmpd.c
 *
 * Copyright (C) 2007 Sebastian Gottschall <gottschall@dd-wrt.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * $Id:
 */

#include <rc.h>
#include <stdlib.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <syslog.h>
//#include <signal.h>
//#include <errno.h>
//#include <sys/stat.h>

/* Strip CR/LF and other control characters from an nvram value before it is
 * written into /tmp/snmpd.conf. A raw newline would let an attacker-set value
 * (community strings, sysName/Location/Contact, SNMPv3 user/passwords) start a
 * fresh net-snmp directive line such as extend/exec/pass -> shell RCE on poll
 * (C4), or inject extra createUser/rwuser lines (H9). Copies src into dst
 * (capacity dsize), dropping any byte < 0x20 or == 0x7f; always NUL-terminates. */
static void snmp_sanitize(char *dst, size_t dsize, const char *src)
{
	size_t j = 0;

	if (dsize == 0)
		return;
	for (; src && *src && j + 1 < dsize; src++) {
		unsigned char c = (unsigned char)*src;
		if (c < 0x20 || c == 0x7f)
			continue;	/* drop CR/LF/TAB and other control chars */
		dst[j++] = (char)c;
	}
	dst[j] = '\0';
}

void start_snmpd(void)
{
	int ret = 0;
	FILE *fp;
	char user[35], authType[5], privType[5], authPwd[256], privPwd[256];
	char cval[256];

	if (!nvram_match("snmpd_enable", "1")) {
		return;
	}

	// Create config file
	fp = fopen("/tmp/snmpd.conf", "w");
	if (fp == NULL) {
		cprintf("Can't open /tmp/snmpd.conf!\n");
		return;
	}

	memset(user, 0x0, 35);
	memset(authType, 0x0, 5);
	memset(privType, 0x0, 5);
	memset(authPwd, 0x0, 256);
	memset(privPwd, 0x0, 256);
	snmp_sanitize(user, sizeof(user), nvram_safe_get("http_username"));
	snmp_sanitize(authType, sizeof(authType), nvram_safe_get("v3_auth_type"));
	snmp_sanitize(authPwd, sizeof(authPwd), nvram_safe_get("v3_auth_passwd"));
	snmp_sanitize(privType, sizeof(privType), nvram_safe_get("v3_priv_type"));
	snmp_sanitize(privPwd, sizeof(privPwd), nvram_safe_get("v3_priv_passwd"));

	cprintf("write config for snmpd!\n");

	fprintf(fp, "agentAddress  udp:161\n");

	if(!strcmp(authType, "MD5") || !strcmp(authType, "SHA")) {	
		if(!strcmp(privType, "DES") || !strcmp(privType, "AES")) {
			fprintf(fp, "createUser %s %s %s %s %s\n", user, authType, authPwd, privType, privPwd);
			fprintf(fp, "rwuser %s priv\n", user);
		}
		else if(!strcmp(privType, "NONE")) {
			fprintf(fp, "createUser %s %s %s\n", user, authType, authPwd);
			fprintf(fp, "rwuser %s auth\n", user);
		}
		else
			cprintf("Wrong SNMPv3 Privacy Type!!\n");	
	}
	else if(!strcmp(authType, "NONE"))
	{
		fprintf(fp, "createUser %s\n", user);
		fprintf(fp, "rwuser %s noauth\n", user);
	}
	else
		cprintf("Wrong SNMPv3 Authentication type!!\n");

	if(strlen(nvram_safe_get("roCommunity"))) {
		snmp_sanitize(cval, sizeof(cval), nvram_safe_get("roCommunity"));
		if(cval[0])
			fprintf(fp, "rocommunity %s default\n", cval);
	}

	if(strlen(nvram_safe_get("rwCommunity"))) {
		snmp_sanitize(cval, sizeof(cval), nvram_safe_get("rwCommunity"));
		if(cval[0])
			fprintf(fp, "rwcommunity %s default\n", cval);
	}

#if 0
	fprintf(fp, "com2sec	defROnlyUser	default	%s\n", nvram_get("roCommunity"));
	fprintf(fp, "com2sec	defRWUser	default	%s\n", nvram_get("rwCommunity"));
	fprintf(fp, "group	ROnlyGroup	v1	defROnlyUser\n");
	fprintf(fp, "group	ROnlyGroup	v2c	defROnlyUser\n");
	fprintf(fp, "group	RWGroup	v1	defRWUser\n");
	fprintf(fp, "group	RWGroup	v2c	defRWUser\n");
	fprintf(fp, "view	all	included	.1\n");
	fprintf(fp, "access	ROnlyGroup	\"\"	any	noauth	exact	all	none	none\n");
	fprintf(fp, "access	RWGroup		\"\"	any	noauth	exact	all	all	none\n");
#endif

	if(strlen(nvram_safe_get("sysName"))) {
		snmp_sanitize(cval, sizeof(cval), nvram_safe_get("sysName"));
		if(cval[0])
			fprintf(fp, "sysName %s\n", cval);
	}

	if(strlen(nvram_safe_get("sysLocation"))) {
		snmp_sanitize(cval, sizeof(cval), nvram_safe_get("sysLocation"));
		if(cval[0])
			fprintf(fp, "sysLocation %s\n", cval);
	}

	if(strlen(nvram_safe_get("sysContact"))) {
		snmp_sanitize(cval, sizeof(cval), nvram_safe_get("sysContact"));
		if(cval[0])
			fprintf(fp, "sysContact %s\n", cval);
	}

	append_custom_config("snmpd.conf", fp);
	fclose(fp);
	use_custom_config("snmpd.conf", "/tmp/snmpd.conf");
	run_postconf("snmpd","/tmp/snmpd.conf");

	// Execute snmp daemon
	ret = eval("snmpd", "-c", "/tmp/snmpd.conf");

	_dprintf("start_snmpd: ret= %d\n", ret);

	return;
}

void stop_snmpd(void)
{
	if (getpid() != 1) {
		notify_rc("stop_snmpd");
	}

	killall_tk("snmpd");
	return;
}
