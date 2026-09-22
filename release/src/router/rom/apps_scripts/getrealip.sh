#!/bin/sh
# use STUN to find the external IP.

servers="default stun.l.google.com:19302 stun.cloudflare.com:3478 stun1.l.google.com:19302 stun2.l.google.com:19302 stun3.l.google.com:19302 stun4.l.google.com:19302"
prefixes="wan0_ wan1_"

which ministun >/dev/null || exit 1

# GT-BE98 NAT loopback (vts_hairpin, auto mode): the firewall's loopback rule
# embeds the public IP, so rebuild it when the detected address changes.
# A failed probe (empty result) never triggers a rebuild, so a flaky STUN
# server can't make the rules flap.
natloop_changed=0
natloop_check() {
	[ "$(nvram get vts_hairpin)" = "1" ] || return 0
	[ "$(nvram get vts_hairpin_mode)" = "static" ] && return 0
	[ -n "$2" ] && [ "$1" != "$2" ] && natloop_changed=1
	return 0
}

if [ "$(nvram get wans_mode)" = "lb" ] ; then
	primary="0"
	for prefix in $prefixes; do
		state=$(nvram get ${prefix}state_t)
		sbstate=$(nvram get ${prefix}sbstate_t)
		auxstate=$(nvram get ${prefix}auxstate_t)

		# is_wan_connect()
		[ "$state" = "2" ] || continue
		[ "$sbstate" = "0" ] || continue
		[ "$auxstate" = "0" -o "$auxstate" = "2" ] || continue

		# get_wan_ifname()
		proto=$(nvram get ${prefix}proto)
		if [ "$proto" = "pppoe" -o "$proto" = "pptp" -o "$proto" = "l2tp" ] ; then
			ifname=$(nvram get ${prefix}pppoe_ifname)
		else
			ifname=$(nvram get ${prefix}ifname)
		fi

		for server in $servers; do
			[ "$server" = "default" ] && server=
			result=$(ministun -t 1000 -c 1 -i $ifname $server 2>/dev/null)
			[ $? -eq 0 ] && break
			result=
		done
		[ -z "$result" ] && state=1 || state=2
		natloop_check "$(nvram get ${prefix}realip_ip)" "$result"
		nvram set ${prefix}realip_state=$state
		nvram set ${prefix}realip_ip=$result

		wan=`echo $prefix|sed -e "s,_,,"`
		[ -z "$result" ] && echo "$wan failed." || echo "$wan external IP is $result"
	done
else
	for prefix in $prefixes; do
		primary=$(nvram get ${prefix}primary)
		[ "$primary" = "1" ] && break
	done

	[ "$primary" = "1" ] || exit 1

	# get_wan_ifname()
	proto=$(nvram get ${prefix}proto)
	if [ "$proto" = "pppoe" -o "$proto" = "pptp" -o "$proto" = "l2tp" ] ; then
		ifname=$(nvram get ${prefix}pppoe_ifname)
	else
		ifname=$(nvram get ${prefix}ifname)
	fi

	for server in $servers; do
		[ "$server" = "default" ] && server=
		result=$(ministun -t 1000 -c 1 -i $ifname $server 2>/dev/null)
		[ $? -eq 0 ] && break
		result=
	done
	[ -z "$result" ] && state=1 || state=2
	natloop_check "$(nvram get ${prefix}realip_ip)" "$result"
	nvram set ${prefix}realip_state=$state
	nvram set ${prefix}realip_ip=$result

	[ -z "$result" ] && echo "Failed." || echo "External IP is $result"
fi

[ "$natloop_changed" = "1" ] && service restart_firewall >/dev/null 2>&1
exit 0
