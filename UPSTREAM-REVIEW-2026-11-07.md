# GT-BE98: upstream review and dav29 backports — 07.11.2026

Local base: dav28, 8e3ad4d1181da748dcfdae6e4a2334300ebbf444.
Sources: Gnuton beta2 eb46d8b17f164178956a03763ca054010dcc11a1;
Merlin main d6eb778d021f0dcd5656ed3c7f0a91d5d86030e2;
AM-Reaper Dev-102.8 7477e52f086bcb17a124aa2e54c4938b9b93b2df.

## Gnuton beta2 and conservative boot choice

There are six commits after beta1, all for adding RT-BE82M (BCM6766):
target/configuration, MXL switch kernel prebuilt and ioctl layout,
libhostapi, ethswbox, switch firmware and the merge. Shared build rules
add RT-BE82M cases. They do not change the GT-BE98 boot path.

The entire router-sysdep.gt-be98 tree is unchanged, SHA
637b0a14763fb396bd26f811e3b885a46a1d7d42. The GT-BE98 dongle firmware tree
is unchanged, SHA 8b413c876332367aca33974598fc1032360a7437.
At the user's request the working local bootloader is preserved.
No bootloader, PHY boot object, ATF, DDR or image-layout change was applied.

## Recheck of the actual dav28 images

Downloaded default, ROG and slim from run 42222123066, plus Gnuton GT-BE98
default from run 42120269638. All four image MD5 files match.
Parsed both layers of FIT/FDT: the outer NAND/BCM6813/DDR4/squashfs bundle
has bootfs and rootfs; bootfs includes ATF, U-Boot, kernel and DTBs.
Verified both outer SHA-256 payload hashes and all 62 inner image hashes
in each of the four images. The GT-BE98 DTB and U-Boot DTB are identical
between our three images and Gnuton.

All 14 selected ready-to-load modules are byte-identical between default,
ROG, slim AND Gnuton: wl, dhd, bcm_enet, bcm_mpm, bdmf, emf, hnd, igs,
pktrunner, rdpa, rdpa_gpl, rdpa_usr, wfd and rtl8372. Every module reports
4.19.294 SMP preempt mod_unload aarch64. None of the six replaced driver
objects removed a previous global export.

Both installed radio firmwares match our checked-in files. BCM6726 is
identical to Gnuton (19.10.2026). BCM6717 intentionally stays newer than
Gnuton: ours 08.05.2026, his 09.10.2025; same driver branch/r839077,
ours microcode 1892.42726 versus 1892.42713. The runtime check on the actual
router is separate; no flashing, reboot or factory reset was performed.

## Backports selected for dav29

Firmware changes are limited to the reviewed fixes below. Native source
and build checks do not establish that every upstream CVE label or exploit
claim is independently verified.

* Merlin 63127814d9ea
* Merlin ac8c874f1805
* Merlin ba476c59af13
* Merlin cd17e2a2cc4a
* Merlin e26fc8f4d78c
* Merlin e52153f4ade2
* Merlin f3118f48d11d
* Merlin OpenVPN 2.7.9
* Reaper 0894
* Reaper 0898
* Reaper 0908
* Reaper 0917
* Reaper 0922
* Reaper 0931
* Reaper 0935
* Reaper 0939
* Reaper 0943
* Reaper 0944
* Reaper 0945
* Reaper 0948
* Reaper 0951
* Reaper 0963
* Merlin 262f2042128d (CLI return path adapted)
* Merlin 3b6e83e0e33e (102.8 guards adapted)

Merlin: OpenVPN 2.7.9, emSign CA distrust, idle HTTPS select handling,
Parental Controls JSON cleanup, DNS TCP for SDN, wanduck close-on-exec,
UDP timeout restoration, IP-options RCU lifetime and both VPN Director
rule-rebuild fixes. The latter are adapted to our older 102.8 feature
conditions; the existing WireGuard bypass helper is retained.

Reaper: bounded product-icon copy; strict MAC validator plus separator
follow-up; Guest Network Pro/OpenVPN DNS plus the CAP_NET_RAW follow-up;
selected SCSI/file-lock/IGMP/TCP-timewait/IPv6-reject fixes; port-trigger
locking plus rule-lifetime follow-up; executable hardening; SMB log setting;
udhcpc length check; WireGuard response and timestamp races; hostapd MLO
parser checks; selected dnsmasq/wget/iperf3/minidlna/libevent/rp-l2tp/avahi
fixes; fw-classifier and HFSC fixes. Kernel structure/header layouts used
by closed modules are not changed by this selected kernel set.

Two errors in the imported wget patch were corrected during review:
* html_quote_string() removed the loop's increment but still counted only
  the entity suffix. ASan reproduced heap-buffer-overflow on a single '&'.
  Counts now include the leading '&' as well as the suffix and final NUL.
* parse_content_range() now uses strtoll, not strtol: wgint is int64_t,
  while our ARM userspace has a 32-bit long. Valid ranges above 2 GiB
  remain accepted and overflowing input is rejected.
The MAC validator additionally handles NULL and casts input to unsigned
char before ctype calls.

## Exclusions

The 221-file / 279-fix kernel bundle 0949, wholesale protocol/Kconfig
removals, broad Broadcom capability-policy changes, USB controller tuning,
Netatalk overhaul, Reaper's UI/Wallguard/AI stack and automatic conntrack
helper policy changes are outside this selected backport. Each needs
separate review. The RT-BE86U energy-detect reload fix excludes GT-BE98.
Our dynamic no-cache headers are already stricter than Merlin's new ones.

## Validation

Native ASan/UBSan tests in tools/tests/test_dav29_backports.py exercise
MAC validation, HTML quoting (including repeated entities), 64-bit HTTP
ranges/overflow and VPN rule rebuild with and without WireGuard.
The actual in-tree functions are extracted and compiled for these cases.
All 130 pre-existing modified files are preserved; bootloader and driver
prebuilts are unchanged. Full default/ROG/slim cross-build validation is
performed by GitHub Actions. Boot and runtime testing require the router;
this task does not flash it.
