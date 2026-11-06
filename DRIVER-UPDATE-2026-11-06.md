# GT-BE98: драйверы GPL 102_40585 и зависимости — 06.11.2026

Источник: gnuton/asuswrt-merlin.ng, фиксированный commit
`73f9d14c84992e81a33030291b2de0361e83d5d8`.
Последняя проверенная сборка: https://github.com/gnuton/asuswrt-merlin.ng/actions/runs/42120269638
Импорт GPL: https://github.com/gnuton/asuswrt-merlin.ng/commit/eeb776b0859e62f53399f4b755719d0af78060de
База локального дерева: `ceff7311ac` (dav27).

## SDK и состав переноса

Базовый SDK тот же: BB0B / bcm963xx_5.04L.04p3;
`sdk_version`, `version.make`, `sdk_profile.mak`, `make.wlan` совпадают побайтово.
Номер Wi-Fi тот же: 17.10.369.39012 (r839077), но сборки отличаются.
Перенесены модельные wl.o, dhd.o, bcm_enet.o, rdpa.o, rtl8372.o, wfd.o;
прошивка BCM6726 от 19.10.2026; acsd2, acs_cli2, eapd, wlconf,
debug_monitor, libwlcsm.so; четыре исправленных скрипта WLAN.

BCM6717 сохранён от 08.05.2026: у источника версия от 09.10.2025.
Сохранён более новый wlc_types.h (r834507 против r831530).
Общая утилита wl не менялась в импорте GPL 40585 и не заменялась.
Неизменившиеся драйверные объекты повторно не копировались.

## Разрешённые зависимости

* wl.o / dhd.o: новый импорт kstrtoull уже экспортируется ядром
  (kernel/linux-4.19/lib/kstrtox.c, EXPORT_SYMBOL).
* eapd: _wlcsm_init и g_WLCSM_IS_DAEMON экспортируются переносимой libwlcsm.so.
* wlconf: nvram_get_int реализован в shared/misc.c; бинарник зависит от libshared.so.
* libwlcsm.so: новый usleep@GLIBC_2.4 использует существующую libc.
* Новая libnvram.so требует check_allow_nvram_caller. Реальная реализация
  поставляется новым shared/prebuild/GT-BE98/spwenc.o; перенесена без заглушек.
* Вместе со spwenc.o перенесён libwebapi/prebuild/GT-BE98/priv_webapi.o:
  оба используют новую таблицу ASUS_PP_t. В shared.h только для GTBE98
  добавлены force_sign и ASUS_PP_LICENSE_UPDATE_V5. ARM32 размер записи —
  16 байт, 9 записей; у остальных моделей сохранены 12 байт и 8 записей.
* init_asus_pp_eula() вызывается в init_nvram2() после detect_vul_scan(),
  как у Gnuton/ASUS. Это исправляет причину прежнего зависания QIS при
  неполном переносе новых policy-библиотек. Код интерфейса QIS не менялся.
* Новые импорты spwenc.o — функции libc и существующие _eval / isValid_digit_string.
* priv_webapi.o: is_valid_domainname предоставляется libshared;
  is_valid_netbios_name перенесён из shared/misc.c Gnuton в libshared
  только для GTBE98. Старая локальная копия в write_smb_conf.c является
  частью отдельного исполняемого файла и не экспортируется libdisk.so.
  Новый ookla_eos_support предоставляется перенесёнными ookla_utils.c /
  ookla_common.h. Объект включён для GT-BE98 независимо от OOKLA, поскольку
  новый priv_webapi.o импортирует символ безусловно. В helper включён его
  собственный заголовок вместо общего shared.h, чтобы не распространять
  новые Ookla enum на старые httpd/rc с их собственными определениями.
* Новые spwenc.o и priv_webapi.o сохраняют все прежние глобальные экспорты.

## Выполненные проверки и ограничения

Проверены хеши 17 файлов первого переноса, ELF-импорты/экспорты, наличие
провайдеров новых символов в исходниках, Makefile и библиотеках.
ARM32 ABI таблицы проверен компиляцией clang --target=armv7-linux-gnueabi
для GTBE98 и другой модели. Нативный тест Ookla проверяет профиль AXHND_A7,
EOS=0 и tcp_discard=0 с OOKLA включённым и выключенным.
Синтаксис четырёх WLAN-скриптов проверен bash -n; git diff --check пройден.
Все 130 ранее изменённых файлов сохранены побайтово.

Это статическая проверка зависимостей, не полная линковка прошивки.
Полная сборка GT-BE98 (default/rog/ctrld) выполняется в GitHub Actions.
Загрузка на устройстве, upgrade и factory reset не выполнялись. Успех сборки Gnuton подтверждает его дерево, но не нашу комбинацию
патчей. Проверка свежего NVRAM особенно нужна из-за смены policy ABI.
Прошивка роутера не выполнялась.

## SHA-256 перенесённых бинарников и скриптов

* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/hnd_extra/prebuilt/wl.o`
  `1ecdb7817945f4c3d59e3ba3b6d454f421c7516c348c2a3754b5c3bcfb794570`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/hnd_extra/prebuilt/dhd.o`
  `1534c6968333526a009f795fdd8880ed5516b73e762a6acdd1d33666487b1251`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/hnd_extra/prebuilt/bcm_enet.o`
  `c9e5ad9b2ed1fcae7f037b97649dece1598f66f06e90e73da22883def8f1745d`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/hnd_extra/prebuilt/rdpa.o`
  `51c6a0f029e6246e22b26e9d3f80d27404675e5635606a41c3f6a45b126691b8`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/hnd_extra/prebuilt/rtl8372.o`
  `3e1948756cec3f05e217c637dc9debe7a9addfc93749feb3653fb9a3006e38f7`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/hnd_extra/prebuilt/wfd.o`
  `0df859d82240390a632dd9ee2823981c2860fd7db466e9c2f09fd88b7d368884`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/dhd_monitor/prebuilt/debug_monitor`
  `618e87556480fb227a6029ff18a0373543407dd40fd4bef2416cee2ae6861266`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/eapd/linux/prebuilt/eapd`
  `e205a3636c9e560c851458b60e35ebf450b6ebb206c0791b090e7c3998d6ba0f`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/wlconf/prebuilt/wlconf`
  `85e888e75a1b010a9afcbc6e3d913a8f4e28636bc479cfdf3b97a8396d8a8860`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/wlcsm/prebuilt/libwlcsm.so`
  `f028d8244980496009825dc2af137e96e833129cc206d4498286d09bfa61b743`
* `release/src-rt-5.04behnd.4916/bcmdrivers/broadcom/net/wl/impl103/main/components/apps/acsdv2/prebuilt/GT-BE98/acsd2`
  `d0b1c1effa28a5f1a96a126e3e445a62f25b935c79d5823ee86d709961d9f527`
* `release/src-rt-5.04behnd.4916/bcmdrivers/broadcom/net/wl/impl103/main/components/apps/acsdv2/prebuilt/GT-BE98/acs_cli2`
  `3358f2711b2fad5976214be95edad9f020ff92411de316130be9c703930bf153`
* `release/src-rt-5.04behnd.4916/bcmdrivers/broadcom/net/wl/impl103/sys/src/dongle/sysdeps/GT-BE98/6726b0/rtecdc.bin`
  `f2c7483881f6a67012cbce3e31642a126e60efce59d0f8a5032dc0fb3b58b248`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/wlan/scripts/bcm-wlan-drivers.sh`
  `109a188bf2eb4e51c7cd191342448e28f4c0a78b57bbb294cfd76b8d08f8a102`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/wlan/scripts/hndnvram.sh`
  `41ff33d8b7f0157cb5e4ad966d3e3b6ccd23698f7cc7b5395888e51ae684c89a`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/wlan/scripts/wifi.sh`
  `c2895daac1d176642e649dce77e9b7580a6186aa7bc542a5424abf60652f866c`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/wlan/scripts/wlinc.sh`
  `87ebc75cf3c751df28e1c79cb9259766e84b195e214fece060ef8e7294215e8d`
* `release/src/router/shared/prebuild/GT-BE98/spwenc.o`
  `0ed70f2f86ee96f888cb5e0194077ce104eadb67bbc380ff253dcffd168a7f20`
* `release/src/router/libwebapi/prebuild/GT-BE98/priv_webapi.o`
  `fb71caebbb661262f8f91db12fb42dfe5248e7037792a4053e627e751657b2d6`
* `release/src-rt-5.04behnd.4916/router-sysdep.gt-be98/wlan/nvram/prebuilt/libnvram.so`
  `0309f85bdd72c4b26522ccbf274438ebe1de77d7e5c991dc6a4e3b127747a171`
