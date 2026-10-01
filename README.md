# qdss2pcap

[Русский](#русская-версия)

Script that parses iPhone sysdiagnose dumps and produces a `.pcap` with LTE/NR RRC signaling for Wireshark.

For each `sysdiagnose_*` folder it takes the modem log `logs/Baseband/*-qdss/0x*.bin` and writes `<folder>.pcap` next to it.

Tested on iPhone 16 Pro, iOS 24A435.

Requirements: Python 3.8+, standard library only, nothing to install. Optional: tshark (comes with Wireshark) for the summary table at the end; Wireshark to open the resulting pcap.

## Why this project

An iPhone never shows you what its modem is doing: which cells it camps on, why it loses service, how handovers go, what it negotiates with the network on attach or during a call. The sysdiagnose log does contain the modem trace, but as a raw QDSS binary that neither Wireshark nor any off-the-shelf tool understands.

This script closes that gap: it turns the modem log into a regular `.pcap` with LTE/NR RRC signaling that opens in Wireshark. With it you can see the actual dialogue between the phone and the base station — for example why 5G NSA won't attach, which bands the phone prefers, or how the radio module behaves in edge cases (useful, among other things, to identify the radio module vendor).

## What the capture contains

Everything the modem logged inside the ~30-second sysdump window: broadcast system information (SIB1 with cell identity, PLMN and band; SIB2–SIB7 with radio config, reselection and neighbour cells; SIB16 GPS time), paging, RRC connection setup/release/resume, security mode, capability enquiries, reconfigurations (bearer setup, measurement config, handovers), measurement reports with serving/neighbour cell levels, and all NAS exchanged with the core network — attach, tracking area updates, authentication, PDN/APN session setup and teardown, detach, CSFB service requests — plus 5G NSA traces (SCG failures, MRDC transfers, NR measurement objects and NR cells).

For reference: 25 dumps taken 24–29 Sep 2026 gave 4810 RRC messages on LTE bands 1 (2100), 3 (1800), 7 (2600), 20 (800) and 38 (TDD 2600).

One known hole: UECapabilityInformation comes back empty (see Notes).

## Capturing a sysdump yourself

Everything described here can be repeated on your own device, with caveats that in practice show why a network-side capture was needed in the first place. To do this:

1. Get and install the Apple Inc. diagnostic certificate (without it the sysdump will have no modem data), then reboot the device.

2. Take the sysdump: press and hold the power button together with volume up and volume down, there should be a characteristic vibration. Important: the captured window is 15–20 seconds before pressing the buttons and 5–10 seconds after, so right before capturing turn airplane mode on and off.

3. After 2–3 minutes the log should be ready. Get it via Settings → Privacy & Security → Analytics & Improvements → View Analytics Logs → search for "sysdump". If there is an `IN_PROGRESS_...` log, it is still being written. Export the log through any channel convenient for you.

4. Run the Python script from this repository (see below). You should get a `.pcap` file you can open in Wireshark and see what is happening on the network on your iPhone.

## Usage

```bash
python3 qdss2pcap.py [folder]                     # default: the script's own folder
python3 qdss2pcap.py [folder] -f                  # rebuild existing .pcap files
python3 qdss2pcap.py path/to/sysdiagnose_...      # a single dump
```

`--no-summary` skips the tshark summary table, `-j N` sets the number of parallel processes.

## Notes

If you open the `.pcap` and look for UECapability, the field will be empty, because the modem does not provide this information (large messages like UECapabilityInformation are logged with zero length, the body is not stored at all and cannot be recovered).

But the signaling and the exchange itself are available: signal levels, cell and radio module parameters, RRC messages, handovers, APN and VoLTE session setup, and more — useful, for example, for identifying the radio module vendor.

IMPORTANT: before sharing this file with anyone or publishing it, check and clean it — the capture contains messages where the IMSI or IMEI of the device, the CellID of the base station, and other data tying the capture to a specific person and place may be exposed.

---

## Русская версия

[English](#qdss2pcap)

Скрипт, который парсит sysdiagnose-дампы с iPhone и делает из них `.pcap` с LTE/NR RRC-сигнализацией для Wireshark.

Для каждой папки `sysdiagnose_*` берёт лог модема `logs/Baseband/*-qdss/0x*.bin` и пишет рядом `<папка>.pcap`.

Проверено на iPhone 16 Pro, iOS 24A435.

Требования: Python 3.8+, только стандартная библиотека, ничего ставить не надо. Опционально: tshark (идёт с Wireshark) для сводной таблицы в конце; Wireshark, чтобы открыть получившийся pcap.

## Зачем этот проект

iPhone никогда не показывает, что делает его модем: на каких сотах сидит, почему пропадает связь, как проходят handover'ы, о чём он договаривается с сетью при аттаче или во время звонка. В системном логе sysdiagnose трейс модема есть, но в виде сырого QDSS-бинарника, который не понимают ни Wireshark, ни другие готовые инструменты.

Этот скрипт закрывает пробел: превращает лог модема в обычный `.pcap` с LTE/NR RRC-сигнализацией, который открывается в Wireshark. С ним виден реальный диалог телефона с базовой станцией — например, почему не цепляется 5G NSA, какие бэнды предпочитает телефон, как ведёт себя радиомодуль в пограничных случаях (полезно, среди прочего, для определения вендора радиомодуля).

## Что есть в захвате

Всё, что модем записал в ~30-секундное окно sysdump: широковещательная системная информация (SIB1 с identity соты, PLMN и бэндом; SIB2–SIB7 с радиоконфигурацией, реселекцией и соседями; SIB16 с GPS-временем), пейджинг, установка/разрыв/возобновление RRC-соединения, security mode, запросы возможностей, реконфигурации (поднятие bearers, конфиг измерений, handover'ы), measurement report'ы с уровнями serving- и neighbour-сот, весь NAS-обмен с core-сетью — attach, tracking area update, аутентификация, поднятие и разрыв PDN/APN-сессий, detach, CSFB-запросы — плюс следы 5G NSA (SCG failure'ы, MRDC-передачи, NR measurement object'ы и NR-соты).

Для ориентира: 25 дампов, снятых 24–29 сентября 2026, дали 4810 RRC-сообщений на LTE-бэндах 1 (2100), 3 (1800), 7 (2600), 20 (800) и 38 (TDD 2600).

Одна известная дыра: UECapabilityInformation приходит пустым (см. Примечания).

## Как снять лог с модема самому

Всё, что описано выше, можно повторить на своём устройстве, но с оговорками, которые на практике и показывают, почему всё же потребовался захват со стороны сети. Для этого необходимо:

1. Получить и установить сертификат Apple Inc. для диагностики (без него в sysdump не будет данных модема), после чего перезагрузить устройство.

2. Снять sysdump (системный лог): зажать кнопку питания вместе с кнопками громкости вниз и вверх, должен быть характерный виброотклик. Важно: захватывается окно в 15–20 секунд до зажатия кнопок и 5–10 секунд после, то есть перед тем, как снимать системный лог, лучше включить и выключить режим полёта.

3. Через 2–3 минуты лог должен быть готов, получить его можно через Настройки → Конфиденциальность и безопасность → Аналитика и улучшения → Посмотреть журналы аналитики → в поиске ввести «sysdump». Если есть лог `IN_PROGRESS_...`, значит лог ещё записывается. Экспортируем лог через любой удобный канал связи.

4. Используем Python-скрипт из данного репозитория (см. ниже). Должны получить `.pcap` файл, который можно открыть через Wireshark и проанализировать, что происходит в сети на вашем iPhone.

## Запуск

```bash
python3 qdss2pcap.py [каталог]                # по умолчанию — каталог со скриптом
python3 qdss2pcap.py [каталог] -f             # пересоздать уже существующие .pcap
python3 qdss2pcap.py путь/к/sysdiagnose_...   # одна папка
```

`--no-summary` — не запускать tshark для сводной таблицы, `-j N` — число параллельных процессов.

## Примечания

Есть нюанс: если открыть `.pcap` и найти там UECapability, то поле окажется пустым, потому что модем не отдаёт эту информацию (крупные сообщения вроде UECapabilityInformation пишутся с нулевой длиной, тела в логе нет вообще, восстановить его нельзя).

Но доступна сигнализация и процесс обмена: уровни сигнала, параметры сектора и радиомодуля, RRC-сообщения, handover'ы, поднятия сессий APN и VoLTE и множество других фишек, которые могут пригодиться, например, для определения вендора радиомодуля.

ВАЖНО! Прежде чем делиться этим файлом с кем-либо либо публиковать его, проверьте и вычистите его, так как в захвате встречаются сообщения, в которых может быть открыт IMSI или IMEI устройства, CellID базовой станции и другие данные, которые привязывают захват к конкретному человеку и месту.
