#!/usr/bin/env python3
"""
qdss2pcap.py - iPhone (Qualcomm-модем) sysdiagnose -> pcap с LTE RRC для Wireshark.

Для каждой папки sysdiagnose_* в указанном каталоге берёт лог модема
logs/Baseband/*-qdss/0x*.bin, разбирает его и пишет <папка>.pcap рядом с ней.

Формат лога (восстановлен реверсом, проверен на iPhone 16 Pro / Mav24, iOS 24A435):
  1. ARM CoreSight TPIU: кадры по 16 байт, полезный поток - самый большой ATID (обычно 0x32).
  2. Блоки по 16 байт: tag(1) b1(1) len(2) + 12 байт данных.
     tag & 0x1f: 0x13 - начало сообщения, 0x03 - продолжение, 0x02 - конец/заполнитель.
     tag >> 5  : номер потока (0..7), сообщения разных потоков перемежаются.
     b1 & 0x40 : перед данными ещё 4 байта (всего 8 вместо 4).
     Выравнивание блоков своё в каждом .bin, поэтому файлы разбираются по отдельности.
  3. Внутри - обычные diag log-пакеты Qualcomm (0x10 0x00 len len code ts...).
     LTE RRC OTA = 0xB0C0 (версия 0x1e), тип PDU:
       3 BCCH-DL-SCH, 7 PCCH, 8 DL-CCCH, 9 DL-DCCH, 10 UL-CCCH, 11 UL-DCCH.
  Крупные сообщения (напр. UECapabilityInformation с LTE) модем пишет с длиной 0 -
  они в pcap не попадают, но учитываются в сводке как "пустые". Тела в логе нет
  вообще (запись 26 байт), восстановить его нельзя. Пустое UL-DCCH в течение
  CAPINFO_WINDOW после UECapabilityEnquiry считается UECapabilityInformation.
  NR RRC OTA (0xB821): PCI - uint16 по смещению 7, NR-ARFCN - uint32 по смещению 17
  (0xffff / 0 - нет NR-ячейки). По ним в сводке выводятся NR-ячейки и бэнд.

Использование:
  python3 qdss2pcap.py [каталог]        # по умолчанию - каталог со скриптом
  python3 qdss2pcap.py [каталог] -f     # пересоздать уже существующие .pcap
  python3 qdss2pcap.py путь/к/sysdiagnose_...   # одна папка
"""
import argparse
import collections
import glob
import os
import re
import shutil
import struct
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor

LOG_LTE_RRC_OTA = 0xB0C0
NR_RRC_OTA = 0xB821      # NR RRC OTA (сообщения NR, в т.ч. внутри EN-DC)
NR_RRC_CFG = 0xB825      # NR RRC Configuration Info (состояние, не сообщения)
# PDU number в 0xB0C0 v30 -> GSMTAP LTE RRC subtype
PDU2GSMTAP = {3: 5, 7: 6, 8: 0, 9: 1, 10: 2, 11: 3}
UPLINK_PDUS = {10, 11}
GPS_EPOCH = 315964800  # 1980-01-06 в unix time
CAPINFO_WINDOW = 2.0   # с, от UECapabilityEnquiry до пустого UL-DCCH

# NR-бэнды (DL NR-ARFCN, TS 38.101-1), перекрывающиеся выводятся все
NR_BANDS = [('n28', 151600, 160600), ('n20', 158200, 164200), ('n8', 185000, 192000),
            ('n3', 361000, 376000), ('n1', 422000, 434000), ('n40', 460000, 480000),
            ('n7', 524000, 538000), ('n38', 514000, 524000), ('n41', 499200, 537999),
            ('n78', 620000, 653333), ('n77', 620000, 680000), ('n79', 693334, 733333)]


def nr_arfcn_mhz(n):
    if n < 600000:
        return n * 0.005
    if n < 2016667:
        return 3000 + (n - 600000) * 0.015
    return 24250.08 + (n - 2016667) * 0.06


def nr_bands(n):
    return '/'.join(b for b, lo, hi in NR_BANDS if lo <= n <= hi) or '?'


def is_cap_enquiry(pdu, msg):
    # DL-DCCH: бит 0 - c1, следующие 4 бита - тип; 7 = ueCapabilityEnquiry
    return pdu == 9 and msg and not msg[0] & 0x80 and (msg[0] >> 3) & 0xf == 7


# ---------- слой 1: CoreSight TPIU ----------
def tpiu_deframe(data):
    out = collections.defaultdict(bytearray)
    cur = None
    for off in range(0, len(data) - 15, 16):
        f = data[off:off + 16]
        if f[:4] == b'\xff\xff\xff\x7f':  # frame sync
            continue
        aux = f[15]
        for i in range(0, 15, 2):
            b = f[i]
            k = i // 2
            if b & 1:  # смена ID
                nid = b >> 1
                if i + 1 < 15:
                    if (aux >> k) & 1:  # следующий байт ещё относится к старому ID
                        if cur is not None:
                            out[cur].append(f[i + 1])
                        cur = nid
                    else:
                        cur = nid
                        out[cur].append(f[i + 1])
                else:
                    cur = nid
            elif cur is not None:
                out[cur].append((b & 0xfe) | ((aux >> k) & 1))
                if i + 1 < 15:
                    out[cur].append(f[i + 1])
    return out


# ---------- слой 2: блоки по 16 байт ----------
_TAG_RE = re.compile(rb'[\x03\x23\x43\x63\x83\xa3\xc3\xe3]\x00\x00\x00')


def unit_alignment(s):
    c = collections.Counter(m.start() % 16 for m in _TAG_RE.finditer(s))
    return c.most_common(1)[0][0] if c else 0


def reassemble(s):
    pend = {}
    for off in range(unit_alignment(s), len(s) - 15, 16):
        u = s[off:off + 16]
        typ = u[0] & 0x1f
        st = u[0] >> 5
        if typ == 0x13:
            length = struct.unpack_from('<H', u, 2)[0]
            pre = 8 if u[1] & 0x40 else 4
            pend[st] = [length, bytearray(u[4:16]), pre]
        elif typ == 0x03 and st in pend:
            pend[st][1] += u[4:16]
        else:
            continue
        if st in pend:
            length, buf, pre = pend[st]
            if len(buf) >= pre + length:
                del pend[st]
                yield bytes(buf[pre:pre + length])


# ---------- слой 3: diag log-пакеты ----------
def diag_logs(s):
    for m in reassemble(s):
        if len(m) < 16 or m[:2] != b'\x10\x00' or m[4:6] != m[2:4]:
            continue
        if struct.unpack_from('<H', m, 2)[0] + 4 != len(m):
            continue
        code = struct.unpack_from('<H', m, 6)[0]
        ts = GPS_EPOCH + (struct.unpack_from('<Q', m, 8)[0] >> 16) * 1.25e-3
        yield code, ts, m[16:]


# ---------- pcap (DLT_RAW, IPv4/UDP/GSMTAP) ----------
def gsmtap_packet(subtype, arfcn, payload, uplink):
    a = (arfcn & 0x3fff) | (0x4000 if uplink else 0)
    gt = struct.pack('>BBBBHbbIBBBB', 2, 4, 0x0d, 0, a, 0, 0, 0, subtype, 0, 0, 0) + payload
    udp = struct.pack('>HHHH', 4729, 4729, 8 + len(gt), 0) + gt
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     b'\x7f\0\0\1', b'\x7f\0\0\1')
    return ip + udp


def write_pcap(path, recs):
    tmp = path + '.part'
    with open(tmp, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        for ts, pkt in recs:
            sec = int(ts)
            f.write(struct.pack('<IIII', sec, int((ts - sec) * 1e6), len(pkt), len(pkt)))
            f.write(pkt)
    os.replace(tmp, path)


# ---------- обработка одной папки ----------
def find_qdss_dir(folder):
    if glob.glob(os.path.join(folder, '0x*.bin')):
        return folder
    cands = sorted(glob.glob(os.path.join(folder, 'logs', 'Baseband', '*qdss*')))
    return cands[-1] if cands else None


def process(folder, out_path):
    qdir = find_qdss_dir(folder)
    if not qdir:
        return {'folder': folder, 'error': 'нет logs/Baseband/*-qdss'}
    files = sorted(glob.glob(os.path.join(qdir, '0x*.bin')),
                   key=lambda p: int(os.path.basename(p)[2:-4], 16))
    st = collections.Counter()
    recs = []
    enquiries, empty_ul = [], []
    nr_cells = collections.Counter()
    tmin = tmax = None
    for fn in files:
        with open(fn, 'rb') as fh:
            streams = tpiu_deframe(fh.read())
        if not streams:
            continue
        s = bytes(max(streams.values(), key=len))
        for code, ts, p in diag_logs(s):
            st['diag'] += 1
            if code == NR_RRC_OTA:
                st['nr_ota'] += 1
                if len(p) >= 21:
                    pci = struct.unpack_from('<H', p, 7)[0]
                    arfcn = struct.unpack_from('<I', p, 17)[0]
                    if pci != 0xffff and arfcn:
                        nr_cells[(pci, arfcn)] += 1
                continue
            if code == NR_RRC_CFG:
                # байт 13 != 0 - похоже на заданную NR-конфигурацию; сохраняем для отчёта
                st['nr_cfg'] += 1
                continue
            if code != LOG_LTE_RRC_OTA or len(p) < 24:
                continue
            if p[0] != 0x1e:
                st['rrc_unknown_ver'] += 1
                continue
            pdu = p[14]
            ln = struct.unpack_from('<H', p, 19)[0]
            if ln == 0:
                st['empty_' + ('ul' if pdu in UPLINK_PDUS else 'dl')] += 1
                if pdu == 11:
                    empty_ul.append(ts)
                continue
            if pdu not in PDU2GSMTAP or 24 + ln > len(p):
                st['rrc_skipped'] += 1
                continue
            if is_cap_enquiry(pdu, p[24:24 + ln]):
                enquiries.append(ts)
            earfcn = struct.unpack_from('<I', p, 8)[0]
            recs.append((ts, gsmtap_packet(PDU2GSMTAP[pdu], earfcn, p[24:24 + ln],
                                           pdu in UPLINK_PDUS)))
    # отбрасываем записи с испорченным временем (напр. 0 -> 1980 год): > 1 ч от медианы
    if recs:
        med = sorted(r[0] for r in recs)[len(recs) // 2]
        good = [r for r in recs if abs(r[0] - med) < 3600]
        st['bad_ts'] = len(recs) - len(good)
        recs = good
    recs.sort(key=lambda r: r[0])
    if recs:
        tmin, tmax = recs[0][0], recs[-1][0]
    write_pcap(out_path, recs)
    # пустой UL-DCCH вскоре после CapEnq - это UECapabilityInformation без тела
    cap_empty = [t for t in empty_ul if any(0 <= t - e <= CAPINFO_WINDOW for e in enquiries)]
    st['capinfo_empty'] = len(cap_empty)
    return {'folder': folder, 'pcap': out_path, 'rrc': len(recs), 'files': len(files),
            'tmin': tmin, 'tmax': tmax, 'stats': dict(st), 'cap_empty': cap_empty,
            'nr_cells': sorted(nr_cells.items())}


# ---------- сводка через tshark ----------
SUMMARY_FILTERS = [
    ('5G-флаг SIB2', 'lte-rrc.upperLayerIndication_r15'),
    ('CapEnq', 'lte-rrc.ueCapabilityEnquiry_element'),
    ('CapEnq NR', 'lte-rrc.ueCapabilityEnquiry_element && (lte-rrc.RAT_Type == 5 || lte-rrc.RAT_Type == 6)'),
    ('CapInfo', 'lte-rrc.ueCapabilityInformation_element'),
    ('measObjNR', 'lte-rrc.measObjectNR_r15_element'),
    ('nr-Config', 'lte-rrc.nr_Config_r15'),
    ('SCG fail', 'lte-rrc.scgFailureInformationNR_r15_element'),
]


def tshark_summary(pcap):
    tshark = shutil.which('tshark') or '/Applications/Wireshark.app/Contents/MacOS/tshark'
    if not os.path.exists(tshark):
        return None
    res = {}
    for name, flt in SUMMARY_FILTERS:
        r = subprocess.run([tshark, '-r', pcap, '-Y', flt, '-T', 'fields', '-e', 'frame.number'],
                           capture_output=True, text=True)
        res[name] = len(r.stdout.split())
    return res


def fmt_time(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S') if ts else '-'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('path', nargs='?', default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument('-f', '--force', action='store_true', help='пересоздать существующие .pcap')
    ap.add_argument('-j', '--jobs', type=int, default=os.cpu_count(), help='параллельных процессов')
    ap.add_argument('--no-summary', action='store_true', help='не запускать tshark для сводки')
    args = ap.parse_args()

    root = os.path.abspath(os.path.expanduser(args.path))
    if find_qdss_dir(root) and os.path.basename(root).startswith('sysdiagnose'):
        folders = [root]
    else:
        folders = sorted(d for d in glob.glob(os.path.join(root, 'sysdiagnose_*')) if os.path.isdir(d))
    if not folders:
        sys.exit('Не найдено папок sysdiagnose_* в %s' % root)

    jobs = []
    for d in folders:
        out = d.rstrip('/') + '.pcap'
        if os.path.exists(out) and not args.force:
            print('пропуск (уже есть): %s' % os.path.basename(out))
            continue
        jobs.append((d, out))

    results = []
    with ProcessPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = [ex.submit(process, d, out) for d, out in jobs]
        for fu in futs:
            r = fu.result()
            results.append(r)
            name = os.path.basename(r['folder'])
            if 'error' in r:
                print('%s: ОШИБКА %s' % (name, r['error']))
            else:
                print('%s: %d RRC, окно %s-%s' % (name, r['rrc'], fmt_time(r['tmin']), fmt_time(r['tmax'])))

    if args.no_summary or not results:
        return
    print()
    cols = [n for n, _ in SUMMARY_FILTERS]
    head = ('%-22s %5s %6s %6s %8s ' % ('sysdiagnose', 'RRC', 'пустUL', 'пустDL', 'CapInfo∅')
            + ' '.join('%11s' % c for c in cols) + '  NR-OTA')
    print(head)
    print('-' * len(head))
    for r in results:
        if 'error' in r:
            continue
        summ = tshark_summary(r['pcap']) or {}
        st = r['stats']
        nr = st.get('nr_ota', 0)
        short = os.path.basename(r['folder']).replace('sysdiagnose_', '')[:22]
        print('%-22s %5d %6d %6d %8d ' % (short, r['rrc'], st.get('empty_ul', 0), st.get('empty_dl', 0),
                                          st.get('capinfo_empty', 0))
              + ' '.join('%11s' % summ.get(c, '?') for c in cols) + '  %d' % nr)

    # детали: UECapabilityInformation без тела и NR-ячейки (из 0xB821)
    for r in results:
        if 'error' in r or not (r['cap_empty'] or r['nr_cells']):
            continue
        print('\n%s:' % os.path.basename(r['folder']))
        for t in r['cap_empty']:
            print('  %s UECapabilityInformation отправлена, тело модем не логирует' % fmt_time(t))
        for (pci, arfcn), n in r['nr_cells']:
            print('  NR-ячейка PCI %d, NR-ARFCN %d (%.2f МГц, %s) - %d записей'
                  % (pci, arfcn, nr_arfcn_mhz(arfcn), nr_bands(arfcn), n))


if __name__ == '__main__':
    main()
