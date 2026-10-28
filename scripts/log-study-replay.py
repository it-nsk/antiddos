#!/usr/bin/env python3
import argparse, datetime as dt, re, time
from pathlib import Path
from threading import Thread

ACCESS = re.compile(r'^(\S+ - - \[)([^]]+)(\])')
ERROR = re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})')
SYSLOG = re.compile(r'^([A-Z][a-z]{2}\s+[ 0-9][0-9]\s+\d{2}:\d{2}:\d{2})')
ISO = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))')

def stamp(line, kind, now):
    if kind == 'access':
        value = now.strftime('%d/%b/%Y:%H:%M:%S %z')
        return ACCESS.sub(lambda match: match.group(1) + value + match.group(3), line, count=1)
    if kind == 'error':
        return ERROR.sub(now.strftime('%Y/%m/%d %H:%M:%S'), line, count=1)
    if ISO.match(line):
        return ISO.sub(now.isoformat(timespec='seconds'), line, count=1)
    return SYSLOG.sub(now.strftime('%b %e %H:%M:%S'), line, count=1)

def parse_time(line, kind, fallback):
    try:
        if kind == 'access':
            return dt.datetime.strptime(ACCESS.search(line).group(2), '%d/%b/%Y:%H:%M:%S %z').timestamp()
        if kind == 'error':
            return dt.datetime.strptime(ERROR.search(line).group(1), '%Y/%m/%d %H:%M:%S').replace(tzinfo=dt.timezone.utc).timestamp()
        iso = ISO.search(line)
        if iso:
            value = iso.group(1).replace('Z', '+00:00')
            return dt.datetime.fromisoformat(value).timestamp()
        year = dt.datetime.now().year
        return dt.datetime.strptime(f'{year} {SYSLOG.search(line).group(1)}', '%Y %b %d %H:%M:%S').replace(tzinfo=dt.timezone.utc).timestamp()
    except Exception:
        return fallback

def replay(name, source, out, kind, speed, stop):
    prev = None; written = 0; progress_at = time.monotonic() + 60
    with open(source, errors='replace') as inp, open(out, 'a', buffering=1) as dst:
        for raw in inp:
            if stop[0]: break
            line = raw.rstrip('\n')
            ts = parse_time(line, kind, prev or time.time())
            if prev is not None:
                delay = max(0.0, (ts - prev) / speed)
                while delay > 0 and not stop[0]:
                    pause = min(delay, 1.0)
                    time.sleep(pause)
                    delay -= pause
            prev = ts
            if stop[0]: break
            dst.write(stamp(line, kind, dt.datetime.now().astimezone()) + '\n')
            written += 1
            if time.monotonic() >= progress_at:
                print(f'{name}: replayed {written} lines', flush=True)
                progress_at = time.monotonic() + 60
    print(f'{name}: replay stopped after {written} lines', flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--speed', type=float, default=1.0)
    ap.add_argument('--output', required=True)
    ap.add_argument('--duration', type=int, default=0)
    ap.add_argument('--source', action='append', nargs=3, metavar=('NAME','KIND','PATH'), required=True)
    args = ap.parse_args()
    if args.speed <= 0: ap.error('--speed must be positive')
    if args.duration < 0: ap.error('--duration must not be negative')
    stop = [False]; threads=[]
    for name, kind, path in args.source:
        t=Thread(target=replay,args=(name,path,str(Path(args.output)/(name+'.log')),kind,args.speed,stop),daemon=True); t.start(); threads.append(t)
    deadline = time.time()+args.duration if args.duration else None
    try:
        while any(t.is_alive() for t in threads):
            if deadline and time.time() >= deadline: stop[0]=True; break
            time.sleep(1)
    except KeyboardInterrupt: stop[0]=True
    for t in threads: t.join()

if __name__ == '__main__': main()
