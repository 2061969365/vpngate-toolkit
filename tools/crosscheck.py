#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨语言交叉验证：Go 与 Python 必须对同一 DAT 输出逐字节一致

用法（从 vpngate-toolkit 根目录）:
    python tools/crosscheck.py
"""
import hashlib
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, 'fixtures', 'api_raw.bin')
FIX2 = os.path.join(ROOT, 'fixtures', 'VPNGate.dat')


def run(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
    return r.returncode, r.stdout, r.stderr


def check(fixture, go_out, py_out):
    print(f'\n=== {os.path.basename(fixture)} ===')
    g = subprocess.run(['go', 'run', './cmd/vpngate', 'decode',
                        '--in', fixture, '--out', go_out],
                       cwd=os.path.join(ROOT, 'go'),
                       capture_output=True, text=True, timeout=600)
    print(f'  go  rc={g.returncode}  {g.stderr.strip()[:200]}')
    if g.returncode != 0:
        return False

    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, 'python'))
    p = subprocess.run([sys.executable, '-m', 'vpngate', 'decode',
                        '--in', fixture, '--out', py_out],
                       cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=300)
    print(f'  py  rc={p.returncode}  {p.stderr.strip()[:200]}')
    if p.returncode != 0:
        return False

    gb = open(go_out, 'rb').read()
    pb = open(py_out, 'rb').read()
    hg = hashlib.sha256(gb).hexdigest()[:16]
    hp = hashlib.sha256(pb).hexdigest()[:16]
    print(f'  go  {len(gb):>8} B  sha256={hg}')
    print(f'  py  {len(pb):>8} B  sha256={hp}')

    if gb == pb:
        print('  ✓ 逐字节一致')
        return True

    print('  ✗ 不一致')
    # 定位首个差异
    for i, (a, b) in enumerate(zip(gb, pb)):
        if a != b:
            print(f'    首个差异 @ byte {i}')
            print(f'    go: ...{gb[max(0,i-60):i+60]!r}')
            print(f'    py: ...{pb[max(0,i-60):i+60]!r}')
            break
    else:
        print(f'    长度不同: go={len(gb)} py={len(pb)}')
    return False


def main():
    if not os.path.isfile(FIX):
        sys.exit(f'缺少 fixture: {FIX}')
    tmp = tempfile.mkdtemp()
    ok = True
    for f in (FIX, FIX2):
        if not os.path.isfile(f):
            print(f'跳过（不存在）: {f}')
            continue
        g = os.path.join(tmp, os.path.basename(f) + '.go.json')
        p = os.path.join(tmp, os.path.basename(f) + '.py.json')
        ok &= check(f, g, p)

    print('\n' + '=' * 50)
    print('RESULT:', 'PASS' if ok else 'FAIL')
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
