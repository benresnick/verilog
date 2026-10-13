#!/usr/bin/env python3
"""Encrypted DRAM records -> tagged matrix multiply -> committed GCM records.

Independent OpenSSL EVP ciphertext/tags and Python signed matrix multiplication
are the only golden data. No network or third-party Python packages required.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
from run_gcm import OpenSSLGCM, nist_vectors

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ['pe.sv', 'sysarr.sv', 'buffers.sv', 'secure_tags.sv',
           'weight_stationary_accelerator.sv', 'aes_primitives.sv', 'aes_key_expand.sv',
           'aes_encrypt_block.sv', 'gf128_mul.sv', 'ghash_core.sv', 'gctr_core.sv',
           'aes_gcm_engine.sv', 'tenant_key_regfile.sv', 'tenant_gcm_port.sv',
           'tenant_gcm_cluster.sv', 'authenticated_row_stager.sv', 'secure_memory_accelerator.sv']
TENANTS = [0, 0x823456789abcdef001234567, 0xfedcba987654321098765432]
COUNTERS = 32


def aad(tenant, kind, length, row):
    return b'TGC1' + tenant.to_bytes(12, 'big') + kind.to_bytes(4, 'big') + length.to_bytes(4, 'big') + row.to_bytes(8, 'big')


def fixtures(path, oracle, bits, data_bits, acc_bits, quick):
    keys = [hashlib.shake_256(f'secure-memory-key-{bits}-{i}'.encode()).digest(bits // 8) for i in range(3)]
    shapes = [(3, 19, 5)] if quick else [(3, 19, 5), (1, 1, 1), (4, 7, 7), (2, 17, 3)]
    rows = [str(len(shapes))]
    rows += [f'{TENANTS[i]:024x} {keys[i].hex()} {0xb1230000+i:08x}' for i in range(3)]
    mask = (1 << acc_bits) - 1
    data_bytes, acc_bytes = data_bits // 8, acc_bits // 8
    for case, (m, k, n) in enumerate(shapes):
        raw = hashlib.shake_256(f'secure-matrix-{case}-{data_bits}'.encode()).digest((m*k + k*n)*data_bytes)
        values = [int.from_bytes(raw[i:i+data_bytes], 'big', signed=True) for i in range(0, len(raw), data_bytes)]
        a = [values[r*k:(r+1)*k] for r in range(m)]
        b = [values[m*k+r*n:m*k+(r+1)*n] for r in range(k)]
        rows.append(f'{m} {k} {n}')
        for r in range(m):
            tenant = 1 + r % 2
            plain = b''.join(v.to_bytes(data_bytes, 'big', signed=True) for v in a[r])
            iv = (0xa1230000+tenant).to_bytes(4, 'big') + (case*32+r).to_bytes(8, 'big')
            cipher, tag = oracle.transform(keys[tenant], iv, aad(TENANTS[tenant], 1, len(plain), r), plain)
            header = b'TGR1' + iv + tag
            alternate = bytes([plain[0] ^ 0x5a]) + plain[1:]
            alternate_iv = (0xa1230000+tenant).to_bytes(4, 'big') + (0x8000+case*32+r).to_bytes(8, 'big')
            alternate_cipher, alternate_tag = oracle.transform(keys[tenant], alternate_iv, aad(TENANTS[tenant], 1, len(plain), r), alternate)
            alternate_header = b'TGR1' + alternate_iv + alternate_tag
            rows.append(f'{plain.hex()} {header.hex()} {cipher.hex()} {alternate.hex()} {alternate_header.hex()} {alternate_cipher.hex()}')
        for r in range(k):
            plain = b''.join(v.to_bytes(data_bytes, 'big', signed=True) for v in b[r])
            iv = bytes.fromhex('a1230000') + (case*32+r).to_bytes(8, 'big')
            cipher, tag = oracle.transform(keys[0], iv, aad(0, 2, len(plain), r), plain)
            alternate = bytes([plain[0] ^ 0x5a]) + plain[1:]
            alternate_iv = bytes.fromhex('a1230000') + (0x8000+case*32+r).to_bytes(8, 'big')
            alternate_cipher, alternate_tag = oracle.transform(keys[0], alternate_iv, aad(0, 2, len(plain), r), alternate)
            alternate_header = b'TGR1' + alternate_iv + alternate_tag
            rows.append(f'{plain.hex()} {(b"TGR1"+iv+tag).hex()} {cipher.hex()} {alternate.hex()} {alternate_header.hex()} {alternate_cipher.hex()}')
        for r in range(m):
            tenant = 1 + r % 2
            sums = [sum(a[r][i] * b[i][c] for i in range(k)) & mask for c in range(n)]
            plain = b''.join(v.to_bytes(acc_bytes, 'big') for v in sums)
            rows.append(plain.hex())
            for counter in range(COUNTERS):
                iv = (0xb1230000+tenant).to_bytes(4, 'big') + counter.to_bytes(8, 'big')
                cipher, tag = oracle.transform(keys[tenant], iv, aad(TENANTS[tenant], 3, len(plain), r), plain)
                assert oracle.transform(keys[tenant], iv, aad(TENANTS[tenant], 3, len(plain), r), cipher, tag) == plain
                rows.append(f'{cipher.hex()} {(b"TGR1"+iv+tag).hex()}')
    path.write_text('\n'.join(rows) + '\n')
    return shapes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keys', default='128,256')
    parser.add_argument('--widths', default='128,384')
    parser.add_argument('--quick', action='store_true')
    parser.add_argument('--data-bits', type=int, default=8)
    parser.add_argument('--acc-bits', type=int, default=32)
    parser.add_argument('--rows', type=int, default=2)
    parser.add_argument('--cols', type=int, default=2)
    parser.add_argument('--banks', type=int, default=2)
    parser.add_argument('--match', default='')
    parser.add_argument('--oracle-only', action='store_true')
    args = parser.parse_args()
    oracle = OpenSSLGCM()
    print(f'PASS OpenSSL self-check: {len(nist_vectors(oracle))} NIST records', flush=True)
    if args.oracle_only:
        return
    logs = ROOT / 'logs/secure-memory'
    logs.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix='secure-memory-') as tmp:
        scratch = Path(tmp)
        for bits in map(int, args.keys.split(',')):
            fixture = scratch / f'fixture-{bits}.txt'
            shapes = fixtures(fixture, oracle, bits, args.data_bits, args.acc_bits, args.quick)
            for width in map(int, args.widths.split(',')):
                name = f'secure-aes{bits}-w{width}-d{args.data_bits}-a{args.acc_bits}-{args.rows}x{args.cols}-banks{args.banks}'
                if args.match and args.match not in name:
                    continue
                binary = scratch / name
                command = ['iverilog', '-g2012', '-DENABLE_SECURE_TAGS', '-DENABLE_SECURE_MEMORY',
                           '-s', 'secure_memory_accelerator_tb', '-o', str(binary)]
                params = {'AES_KEY_W': bits, 'MEM_DATA_W': width, 'DATA_WIDTH': args.data_bits,
                          'ACC_WIDTH': args.acc_bits, 'ROWS': args.rows, 'COLS': args.cols,
                          'WEIGHTS_PER_PE': args.banks}
                command += [f'-Psecure_memory_accelerator_tb.{k}={v}' for k, v in params.items()]
                command += [str(ROOT / s) for s in SOURCES + ['secure_memory_accelerator_tb.sv']]
                started = time.monotonic()
                output, passed = '', False
                try:
                    build = subprocess.run(command, capture_output=True, text=True, timeout=120)
                    output = build.stdout + build.stderr
                    if build.returncode == 0:
                        sim = subprocess.run(['vvp', str(binary), f'+vectors={fixture}'], capture_output=True, text=True, timeout=600)
                        output += sim.stdout + sim.stderr
                        passed = sim.returncode == 0 and 'PASS SECURE_MEMORY' in output and 'FATAL' not in output and 'ERROR:' not in output
                except subprocess.TimeoutExpired as error:
                    chunk = error.stdout or ''
                    output += (chunk.decode() if isinstance(chunk, bytes) else chunk) + '\nFAIL watchdog\n'
                (logs / f'{name}.log').write_text(output)
                entry = dict(case=name, passed=passed, seconds=round(time.monotonic()-started, 2), shapes=shapes)
                coverage = re.search(r'(\d+) loads, (\d+) stored rows, (\d+) rejected loads, (\d+) checks', output)
                if coverage:
                    entry.update(zip(('loads', 'stored_rows', 'rejected_loads', 'checks'), map(int, coverage.groups())))
                results.append(entry)
                print(f'{"PASS" if passed else "FAIL"} {name} ({entry["seconds"]}s)', flush=True)
                print('\n'.join(output.splitlines()[-2:]) if passed else output[-7000:], flush=True)
    if not results:
        parser.error('no configurations matched')
    selected = args.quick or args.match or args.keys != '128,256' or args.widths != '128,384' or args.data_bits != 8 or args.acc_bits != 32 or args.rows != 2 or args.cols != 2 or args.banks != 2
    (logs / ('selected-summary.json' if selected else 'summary.json')).write_text(json.dumps(results, indent=2)+'\n')
    print(f'SECURE_MEMORY: {sum(r["passed"] for r in results)}/{len(results)} configurations passed')
    if not all(r['passed'] for r in results):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
