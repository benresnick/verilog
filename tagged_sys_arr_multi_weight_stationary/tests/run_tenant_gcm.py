#!/usr/bin/env python3
"""Independent OpenSSL differential and adversarial tests for tenant GCM integration.

The fixture AAD is encoded here from public record fields, independently of RTL.
No Python package or network access is required. Retained logs describe coverage;
compiled simulations and secrets used only as deterministic fixtures are temporary.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from run_gcm import OpenSSLGCM, nist_vectors

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ["aes_primitives.sv", "aes_key_expand.sv", "aes_encrypt_block.sv",
           "gf128_mul.sv", "ghash_core.sv", "gctr_core.sv", "aes_gcm_engine.sv",
           "tenant_key_regfile.sv", "tenant_gcm_port.sv", "tenant_gcm_cluster.sv",
           "tenant_gcm_cluster_tb.sv"]


def vectors(oracle, bits, width, maximum, quick):
    bus = width // 8
    # Vector zero must span multiple beats for cancellation/framing scenarios.
    lengths = [min(2 * bus + 7, maximum), 0, 1, 15, 16, 17,
               bus - 1, bus, min(bus + 1, maximum), maximum - 1, maximum]
    lengths += list(range(min(bus, 8) + 1)) if quick else list(range(bus + 1))
    for index in range(4 if quick else 16):
        lengths.append(int.from_bytes(hashlib.sha256(f"tenant-gcm-length-{index}".encode()).digest()[:4], "big") % (maximum + 1))
    result = []
    for index, length in enumerate(lengths):
        material = hashlib.shake_256(f"tenant-gcm-v1-{bits}-{width}-{index}".encode()).digest(bits // 8 + 36 + length)
        key = material[:bits // 8]
        metadata = material[bits // 8:]
        tenant, fixed = metadata[:12], metadata[12:16]
        record_type, destination = metadata[16:20], metadata[20:28]
        plain = metadata[36:]
        aad = b"TGC1" + tenant + record_type + length.to_bytes(4, "big") + destination
        entry = dict(name=f"record-{index}-bytes-{length}", key=key, tenant=tenant,
                     record_type=record_type, destination=destination, plaintext=plain,
                     iv=fixed + bytes(8), length=length)
        for counter in range(3):
            iv = fixed + counter.to_bytes(8, "big")
            cipher, tag = oracle.transform(key, iv, aad, plain)
            assert oracle.transform(key, iv, aad, cipher, tag) == plain
            entry[f"cipher{counter}"], entry[f"tag{counter}"] = cipher, tag
        altered_len = aad[:20] + (length ^ 1).to_bytes(4, "big") + aad[24:]
        entry["bad_length_tag"] = oracle.transform(key, entry["iv"], altered_len, plain)[1]
        entry["bad_magic_tag"] = oracle.transform(key, entry["iv"], b"BAD!" + aad[4:], plain)[1]
        assert oracle.transform(key, entry["iv"], aad, entry["cipher0"], entry["bad_length_tag"]) is None
        result.append(entry)
    return result


def write_fixture(path, cases):
    fields = ["key", "tenant", "record_type", "destination", "iv", "length",
              "plaintext", "cipher0", "tag0", "cipher1", "tag1", "cipher2", "tag2",
              "bad_length_tag", "bad_magic_tag"]
    with path.open("w") as stream:
        stream.write(f"{len(cases)}\n")
        for case in cases:
            stream.write(" ".join((case[k].hex() or "0") if isinstance(case[k], bytes)
                                  else str(case[k]) for k in fields) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keys", default="128,256")
    parser.add_argument("--widths", default="128,384,512")
    parser.add_argument("--slots", default="3", help="Comma-separated key-slot counts")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--match", default="")
    parser.add_argument("--oracle-only", action="store_true")
    args = parser.parse_args()
    oracle = OpenSSLGCM()
    nist = nist_vectors(oracle)
    print(f"PASS OpenSSL EVP self-check: {len(nist)} NIST vectors and tag rejection ({oracle.library})", flush=True)
    if args.oracle_only:
        return
    for executable in ("iverilog", "vvp"):
        if not shutil.which(executable):
            parser.error(f"required tool unavailable: {executable}")
    logs = ROOT / "logs/tenant-gcm"
    logs.mkdir(parents=True, exist_ok=True)
    configs = [(bits, width, slots) for bits in map(int, args.keys.split(','))
               for width in map(int, args.widths.split(','))
               for slots in map(int, args.slots.split(','))]
    full = args.keys == "128,256" and args.widths == "128,384,512" and args.slots == "3" and not args.quick and not args.match
    if full:
        configs += [(128, 128, 1), (256, 128, 1)]
    results = []
    with tempfile.TemporaryDirectory(prefix="tenant-gcm-") as temporary:
        scratch = Path(temporary)
        for bits, width, slots in configs:
            name = f"tenant-gcm-aes{bits}-w{width}-slots{slots}"
            if args.match and args.match not in name:
                continue
            maximum = max(193, 2 * (width // 8) + 7)
            cases = vectors(oracle, bits, width, maximum, args.quick)
            fixture, binary = scratch / f"{name}.txt", scratch / name
            write_fixture(fixture, cases)
            (logs / f"{name}-cases.json").write_text(json.dumps([
                {"name": c["name"], "payload_bytes": c["length"]} for c in cases], indent=2) + '\n')
            started = time.monotonic()
            command = ["iverilog", "-g2012", "-s", "tenant_gcm_cluster_tb", "-o", str(binary),
                       f"-Ptenant_gcm_cluster_tb.AES_KEY_W={bits}",
                       f"-Ptenant_gcm_cluster_tb.MEM_DATA_W={width}",
                       f"-Ptenant_gcm_cluster_tb.NUM_KEY_SLOTS={slots}",
                       f"-Ptenant_gcm_cluster_tb.MAX_TXN_BYTES={maximum}"]
            command.extend(str(ROOT / source) for source in SOURCES)
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=120)
            output = compiled.stdout + compiled.stderr
            passed = False
            if compiled.returncode == 0:
                try:
                    extensive = width == 128 and slots == 3 and not args.quick
                    simulation = subprocess.run(["vvp", str(binary), f"+vectors={fixture}",
                                                 f"+tag_bits={128 if extensive else 8}",
                                                 f"+metadata_bits={64 if extensive else 4}"],
                                                capture_output=True, text=True, timeout=600)
                    output += simulation.stdout + simulation.stderr
                    passed = simulation.returncode == 0 and "PASS TENANT_GCM" in output and "FATAL" not in output
                except subprocess.TimeoutExpired as error:
                    output += '\nFAIL simulation exceeded 600-second watchdog\n'
                    if error.stdout:
                        output += error.stdout.decode() if isinstance(error.stdout, bytes) else error.stdout
            elapsed = round(time.monotonic() - started, 2)
            (logs / f"{name}.log").write_text(output)
            entry = dict(case=name, passed=passed, seconds=elapsed, oracle_vectors=len(cases), max_payload=maximum)
            coverage = re.search(r"(\d+) checked transactions, (\d+) authenticated, (\d+) rejected, (\d+) cancellation(?: scenarios|s), (\d+) groups", output)
            if coverage:
                entry.update(zip(("checked_transactions", "authenticated", "rejected", "cancellation_scenarios", "groups"), map(int, coverage.groups())))
            results.append(entry)
            print(f"{'PASS' if passed else 'FAIL'} {name}: {len(cases)} independent records ({elapsed}s)", flush=True)
            print('\n'.join(output.splitlines()[-2:]) if passed else output[-6000:], flush=True)
    if not results:
        parser.error("no test configuration matched")
    (logs / ("summary.json" if full else "selected-summary.json")).write_text(json.dumps(results, indent=2) + '\n')
    failed = [r['case'] for r in results if not r['passed']]
    print(f"TENANT_GCM: {len(results)-len(failed)}/{len(results)} configurations passed; logs: {logs}")
    if failed:
        raise SystemExit("Failed cases: " + ', '.join(failed))


if __name__ == '__main__':
    main()
