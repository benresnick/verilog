#!/usr/bin/env python3
"""AES-GCM RTL differential tests using the independent OpenSSL EVP oracle.

Requires Python 3, a shared libcrypto, Icarus, and vvp; no Python packages or
network. Inputs are deterministic. Logs and fixture manifests are retained in
logs/gcm; compiled simulations and fixture data use a temporary directory.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ["aes_primitives.sv", "aes_key_expand.sv", "aes_encrypt_block.sv",
           "gf128_mul.sv", "ghash_core.sv", "gctr_core.sv", "aes_gcm_engine.sv",
           "aes_gcm_engine_tb.sv"]
MAX_PAYLOAD = 1031
MAX_AAD = 1033


class OpenSSLGCM:
    """EVP authenticated encrypt/decrypt, independent of every RTL primitive."""
    def __init__(self):
        library = ctypes.util.find_library("crypto")
        if not library:
            raise RuntimeError("A shared OpenSSL libcrypto is required")
        self.library = library
        self.lib = ctypes.CDLL(library)
        ptr, integer = ctypes.c_void_p, ctypes.c_int
        self.lib.EVP_CIPHER_CTX_new.restype = ptr
        self.lib.EVP_CIPHER_CTX_new.argtypes = []
        self.lib.EVP_CIPHER_CTX_free.argtypes = [ptr]
        self.lib.EVP_CIPHER_CTX_free.restype = None
        self.lib.EVP_CIPHER_CTX_ctrl.argtypes = [ptr, integer, integer, ptr]
        self.lib.EVP_CIPHER_CTX_ctrl.restype = integer
        for bits in (128, 256):
            function = getattr(self.lib, f"EVP_aes_{bits}_gcm")
            function.argtypes = []
            function.restype = ptr
        for direction in ("Encrypt", "Decrypt"):
            init = getattr(self.lib, f"EVP_{direction}Init_ex")
            init.argtypes = [ptr, ptr, ptr, ptr, ptr]
            init.restype = integer
            update = getattr(self.lib, f"EVP_{direction}Update")
            update.argtypes = [ptr, ptr, ctypes.POINTER(integer), ptr, integer]
            update.restype = integer
            final = getattr(self.lib, f"EVP_{direction}Final_ex")
            final.argtypes = [ptr, ptr, ctypes.POINTER(integer)]
            final.restype = integer

    @staticmethod
    def checked(result):
        if result != 1:
            raise RuntimeError("OpenSSL EVP operation failed")

    def transform(self, key, iv, aad, data, tag=None):
        if len(key) not in (16, 32) or len(iv) != 12:
            raise ValueError("GCM oracle accepts 128/256-bit keys and 96-bit IVs")
        decrypt = tag is not None
        direction = "Decrypt" if decrypt else "Encrypt"
        init = getattr(self.lib, f"EVP_{direction}Init_ex")
        update = getattr(self.lib, f"EVP_{direction}Update")
        final = getattr(self.lib, f"EVP_{direction}Final_ex")
        cipher = getattr(self.lib, f"EVP_aes_{8 * len(key)}_gcm")()
        context = self.lib.EVP_CIPHER_CTX_new()
        if not context:
            raise RuntimeError("EVP_CIPHER_CTX_new failed")
        try:
            key_buf, iv_buf = ctypes.create_string_buffer(key), ctypes.create_string_buffer(iv)
            self.checked(init(context, cipher, None, None, None))
            self.checked(self.lib.EVP_CIPHER_CTX_ctrl(context, 0x9, len(iv), None))
            self.checked(init(context, None, None, key_buf, iv_buf))
            count = ctypes.c_int()
            if aad:
                self.checked(update(context, None, ctypes.byref(count),
                                    ctypes.create_string_buffer(aad), len(aad)))
            output = ctypes.create_string_buffer(len(data) + 16)
            total = 0
            if data:
                self.checked(update(context, output, ctypes.byref(count),
                                    ctypes.create_string_buffer(data), len(data)))
                total = count.value
            if decrypt:
                if len(tag) != 16:
                    raise ValueError("Expected a 128-bit GCM tag")
                tag_buffer = ctypes.create_string_buffer(tag)
                self.checked(self.lib.EVP_CIPHER_CTX_ctrl(context, 0x11, 16, tag_buffer))
            valid = final(context, ctypes.byref(output, total), ctypes.byref(count))
            if decrypt and valid == 0:
                return None
            self.checked(valid)
            data_out = output.raw[:total + count.value]
            if decrypt:
                return data_out
            tag_buffer = ctypes.create_string_buffer(16)
            self.checked(self.lib.EVP_CIPHER_CTX_ctrl(context, 0x10, 16, tag_buffer))
            return data_out, tag_buffer.raw
        finally:
            self.lib.EVP_CIPHER_CTX_free(context)


def nist_vectors(oracle):
    vectors = json.loads((ROOT / "tests/gcm_nist_vectors.json").read_text())["vectors"]
    decoded = []
    for entry in vectors:
        case = {name: bytes.fromhex(value) if name != "name" else value
                for name, value in entry.items()}
        cipher, tag = oracle.transform(case["key"], case["iv"], case["aad"], case["plaintext"])
        if cipher != case["ciphertext"] or tag != case["tag"]:
            raise RuntimeError(f"OpenSSL failed independent known-answer test {case['name']}")
        plain = oracle.transform(case["key"], case["iv"], case["aad"], cipher, tag)
        if plain != case["plaintext"]:
            raise RuntimeError(f"OpenSSL failed decrypt self-check {case['name']}")
        bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
        if oracle.transform(case["key"], case["iv"], case["aad"], cipher, bad_tag) is not None:
            raise RuntimeError("OpenSSL oracle accepted an invalid tag")
        decoded.append(case)
    return decoded


def vector_cases(oracle, nist, bits, width, quick=False):
    cases = [case for case in nist if len(case["key"]) * 8 == bits]
    bus = width // 8

    def add(name, aad_length, payload_length):
        seed = f"ws-gcm-v1-{bits}-{width}-{name}".encode()
        material = hashlib.shake_256(seed).digest(bits // 8 + 12 + aad_length + payload_length)
        key = material[:bits // 8]
        iv = material[bits // 8:bits // 8 + 12]
        aad = material[bits // 8 + 12:bits // 8 + 12 + aad_length]
        plain = material[bits // 8 + 12 + aad_length:]
        cipher, tag = oracle.transform(key, iv, aad, plain)
        if oracle.transform(key, iv, aad, cipher, tag) != plain:
            raise RuntimeError("Independent EVP round-trip failed")
        cases.append(dict(name=name, key=key, iv=iv, aad=aad, plaintext=plain,
                          ciphertext=cipher, tag=tag))

    # Index two is used for bit-flip, framing, cancellation, and recovery tests.
    add("adversarial", min(2 * bus + 3, MAX_AAD), min(2 * bus + 7, MAX_PAYLOAD))
    lengths = range(min(bus, 16) + 1) if quick else range(bus + 1)
    for length in lengths:
        add(f"tail-{length}", (7 * length) % (bus + 1), length)
    for index, (aad_len, payload_len) in enumerate((
        (0, 1), (1, 0), (15, 16), (16, 15), (17, 17),
        (bus - 1, bus + 1), (bus + 1, bus - 1),
        (2 * bus, 2 * bus), (MAX_AAD, 0), (0, MAX_PAYLOAD),
        (MAX_AAD, MAX_PAYLOAD), (MAX_AAD - 1, MAX_PAYLOAD - 1),
    )):
        add(f"boundary-{index}", aad_len, payload_len)
    for index in range(4 if quick else 24):
        digest = hashlib.sha256(f"ws-gcm-length-{index}".encode()).digest()
        add(f"random-{index}", int.from_bytes(digest[:2], "big") % (MAX_AAD + 1),
            int.from_bytes(digest[2:4], "big") % (MAX_PAYLOAD + 1))
    return cases


def write_fixture(path, cases):
    with path.open("w") as stream:
        stream.write(f"{len(cases)}\n")
        for case in cases:
            fields = [case["key"].hex(), case["iv"].hex(), str(len(case["aad"])),
                      str(len(case["plaintext"])), case["tag"].hex(),
                      case["aad"].hex() or "0", case["plaintext"].hex() or "0",
                      case["ciphertext"].hex() or "0"]
            stream.write(" ".join(fields) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--widths", default="128,384,512", help="Comma-separated memory bus widths")
    parser.add_argument("--keys", default="128,256", help="Comma-separated AES key widths")
    parser.add_argument("--quick", action="store_true", help="Reduce vectors/tag mutations; 4096-bit runs use vector/stall smoke only")
    parser.add_argument("--match", default="", help="Run only names containing this string")
    parser.add_argument("--oracle-only", action="store_true", help="Validate EVP against NIST without RTL")
    args = parser.parse_args()
    oracle = OpenSSLGCM()
    nist = nist_vectors(oracle)
    print(f"PASS OpenSSL EVP self-check: {len(nist)} NIST vectors and altered-tag rejection ({oracle.library})", flush=True)
    if args.oracle_only:
        return
    for tool in ("iverilog", "vvp"):
        if not shutil.which(tool):
            parser.error(f"required tool is unavailable: {tool}")
    logs = ROOT / "logs/gcm"
    logs.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="ws-gcm-") as temporary:
        scratch = Path(temporary)
        for bits in map(int, args.keys.split(",")):
            for width in map(int, args.widths.split(",")):
                name = f"gcm-aes{bits}-w{width}"
                if args.match and args.match not in name:
                    continue
                start = time.monotonic()
                cases = vector_cases(oracle, nist, bits, width, args.quick)
                fixture = scratch / f"{name}.txt"
                write_fixture(fixture, cases)
                (logs / f"{name}-cases.json").write_text(json.dumps([
                    {"name": c["name"], "aad_bytes": len(c["aad"]), "payload_bytes": len(c["plaintext"])}
                    for c in cases], indent=2) + "\n")
                binary = scratch / name
                command = ["iverilog", "-g2012", "-s", "aes_gcm_engine_tb", "-o", str(binary),
                           f"-Paes_gcm_engine_tb.AES_KEY_W={bits}",
                           f"-Paes_gcm_engine_tb.MEM_DATA_W={width}"]
                command.extend(str(ROOT / source) for source in SOURCES)
                compile_result = subprocess.run(command, capture_output=True, text=True, timeout=120)
                output = compile_result.stdout + compile_result.stderr
                passed = False
                if compile_result.returncode == 0:
                    try:
                        plusargs = [f"+vectors={fixture}", f"+tag_bits={8 if args.quick else 128}"]
                        if width == 4096 and args.quick:
                            # The default six configurations exhaust the directed
                            # matrix. Wide smoke retains every oracle byte/tag,
                            # ignored-byte, stall, erasure, and burst assertion.
                            plusargs.append("+smoke")
                        simulation = subprocess.run(["vvp", str(binary), *plusargs],
                                                    capture_output=True, text=True, timeout=600)
                        output += simulation.stdout + simulation.stderr
                        passed = simulation.returncode == 0 and "PASS GCM" in output and "FATAL" not in output
                    except subprocess.TimeoutExpired as error:
                        output += "\nFAIL simulation exceeded 600-second timeout\n"
                        if error.stdout:
                            output += error.stdout.decode() if isinstance(error.stdout, bytes) else error.stdout
                elapsed = round(time.monotonic() - start, 2)
                (logs / f"{name}.log").write_text(output)
                results.append(dict(case=name, passed=passed, seconds=elapsed, oracle_vectors=len(cases)))
                print(f"{'PASS' if passed else 'FAIL'} {name}: {len(cases)} oracle vectors ({elapsed}s)", flush=True)
                print(output[-3000:] if not passed else "\n".join(output.splitlines()[-2:]), flush=True)
    if not results:
        parser.error("no test configurations matched")
    full_campaign = not args.match and not args.quick and args.keys == "128,256" and args.widths == "128,384,512"
    summary_name = "summary.json" if full_campaign else "selected-summary.json"
    if args.widths == "4096":
        summary_name = "wide-summary.json"
    (logs / summary_name).write_text(json.dumps(results, indent=2) + "\n")
    failed = [result["case"] for result in results if not result["passed"]]
    print(f"GCM: {len(results) - len(failed)}/{len(results)} configurations passed; logs: {logs}")
    if failed:
        raise SystemExit("Failed cases: " + ", ".join(failed))


if __name__ == "__main__":
    main()
