#!/usr/bin/env python3
"""Reproducible RTL campaigns, independent AES oracle, and negative controls.

Run from any directory. Requires Python 3, Icarus, and OpenSSL. No third-party
Python packages or network access. All binaries/mutations use a temporary
directory; logs go under the project's ignored logs/rigorous directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
AES = ["aes_primitives.sv", "aes_key_expand.sv", "aes_encrypt_block.sv"]
GHASH = ["gf128_mul.sv", "ghash_core.sv"]
ARRAY = ["pe.sv", "sysarr.sv", "buffers.sv", "secure_tags.sv", "weight_stationary_accelerator.sv"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--match", default="", help="Run only case names containing this text")
    args = parser.parse_args()
    for tool in ("iverilog", "vvp", "openssl"):
        if not shutil.which(tool):
            parser.error(f"required tool is unavailable: {tool}")
    logs = ROOT / "logs" / "rigorous"
    logs.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="ws-rigorous-") as scratch:
        scratch = Path(scratch)

        def run(name, top, sources, params=None, defines=(), plusargs=(), expected_failure=None, mutation=None):
            if args.match and args.match not in name:
                return
            started = time.monotonic()
            source_paths = [ROOT / src for src in sources]
            if mutation:
                filename, before, after = mutation
                source = (ROOT / filename).read_text()
                if before not in source:
                    raise RuntimeError(f"mutation no longer matches {filename}: {name}")
                mutated = scratch / f"{name}.sv"
                mutated.write_text(source.replace(before, after, 1))
                source_paths = [mutated if p == ROOT / filename else p for p in source_paths]
            binary = scratch / name
            compile_cmd = ["iverilog", "-g2012", "-s", top, "-o", str(binary)]
            compile_cmd += [f"-D{define}" for define in defines]
            compile_cmd += [f"-P{top}.{key}={value}" for key, value in (params or {}).items()]
            compile_cmd += [str(path) for path in source_paths]
            build = subprocess.run(compile_cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)
            output = build.stdout + build.stderr
            passed = False
            if build.returncode == 0:
                try:
                    simulation = subprocess.run(["vvp", str(binary), *plusargs], cwd=ROOT,
                                                capture_output=True, text=True, timeout=600)
                    output += simulation.stdout + simulation.stderr
                    if expected_failure:
                        passed = simulation.returncode != 0 and re.search(expected_failure, output) is not None
                    else:
                        passed = simulation.returncode == 0 and "PASS" in output and not re.search(r"FATAL:|ERROR:|\[FAIL\]", output)
                except subprocess.TimeoutExpired:
                    output += "\nFAILED: wall-clock timeout (600 seconds)\n"
            (logs / f"{name}.log").write_text(output)
            elapsed = round(time.monotonic() - started, 2)
            results.append({"case": name, "passed": passed, "seconds": elapsed,
                            "negative_control": bool(expected_failure)})
            print(f"{'PASS' if passed else 'FAIL'} {name} ({elapsed}s)", flush=True)
            if not passed:
                print(output[-5000:], flush=True)

        run("aes-primitives", "aes_primitives_tb", AES[:2] + ["aes_primitives_tb.sv"])
        run("gf128-basis", "gf128_mul_tb", ["gf128_mul.sv", "gf128_mul_tb.sv"])

        for bits in (128, 256):
            name = f"aes{bits}-openssl"
            if not args.match or args.match in name:
                # Walking-one plaintext/key inputs plus 256 fresh random pairs
                # from a fixed, public SHA256 seed. Ciphertext comes from OpenSSL.
                pairs = [(bytes(bits // 8), (1 << bit).to_bytes(16, "big")) for bit in range(128)]
                pairs += [((1 << bit).to_bytes(bits // 8, "big"), bytes(16)) for bit in range(bits)]
                for index in range(256):
                    key = hashlib.sha256(f"ws-rigorous-key-{bits}-{index}".encode()).digest()[:bits // 8]
                    block = hashlib.sha256(f"ws-rigorous-block-{bits}-{index}".encode()).digest()[:16]
                    pairs.append((key, block))
                fixture = scratch / f"aes{bits}.txt"
                with fixture.open("w") as stream:
                    for key, block in pairs:
                        cipher = subprocess.run(["openssl", "enc", f"-aes-{bits}-ecb", "-K", key.hex(), "-nopad", "-nosalt"],
                                                input=block, capture_output=True, check=True, timeout=10).stdout
                        if len(cipher) != 16:
                            raise RuntimeError("OpenSSL did not return one block")
                        stream.write(f"{key.hex()} {block.hex()} {cipher.hex()}\n")
                run(name, "aes_encrypt_block_tb", AES + ["aes_encrypt_block_tb.sv"],
                    {"AES_KEY_W": bits}, plusargs=[f"+oracle_file={fixture}"])

        for width in (128, 256, 384, 512, 1024, 2048, 4096):
            run(f"ghash-{width}", "ghash_core_tb", GHASH + ["ghash_core_tb.sv"],
                {"MEM_DATA_W": width}, plusargs=[f"+seed={1009 + width}", "+stress_iters=16"])
        for slots, bits, ports in ((1,128,1), (3,128,3), (5,256,4), (8,256,3)):
            run(f"keys-{slots}-{bits}-{ports}", "tenant_key_stress_tb",
                ["tenant_key_regfile.sv", "tenant_key_stress_tb.sv"], {"S":slots,"K":bits,"L":ports})
        for rows, cols, ports in ((1,1,1), (1,5,3), (3,1,2), (3,5,3)):
            params = {"R":rows,"C":cols,"P":ports}
            run(f"buffers-{rows}x{cols}-p{ports}", "buffers_stress_tb", ["buffers.sv","buffers_stress_tb.sv"], params)
            for width in (1,96):
                run(f"tags-{rows}x{cols}-p{ports}-t{width}", "secure_tags_stress_tb",
                    ["secure_tags.sv","secure_tags_stress_tb.sv"], dict(params,TW=width), ["ENABLE_SECURE_TAGS"])
        for banks, width in ((1,4),(3,8),(5,4)):
            run(f"pe-w{banks}-d{width}", "pe_stress_tb", ["pe.sv","pe_stress_tb.sv"],
                {"W":banks,"DW":width,"AW":2*width})
        for rows, cols, banks in ((1,1,1),(1,5,3),(3,1,5),(3,5,3)):
            run(f"array-{rows}x{cols}-w{banks}", "sysarr_stress_tb", ["pe.sv","sysarr.sv","sysarr_stress_tb.sv"],
                {"R":rows,"C":cols,"W":banks})
        for rows, cols, banks in ((1,1,1),(2,3,3),(3,1,5)):
            run(f"controller-{rows}x{cols}-w{banks}-wrap", "weight_stationary_accelerator_tb",
                ARRAY+["weight_stationary_accelerator_tb.sv"], {"ROWS":rows,"COLS":cols,"W":banks,"AW":16},
                plusargs=["+host_stress", "+random_iters=20"])
            run(f"tagged-{rows}x{cols}-w{banks}", "secure_tagging_tb", ARRAY+["secure_tagging_tb.sv"],
                {"ROWS":rows,"COLS":cols,"W":banks}, ["ENABLE_SECURE_TAGS","SECURE_TAG_TEST_HOOKS"],
                ["+stress_iters=24", f"+seed={911+rows*cols}"])

        # Invalid configurations must compile and explicitly reject at runtime.
        # Compile failures are not counted as successful negative tests.
        for name, top, sources, params, message in (
            ("aes192", "aes_encrypt_block", AES, {"AES_KEY_W":192}, "AES_KEY_W must be"),
            ("aes-round0", "aes_key_expand", AES[:2], {"ROUND":0}, "ROUND is outside"),
            ("aes-round15", "aes_key_expand", AES[:2], {"ROUND":15}, "ROUND is outside"),
            ("ghash-width", "ghash_core", GHASH, {"MEM_DATA_W":192}, "MEM_DATA_W must be"),
            ("ghash-lanes", "ghash_core", GHASH, {"LANES":2}, "derived parameters"),
            ("ghash-count", "ghash_core", GHASH, {"MEM_DATA_W":512,"COUNT_W":1}, "derived parameters"),
            ("key-width", "tenant_key_regfile", ["tenant_key_regfile.sv"], {"AES_KEY_W":192}, "AES_KEY_W must be"),
            ("key-tenant", "tenant_key_regfile", ["tenant_key_regfile.sv"], {"TENANT_ID_W":0}, "TENANT_ID_W must be"),
            ("key-slots", "tenant_key_regfile", ["tenant_key_regfile.sv"], {"NUM_KEY_SLOTS":0}, "NUM_KEY_SLOTS must be"),
            ("key-ports", "tenant_key_regfile", ["tenant_key_regfile.sv"], {"LOOKUP_PORTS":0}, "LOOKUP_PORTS must be"),
            ("key-address", "tenant_key_regfile", ["tenant_key_regfile.sv"], {"SLOT_W":1}, "SLOT_W cannot"),
        ):
            run(f"reject-{name}", top, sources, params, expected_failure=message)

        # Deliberately faulty temporary RTL proves the suite detects the
        # relevant corruption. Working-tree production sources never change.
        mutations = (
            ("aes-sbox", "aes_primitives_tb", AES[:2]+["aes_primitives_tb.sv"], {}, (),
             ("aes_primitives.sv", "8'h00: aes_sbox = 8'h63;", "8'h00: aes_sbox = 8'h62;")),
            ("gf-reduction", "gf128_mul_tb", ["gf128_mul.sv","gf128_mul_tb.sv"], {}, (),
             ("gf128_mul.sv", "128'he1000000000000000000000000000000", "128'he0000000000000000000000000000000")),
            ("ghash-lane", "ghash_core_tb", GHASH+["ghash_core_tb.sv"], {}, (),
             ("ghash_core.sv", "(lane < in_blocks)", "(lane + 1 < in_blocks)")),
            ("key-counter", "tenant_key_regfile_tb", ["tenant_key_regfile.sv","tenant_key_regfile_tb.sv"], {}, (),
             ("tenant_key_regfile.sv", "invocation_counter[reserve_iv_slot] + 1'b1", "invocation_counter[reserve_iv_slot] + 2'd2")),
            ("tag-hold", "secure_tags_stress_tb", ["secure_tags.sv","secure_tags_stress_tb.sv"], {}, ("ENABLE_SECURE_TAGS",),
             ("secure_tags.sv", "else if (advance) begin", "else begin")),
            ("buffer-clear", "buffers_stress_tb", ["buffers.sv","buffers_stress_tb.sv"], {}, (),
             ("buffers.sv", "if (reset || clear_valids) begin", "if (reset) begin")),
            ("pe-sign", "pe_stress_tb", ["pe.sv","pe_stress_tb.sv"], {"DW":4,"AW":8}, (),
             ("pe.sv", "assign product_extended = product;", "assign product_extended = {1'b0, product[PRODUCT_WIDTH-2:0]};")),
        )
        for name, top, sources, params, defines, mutation in mutations:
            run(f"detect-{name}", top, sources, params, defines, expected_failure=r"FATAL:.*(\.sv|:)", mutation=mutation)

    if not results:
        parser.error("no cases matched")
    (logs / ("summary.json" if not args.match else "selected-summary.json")).write_text(json.dumps(results, indent=2)+"\n")
    failed = [r["case"] for r in results if not r["passed"]]
    print(f"RIGOROUS: {len(results)-len(failed)}/{len(results)} cases passed; logs: {logs}", flush=True)
    if failed:
        raise SystemExit("Failed cases: " + ", ".join(failed))


if __name__ == "__main__":
    main()
