#!/usr/bin/env python3
"""Check GCTR/GCM parameter guards and legal minimal-capacity elaboration.

Requires Python 3, Icarus, and vvp. Invalid configurations must compile and
then fail at runtime with their specific diagnostic: compiler failures never
count as a successful rejection. Binaries use a temporary directory; logs
and the result summary remain under logs/gcm-negative.

With --mutations, additionally prove that the independent GCM testbench
detects deliberately faulty temporary RTL. That mode also needs the shared
OpenSSL libcrypto used by tests/run_gcm.py; production sources are not edited.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
AES = ["aes_primitives.sv", "aes_key_expand.sv", "aes_encrypt_block.sv"]
SOURCES = {
    "gctr_core": AES + ["gctr_core.sv"],
    "aes_gcm_engine": AES + ["gf128_mul.sv", "ghash_core.sv", "gctr_core.sv",
                             "aes_gcm_engine.sv"],
}
PROBE_PASS = "PASS parameter elaboration probe"


def configurations():
    for top, label in (("gctr_core", "gctr"), ("aes_gcm_engine", "gcm")):
        yield (f"reject-{label}-aes192", top, {"AES_KEY_W": 192},
               "AES_KEY_W must be 128 or 256")
        # Exercise both the minimum-width and divisibility requirements.
        for width in (64, 192):
            yield (f"reject-{label}-width{width}", top, {"MEM_DATA_W": width},
                   "MEM_DATA_W must be a positive multiple of 128")
    for parameter, value in (("MAX_TXN_BYTES", 0), ("MAX_AAD_BYTES", -1)):
        yield (f"reject-gcm-{parameter.lower()}", "aes_gcm_engine", {parameter: value},
               "AES-GCM byte capacities must be positive payload and nonnegative AAD")
    # Zero-length AAD capacity is legal. One payload byte must work even when
    # the memory beat is wider, including a non-power-of-two number of lanes.
    for bits in (128, 256):
        for width in (128, 384):
            yield (f"accept-gcm-minimal-aes{bits}-width{width}", "aes_gcm_engine",
                   {"AES_KEY_W": bits, "MEM_DATA_W": width,
                    "MAX_TXN_BYTES": 1, "MAX_AAD_BYTES": 0}, None)


def output_text(result):
    """subprocess timeout output may be bytes even with text=True."""
    chunks = []
    for chunk in (result.stdout, result.stderr):
        if chunk:
            chunks.append(chunk.decode(errors="replace") if isinstance(chunk, bytes) else chunk)
    return "".join(chunks)


def mutation_checks(scratch, logs, match):
    # Reuse fixture generation only, never RTL, for expected cryptographic
    # answers. Imports remain optional for the parameter-only standard-library
    # campaign, which does not require OpenSSL.
    from run_gcm import OpenSSLGCM, SOURCES as GCM_SOURCES, nist_vectors, vector_cases, write_fixture

    cases = [
        ("accept-gcm-mutation-baseline", None, None, None),
        ("detect-gcm-authentication-bypass", "(authentication_success !== 1'b1)", "1'b0",
         r"failed decrypt never exposes plaintext"),
        ("detect-gcm-plaintext-ghash", "hash_in_data = masked_data(in_data, in_keep);",
         "hash_in_data = ctr_out_data;", r"result error expected 0 got 1"),
        ("detect-gcm-omitted-aad-length",
         "{29'b0,aad_total,3'b0,29'b0,payload_total,3'b0}",
         "{64'b0,29'b0,payload_total,3'b0}", r"OpenSSL GCM tag expected"),
        ("detect-gcm-unchecked-payload-last",
         "in_last != (payload_remaining <= MEM_BYTES)", "1'b0",
         r"output last matches declared length|result error expected 2 got 0"),
    ]
    selected = [case for case in cases if match in case[0]]
    if not selected:
        return []
    # Always validate the same unmodified configuration before attributing
    # failures to a mutation, including when selecting one case with --match.
    if selected[0][0] != cases[0][0]:
        selected.insert(0, cases[0])
    oracle = OpenSSLGCM()
    fixture = scratch / "mutation-vectors.txt"
    generated = vector_cases(oracle, nist_vectors(oracle), 128, 128, quick=True)
    # Index two drives adversarial cases; index three must contain multiple
    # beats to exercise the bench's continuous-throughput coverage guard.
    fixture_cases = generated[:3] + [next(case for case in generated[3:]
                                        if len(case["plaintext"]) > 16)]
    write_fixture(fixture, fixture_cases)
    engine_source = (ROOT / "aes_gcm_engine.sv").read_text()
    results = []
    for name, before, after, expected_failure in selected:
        started = time.monotonic()
        source_paths = [ROOT / source for source in GCM_SOURCES]
        output = ""
        compiled = False
        passed = False
        if before and engine_source.count(before) != 1:
            output = f"FAIL: mutation anchor must match exactly once: {before}\n"
        else:
            if before:
                mutated = scratch / f"{name}.sv"
                mutated.write_text(engine_source.replace(before, after, 1))
                source_paths = [mutated if path.name == "aes_gcm_engine.sv" else path
                                for path in source_paths]
            binary = scratch / name
            command = ["iverilog", "-g2012", "-s", "aes_gcm_engine_tb", "-o", str(binary),
                       "-Paes_gcm_engine_tb.AES_KEY_W=128", "-Paes_gcm_engine_tb.MEM_DATA_W=128"]
            command.extend(str(path) for path in source_paths)
            try:
                build = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
                output = output_text(build)
                compiled = build.returncode == 0
                if compiled:
                    simulation = subprocess.run(["vvp", str(binary), f"+vectors={fixture}", "+tag_bits=8"],
                                                cwd=ROOT, capture_output=True, text=True, timeout=180)
                    runtime_output = output_text(simulation)
                    output += runtime_output
                    if expected_failure:
                        passed = (simulation.returncode != 0 and "FATAL:" in runtime_output and
                                  re.search(expected_failure, runtime_output) is not None)
                    else:
                        passed = (simulation.returncode == 0 and "PASS GCM" in runtime_output and
                                  "FATAL:" not in runtime_output and "ERROR:" not in runtime_output)
                else:
                    output += "\nFAIL: mutation compile failure is not a detection.\n"
            except subprocess.TimeoutExpired as error:
                output += output_text(error) + "\nFAIL: mutation check timed out.\n"
        elapsed = round(time.monotonic() - started, 2)
        (logs / f"{name}.log").write_text(output)
        results.append({"case": name, "passed": passed, "compiled": compiled,
                        "negative_control": expected_failure is not None, "seconds": elapsed})
        print(f"{'PASS' if passed else 'FAIL'} {name} ({elapsed}s)", flush=True)
        if not passed:
            print(output[-4000:], flush=True)
            if expected_failure is None:
                # A broken baseline invalidates the attribution of any later
                # failure to intentionally corrupted RTL.
                break
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--match", default="", help="Run case names containing this text")
    parser.add_argument("--mutations", action="store_true", help="Also test temporary security regressions")
    args = parser.parse_args()
    for tool in ("iverilog", "vvp"):
        if not shutil.which(tool):
            parser.error(f"required tool is unavailable: {tool}")
    selected = [case for case in configurations() if args.match in case[0]]
    if not selected and not args.mutations:
        parser.error("no cases matched")
    logs = ROOT / "logs/gcm-negative"
    logs.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="ws-gcm-negative-") as temporary:
        scratch = Path(temporary)
        probe = scratch / "parameter_probe.sv"
        # A second root guarantees a bounded successful simulation and proves
        # that all time-zero parameter checks completed without a fatal error.
        probe.write_text("module parameter_probe;\n"
                         f"  initial begin #1; $display(\"{PROBE_PASS}\"); $finish; end\n"
                         "endmodule\n")
        for name, top, parameters, diagnostic in selected:
            started = time.monotonic()
            binary = scratch / name
            command = ["iverilog", "-g2012", "-s", top, "-s", "parameter_probe",
                       "-o", str(binary)]
            command.extend(f"-P{top}.{key}={value}" for key, value in parameters.items())
            command.extend(str(ROOT / source) for source in SOURCES[top])
            command.append(str(probe))
            passed = False
            compiled = False
            output = ""
            try:
                build = subprocess.run(command, cwd=ROOT, capture_output=True,
                                       text=True, timeout=120)
                output = output_text(build)
                compiled = build.returncode == 0
                if compiled:
                    simulation = subprocess.run(["vvp", str(binary)], cwd=ROOT,
                                                capture_output=True, text=True, timeout=30)
                    runtime_output = output_text(simulation)
                    output += runtime_output
                    if diagnostic:
                        passed = (simulation.returncode != 0 and "FATAL:" in runtime_output
                                  and diagnostic in runtime_output and PROBE_PASS not in runtime_output)
                    else:
                        passed = (simulation.returncode == 0 and PROBE_PASS in runtime_output
                                  and "FATAL:" not in runtime_output and "ERROR:" not in runtime_output)
                else:
                    output += "\nFAIL: compilation failed; this does not count as parameter rejection.\n"
            except subprocess.TimeoutExpired as error:
                output += output_text(error) + "\nFAIL: parameter check timed out.\n"
            elapsed = round(time.monotonic() - started, 2)
            (logs / f"{name}.log").write_text(output)
            results.append({"case": name, "passed": passed, "compiled": compiled,
                            "negative_control": diagnostic is not None, "seconds": elapsed})
            print(f"{'PASS' if passed else 'FAIL'} {name} ({elapsed}s)", flush=True)
            if not passed:
                print(output[-4000:], flush=True)
        if args.mutations:
            results.extend(mutation_checks(scratch, logs, args.match))
    if not results:
        parser.error("no cases matched")
    summary = "selected-summary.json" if args.match else "summary.json"
    (logs / summary).write_text(json.dumps(results, indent=2) + "\n")
    failed = [result["case"] for result in results if not result["passed"]]
    print(f"GCM NEGATIVE: {len(results) - len(failed)}/{len(results)} cases passed; logs: {logs}")
    if failed:
        raise SystemExit("Failed cases: " + ", ".join(failed))


if __name__ == "__main__":
    main()
