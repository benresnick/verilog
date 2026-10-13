#!/usr/bin/env python3
"""Parameter guards and optional security mutations for trusted tenant GCM.

Invalid parameters must compile and then fail with the intended runtime
diagnostic. --mutations additionally uses the independent OpenSSL fixture
generator and tenant testbench to detect deliberately faulty temporary RTL.
Production RTL is never edited. Logs are retained in logs/tenant-gcm-negative.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from run_gcm_negative import output_text

ROOT = Path(__file__).resolve().parents[1]
PORT_SOURCES = ["aes_primitives.sv", "aes_key_expand.sv", "aes_encrypt_block.sv",
                "gf128_mul.sv", "ghash_core.sv", "gctr_core.sv", "aes_gcm_engine.sv",
                "tenant_gcm_port.sv"]
CLUSTER_SOURCES = PORT_SOURCES + ["tenant_key_regfile.sv", "tenant_gcm_cluster.sv"]
PROBE_PASS = "PASS tenant parameter elaboration probe"


def parameters():
    for top, label in (("tenant_gcm_port", "port"), ("tenant_gcm_cluster", "cluster")):
        yield (f"reject-{label}-aes192", top, {"AES_KEY_W": 192}, "AES_KEY_W must be 128 or 256")
        for width in (64, 192):
            yield (f"reject-{label}-width{width}", top, {"MEM_DATA_W": width},
                   "MEM_DATA_W must be a positive multiple of 128")
        yield (f"reject-{label}-capacity", top, {"MAX_TXN_BYTES": 0},
               "MAX_TXN_BYTES must be positive" if label == "port" else
               "Tenant GCM transaction capacity and key slots must be positive")
    yield ("reject-port-slot-width", "tenant_gcm_port", {"SLOT_W": 0}, "SLOT_W must be positive")
    yield ("reject-cluster-slot-count", "tenant_gcm_cluster", {"NUM_KEY_SLOTS": 0},
           "Tenant GCM transaction capacity and key slots must be positive")
    yield ("reject-cluster-slot-width", "tenant_gcm_cluster", {"NUM_KEY_SLOTS": 3, "SLOT_W": 1},
           "SLOT_W cannot address every key slot")
    for bits, slots, width in ((128, 1, 128), (256, 1, 384), (128, 3, 384), (256, 3, 128)):
        yield (f"accept-cluster-aes{bits}-slots{slots}-width{width}", "tenant_gcm_cluster",
               {"AES_KEY_W": bits, "NUM_KEY_SLOTS": slots, "MEM_DATA_W": width,
                "MAX_TXN_BYTES": 1}, None)
    for bits, width, decrypt in ((128, 128, 1), (256, 384, 0)):
        yield (f"accept-port-aes{bits}-width{width}-decrypt{decrypt}", "tenant_gcm_port",
               {"AES_KEY_W": bits, "MEM_DATA_W": width, "SLOT_W": 1,
                "MAX_TXN_BYTES": 1, "DECRYPT": decrypt}, None)


def run_case(name, command, binary, plusargs, logs, expected_failure=None, success=PROBE_PASS,
             timeout=30, setup_error=None):
    started = time.monotonic()
    passed = False
    compiled = False
    output = setup_error or ""
    if setup_error is None:
        try:
            build = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
            output = output_text(build)
            compiled = build.returncode == 0
            if compiled:
                simulation = subprocess.run(["vvp", str(binary), *plusargs], cwd=ROOT,
                                            capture_output=True, text=True, timeout=timeout)
                runtime = output_text(simulation)
                output += runtime
                if expected_failure:
                    passed = (simulation.returncode != 0 and "FATAL:" in runtime and
                              re.search(expected_failure, runtime) is not None and success not in runtime)
                else:
                    passed = (simulation.returncode == 0 and success in runtime and
                              "FATAL:" not in runtime and "ERROR:" not in runtime)
            else:
                output += "\nFAIL: compilation failure does not count as an intended rejection.\n"
        except subprocess.TimeoutExpired as error:
            output += output_text(error) + "\nFAIL: test timeout does not count as mutation detection.\n"
    elapsed = round(time.monotonic() - started, 2)
    (logs / f"{name}.log").write_text(output)
    print(f"{'PASS' if passed else 'FAIL'} {name} ({elapsed}s)", flush=True)
    if not passed:
        print(output[-4500:], flush=True)
    return {"case": name, "passed": passed, "compiled": compiled,
            "negative_control": expected_failure is not None, "seconds": elapsed}


def mutation_checks(scratch, logs, match):
    from run_tenant_gcm import OpenSSLGCM, SOURCES, nist_vectors, vectors, write_fixture

    mutations = [
        ("accept-tenant-mutation-baseline", None, None, None, None),
        ("detect-tenant-destination-binding", "tenant_gcm_port.sv", "cmd_destination};",
         "64'b0};", r"encryption uses independently predicted reserved nonce and tag|expected error0 got1"),
        ("detect-tenant-untrusted-encryption-iv", "tenant_gcm_cluster.sv",
         ".cmd_iv(IS_OUTPUT ? reserved_iv : cmd_iv[p])", ".cmd_iv(cmd_iv[p])",
         r"encryption uses independently predicted reserved nonce and tag|OpenSSL byte"),
        ("detect-tenant-early-owner-release", "tenant_gcm_port.sv",
         "assign key_busy = held_key;", "assign key_busy = held_key && state != RESULT;",
         r"busy slot protected through held result"),
        ("detect-tenant-update-start-race", "tenant_gcm_cluster.sv",
         "wire commands_enabled = !reset && !key_mutation;", "wire commands_enabled = !reset;",
         r"accepted key update globally stalls new commands"),
        ("detect-tenant-reused-nonce", "tenant_key_regfile.sv",
         "invocation_counter[reserve_iv_slot] + 1'b1", "invocation_counter[reserve_iv_slot] + 1'b0",
         r"encryption uses independently predicted reserved nonce and tag|counter|nonce"),
        ("detect-tenant-zero-owner-slot", "tenant_gcm_port.sv",
         "assign key_slot = slot_reg;", "assign key_slot = 0;",
         r"nonzero busy slot blocks its own mutation"),
    ]
    selected = [case for case in mutations if match in case[0]]
    if not selected:
        return []
    if selected[0][0] != mutations[0][0]:
        selected.insert(0, mutations[0])
    oracle = OpenSSLGCM()
    nist_vectors(oracle)
    fixture = scratch / "tenant-mutation-vectors.txt"
    # Three distinct records enable the bench's simultaneous-key scenarios;
    # record zero also spans several beats for cancellation and framing cases.
    write_fixture(fixture, vectors(oracle, 128, 128, 193, True)[:3])
    results = []
    for name, filename, before, after, diagnostic in selected:
        paths = [ROOT / source for source in SOURCES]
        setup_error = None
        if filename:
            source = (ROOT / filename).read_text()
            if source.count(before) != 1:
                setup_error = f"FAIL: mutation anchor must match exactly once in {filename}: {before}\n"
            else:
                mutated = scratch / f"{name}.sv"
                mutated.write_text(source.replace(before, after, 1))
                paths = [mutated if path.name == filename else path for path in paths]
        binary = scratch / name
        command = ["iverilog", "-g2012", "-s", "tenant_gcm_cluster_tb", "-o", str(binary),
                   "-Ptenant_gcm_cluster_tb.AES_KEY_W=128", "-Ptenant_gcm_cluster_tb.MEM_DATA_W=128",
                   "-Ptenant_gcm_cluster_tb.MAX_TXN_BYTES=193", "-Ptenant_gcm_cluster_tb.NUM_KEY_SLOTS=3"]
        command.extend(str(path) for path in paths)
        result = run_case(name, command, binary,
                          [f"+vectors={fixture}", "+tag_bits=8", "+metadata_bits=4"], logs,
                          expected_failure=diagnostic, success="PASS TENANT_GCM", timeout=240,
                          setup_error=setup_error)
        results.append(result)
        if diagnostic is None and not result["passed"]:
            # Any failure in the unchanged design invalidates the attribution
            # of subsequent failures to a deliberate mutation.
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
    logs = ROOT / "logs/tenant-gcm-negative"
    logs.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="tenant-gcm-negative-") as temporary:
        scratch = Path(temporary)
        probe = scratch / "parameter_probe.sv"
        probe.write_text("module parameter_probe;\n"
                         f"  initial begin #1; $display(\"{PROBE_PASS}\"); $finish; end\n"
                         "endmodule\n")
        for name, top, params, diagnostic in parameters():
            if args.match not in name:
                continue
            binary = scratch / name
            command = ["iverilog", "-g2012", "-s", top, "-s", "parameter_probe", "-o", str(binary)]
            command.extend(f"-P{top}.{key}={value}" for key, value in params.items())
            sources = PORT_SOURCES if top == "tenant_gcm_port" else CLUSTER_SOURCES
            command.extend(str(ROOT / source) for source in sources)
            command.append(str(probe))
            results.append(run_case(name, command, binary, [], logs,
                                    re.escape(diagnostic) if diagnostic else None))
        if args.mutations:
            results.extend(mutation_checks(scratch, logs, args.match))
    if not results:
        parser.error("no cases matched")
    summary = "selected-summary.json" if args.match else "summary.json"
    (logs / summary).write_text(json.dumps(results, indent=2) + "\n")
    failed = [result["case"] for result in results if not result["passed"]]
    print(f"TENANT GCM NEGATIVE: {len(results)-len(failed)}/{len(results)} cases passed; logs: {logs}")
    if failed:
        raise SystemExit("Failed cases: " + ", ".join(failed))


if __name__ == "__main__":
    main()
