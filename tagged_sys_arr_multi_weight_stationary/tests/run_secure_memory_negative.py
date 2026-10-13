#!/usr/bin/env python3
"""Parameter guards, row-stager checks, and optional secure-memory mutations.

Invalid parameters must compile and fail at runtime with the intended guard.
Mutations only modify temporary source copies. An unchanged control must pass
first, and each mutation must fail its intended assertion: a timeout or build
failure is never credited as detection. Logs are retained for every case.
"""
import argparse
import json
import re
import shutil
import tempfile

from run_secure_memory import ROOT, SOURCES
from run_tenant_gcm_negative import run_case

PROBE_PASS = "PASS secure-memory parameter elaboration probe"
MACROS = ["-DENABLE_SECURE_TAGS", "-DENABLE_SECURE_MEMORY"]


def parameters():
    stager = "authenticated_row_stager"
    secure = "secure_memory_accelerator"
    for width in (0, 7, 9):
        yield (f"reject-stager-width{width}", stager, {"MEM_DATA_W": width},
               "authenticated_row_stager MEM_DATA_W must be a positive whole-byte width")
    yield ("reject-stager-capacity0", stager, {"MAX_RECORD_BYTES": 0},
           "authenticated_row_stager MAX_RECORD_BYTES must be positive")
    for width, capacity in ((8, 1), (24, 53), (384, 1)):
        yield (f"accept-stager-width{width}-capacity{capacity}", stager,
               {"MEM_DATA_W": width, "MAX_RECORD_BYTES": capacity}, None)
    for name in ("ROWS", "COLS", "MAX_M", "MAX_K", "MAX_N", "WEIGHTS_PER_PE"):
        yield (f"reject-secure-{name.lower()}0", secure, {name: 0},
               "Secure memory dimensions and banks must be positive")
    for name, value in (("DATA_WIDTH", 7), ("DATA_WIDTH", 9), ("ACC_WIDTH", 7),
                        ("ACC_WIDTH", 24), ("ACC_WIDTH", 256)):
        yield (f"reject-secure-{name.lower()}{value}", secure, {name: value},
               "Secure memory needs byte widths and whole accumulator words per beat")
    for width in (0, 65):
        yield (f"reject-secure-cookie{width}", secure, {"COOKIE_W": width},
               "Secure memory COOKIE_W must be 1 through 64")
    yield ("reject-secure-aes192", secure, {"AES_KEY_W": 192},
           "AES_KEY_W must be 128 or 256")
    yield ("reject-secure-bus192", secure, {"MEM_DATA_W": 192},
           "MEM_DATA_W must be a positive multiple of 128")
    yield ("reject-secure-key-slots0", secure, {"NUM_KEY_SLOTS": 0},
           "NUM_KEY_SLOTS must be positive")
    yield ("reject-secure-key-slot-width", secure, {"NUM_KEY_SLOTS": 3, "SLOT_W": 1},
           "SLOT_W cannot address every key slot")
    for bits, width, data, acc, cookie in ((128, 128, 8, 32, 1), (256, 384, 16, 64, 64)):
        yield (f"accept-secure-aes{bits}-bus{width}-minimal", secure,
               {"AES_KEY_W": bits, "MEM_DATA_W": width, "DATA_WIDTH": data,
                "ACC_WIDTH": acc, "COOKIE_W": cookie, "NUM_KEY_SLOTS": 1,
                "ROWS": 1, "COLS": 1, "MAX_M": 1, "MAX_K": 1, "MAX_N": 1}, None)


def compile_command(top, binary, paths, params=None, secure=False):
    command = ["iverilog", "-g2012"]
    if secure:
        command += MACROS
    command += ["-s", top, "-o", str(binary)]
    command += [f"-P{top}.{name}={value}" for name, value in (params or {}).items()]
    return command + [str(path) for path in paths]


def mutated_paths(scratch, name, sources, filename, before, after):
    paths = [ROOT / source for source in sources]
    if filename is None:
        return paths, None
    source = (ROOT / filename).read_text()
    if source.count(before) != 1:
        return paths, f"FAIL: mutation anchor must match exactly once in {filename}: {before}\n"
    changed = scratch / f"{name}.sv"
    changed.write_text(source.replace(before, after, 1))
    return [changed if path.name == filename else path for path in paths], None


def stager_mutations(scratch, logs, match):
    mutations = [
        ("accept-stager-mutation-baseline", None, None, None, None),
        ("detect-stager-premature-commit", "authenticated_row_stager.sv",
         "assign commit_valid = enabled && state == ACTIVE && finish_valid && successful_finish;",
         "assign commit_valid = enabled && state == ACTIVE && record_complete;",
         r"data alone never authorizes commit"),
        ("detect-stager-ignore-finish-error", "authenticated_row_stager.sv",
         "wire successful_finish = (finish_error === OK) && record_complete;",
         "wire successful_finish = record_complete;",
         r"failed record cannot publish bytes"),
        ("detect-stager-ignore-tenant", "authenticated_row_stager.sv",
         "in_tenant !== tenant_reg || in_destination !== destination_reg",
         "1'b0 || in_destination !== destination_reg",
         r"failed record cannot publish bytes"),
        ("detect-stager-ignore-destination", "authenticated_row_stager.sv",
         "in_tenant !== tenant_reg || in_destination !== destination_reg",
         "in_tenant !== tenant_reg || 1'b0",
         r"failed record cannot publish bytes"),
        ("detect-stager-early-finish-ack", "authenticated_row_stager.sv",
         "(!successful_finish || commit_ready);", "1'b1;",
         r"success holds whole record and key ownership until commit"),
    ]
    selected = [case for case in mutations if match in case[0]]
    if not selected:
        return []
    if selected[0] != mutations[0]:
        selected.insert(0, mutations[0])
    results = []
    sources = ["authenticated_row_stager.sv", "authenticated_row_stager_tb.sv"]
    for name, filename, before, after, diagnostic in selected:
        paths, error = mutated_paths(scratch, name, sources, filename, before, after)
        binary = scratch / name
        command = compile_command("authenticated_row_stager_tb", binary, paths,
                                  {"MEM_DATA_W": 128, "MAX_RECORD_BYTES": 53})
        result = run_case(name, command, binary, [], logs, expected_failure=diagnostic,
                          success="PASS STAGER", timeout=30, setup_error=error)
        results.append(result)
        if diagnostic is None and not result["passed"]:
            break
    return results


def integration_mutations(scratch, logs, match):
    from run_secure_memory import OpenSSLGCM, fixtures, nist_vectors

    mutations = [
        ("accept-secure-mutation-baseline", None, None, None, None),
        ("detect-secure-ignore-storage-cookie", "secure_memory_accelerator.sv",
         "wire acknowledge = store_ack_valid && store_ack_ready && store_ack_cookie == cookie_reg;",
         "wire acknowledge = store_ack_valid && store_ack_ready;",
         r"mismatched storage cookie cannot retire row"),
        ("detect-secure-header-retires-row", "secure_memory_accelerator.sv",
         "wire retire_row = acknowledge && (store_ack_success === 1'b1) && crypto_result_valid[2] &&",
         "wire retire_row = (acknowledge || (store_header_valid && store_header_ready)) && crypto_result_valid[2] &&",
         r"complete plaintext row and tenant tags survive until matching successful storage acknowledgement"),
        ("detect-secure-stale-config-data", "weight_stationary_accelerator.sv",
         "wire memory_zeroize = memory_fault_clear || memory_config_accept;",
         "wire memory_zeroize = memory_fault_clear;",
         r"fresh configuration erases every data-valid entry"),
    ]
    selected = [case for case in mutations if match in case[0]]
    if not selected:
        return []
    if selected[0] != mutations[0]:
        selected.insert(0, mutations[0])
    oracle = OpenSSLGCM()
    nist_vectors(oracle)
    fixture = scratch / "secure-mutation-fixtures.txt"
    fixtures(fixture, oracle, 128, 8, 32, True)
    sources = SOURCES + ["secure_memory_accelerator_tb.sv"]
    results = []
    for name, filename, before, after, diagnostic in selected:
        paths, error = mutated_paths(scratch, name, sources, filename, before, after)
        binary = scratch / name
        command = compile_command("secure_memory_accelerator_tb", binary, paths,
                                  {"AES_KEY_W": 128, "MEM_DATA_W": 128,
                                   "DATA_WIDTH": 8, "ACC_WIDTH": 32,
                                   "ROWS": 2, "COLS": 2, "WEIGHTS_PER_PE": 2}, secure=True)
        result = run_case(name, command, binary, [f"+vectors={fixture}"], logs,
                          expected_failure=diagnostic, success="PASS SECURE_MEMORY",
                          timeout=180, setup_error=error)
        results.append(result)
        if diagnostic is None and not result["passed"]:
            break
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--match", default="", help="Run case names containing this text")
    parser.add_argument("--mutations", action="store_true", help="Include temporary security regressions")
    args = parser.parse_args()
    for tool in ("iverilog", "vvp"):
        if not shutil.which(tool):
            parser.error(f"required tool is unavailable: {tool}")
    logs = ROOT / "logs/secure-memory-negative"
    logs.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="secure-memory-negative-") as temporary:
        scratch = Path(temporary)
        probe = scratch / "parameter_probe.sv"
        probe.write_text("module parameter_probe;\n"
                         f"  initial begin #1; $display(\"{PROBE_PASS}\"); $finish; end\n"
                         "endmodule\n")
        for name, top, params, diagnostic in parameters():
            if args.match not in name:
                continue
            secure = top == "secure_memory_accelerator"
            sources = SOURCES if secure else ["authenticated_row_stager.sv"]
            binary = scratch / name
            command = compile_command(top, binary, [ROOT / source for source in sources], params, secure)
            command[1:1] = ["-s", "parameter_probe"]
            command.append(str(probe))
            results.append(run_case(name, command, binary, [], logs,
                                    expected_failure=re.escape(diagnostic) if diagnostic else None,
                                    success=PROBE_PASS))
        for width in (8, 16, 128, 384):
            name = f"accept-stager-byte-oracle-width{width}"
            if args.match not in name:
                continue
            binary = scratch / name
            command = compile_command("authenticated_row_stager_tb", binary,
                                      [ROOT / "authenticated_row_stager.sv", ROOT / "authenticated_row_stager_tb.sv"],
                                      {"MEM_DATA_W": width, "MAX_RECORD_BYTES": 53})
            results.append(run_case(name, command, binary, [], logs, success="PASS STAGER"))
        if args.mutations:
            results += stager_mutations(scratch, logs, args.match)
            results += integration_mutations(scratch, logs, args.match)
    if not results:
        parser.error("no cases matched")
    (logs / ("selected-summary.json" if args.match else "summary.json")).write_text(
        json.dumps(results, indent=2) + "\n")
    failures = [result["case"] for result in results if not result["passed"]]
    print(f"SECURE MEMORY NEGATIVE: {len(results)-len(failures)}/{len(results)} cases passed; logs: {logs}")
    if failures:
        raise SystemExit("Failed cases: " + ", ".join(failures))


if __name__ == "__main__":
    main()
