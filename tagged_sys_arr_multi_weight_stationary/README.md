# Secure-Tagged Weight-Stationary Systolic Array

This directory contains a parameterized SystemVerilog matrix-multiplication
accelerator with a compile-time optional, 96-bit protected ownership-tag plane.
It computes signed matrix multiplication:

```text
C[m,n] = sum(A[m,k] * B[k,n])
```

The numerical design is weight-stationary: selected weights remain in PE-local
storage, activations move left-to-right, and partial sums move top-to-bottom.
The tagged build proves that each live partial sum and final result remains
associated with the trusted tag assigned to its source activation row.

## Three builds from one source

| Build | Defines | Top module | What it adds |
| --- | --- | --- | --- |
| Plain | none | `weight_stationary_accelerator` | The numerical baseline. No tag or crypto logic is elaborated. |
| Tagged | `ENABLE_SECURE_TAGS` | `weight_stationary_accelerator` | A 96-bit ownership tag per A row, carried beside the math and stored with every C entry; any mismatch raises a sticky, fail-closed `security_fault`. Interfaces stay plaintext. |
| Secure memory | `ENABLE_SECURE_TAGS` + `ENABLE_SECURE_MEMORY` | `secure_memory_accelerator` | A and B arrive only as authenticated AES-GCM row records; C leaves only as encrypted records, retired after a matching storage acknowledgement. The tenant ID that authenticates a record becomes its row's tag. |

Tags keep tenants apart inside the chip; encryption protects them from anyone
who can read or modify memory. See [secure memory](docs/secure-memory.md) and
[crypto implementation status](docs/crypto-primitives.md).

## Status (14 Oct 2026)

- `make full-ci` and `make rigorous-ci` pass under Icarus Verilog 13, and
  Verilator 5 lint is clean on all three builds.
- Formal checks found a race in the tagged build: a configure and a `start` on
  the same edge launched a job on the epoch the configure had just erased.
  It is fixed (a start on a configure edge is refused) with a regression test,
  and the tagged-core properties are now proved at two array shapes.
- Blind tests written only from this spec, with no access to the RTL, found no
  violations on the current design. They did find flushed results lingering on
  the tagged result port while `result_valid` was low; the port now reads zero
  without a valid result.
- The main open gap is replay freshness: an old but valid record for the same
  tenant, row and length still authenticates. See
  [Limitations](#limitations-and-intended-next-integration).

## What the protected tag plane does

- Trusted ingress binds one opaque 96-bit tag to every logical `A[m,*]` row.
- Public stationary weights always have implicit `TAG 0`.
- One shared tag queue advances in lockstep with the numerical compute pass.
- Each physical output column observes a read-only tap into that same queue.
- A protected OBuff tag store mirrors every numerical OBuff commit, including
  concurrent diagonal commits and retained partial sums across K passes.
- Feedback is permitted only when the retained partial tag matches the incoming
  row tag. Missing or incompatible metadata causes a sticky `security_fault`.
- Faulted work is flushed and final result export is suppressed until reset.

There are no tag registers inside every PE. The arithmetic mesh remains a
numerical data path; protected ownership travels in parallel and rejoins each
result at OBuff.

## Four-cycle 2x2 timing example

The diagram shows two users sharing one physical 2x2 array. Blue row A and red
row B carry distinct opaque tags through exactly one queue. A tap observes its
queue stage without consuming it, so the same tag can reach a later column on
the following cycle.

![Shared tag queue timing: two protected users on a 2x2 array](docs/shared-tag-queue-timing.png)

For an array with `ROWS = R` and `COLS = C`:

```text
queue depth        = R + C - 1
tap for column pc  = queue stage (R - 1 + pc)
```

The queue receives one row-tag packet per issued logical row; bubbles are
preserved. For the numerical schedule used here, row `m` commits at column
`pc` on compute cycle `m + R + pc`, matching the tap above. Partial final N
tiles mask inactive columns, so an inactive tap cannot write protected state.

## Trust boundary and interfaces

### Normal build

Without `ENABLE_SECURE_TAGS`, the top level preserves the ordinary numerical
host interface:

1. While idle, write dimensions with `config_we`.
2. Write every `A[m,k]` with `a_we` and every `B[k,n]` with `b_we`.
3. Pulse `start`.
4. Receive coordinates and values using `result_valid` / `result_ready`.

The disabled elaboration contains no secure tag queue, tag memory, tag checks,
or trusted tag ports.

### Tagged build

Defining `ENABLE_SECURE_TAGS` adds a trusted integration interface:

| Signal | Direction | Meaning |
| --- | --- | --- |
| `trusted_tag_we` | in | Trusted tag-binding event, simultaneous with an A write. |
| `trusted_tag_row` | in | Logical activation row being bound. |
| `trusted_tag_data[95:0]` | in | Opaque authenticated ownership/context tag. |
| `trusted_abort` | in | Trusted cancellation; flushes protected work. |
| `trusted_result_tag_valid` | out | Trusted final-result metadata is valid. |
| `trusted_result_tag[95:0]` | out | Opaque tag paired with the public numerical result. |
| `security_fault` | out | Sanitized sticky status; never reveals a tag value. |

These trusted signals must **not** be mapped into host MMIO, DMA descriptors,
debug readback, or a software-controlled register file. The tag memories are
accessible only to internal trusted scheduler, queue, policy, and egress logic.

Each accepted `config_we` starts a new ownership epoch: it erases every row tag
**and every A element's written status**, so the host must rewrite all of A
(with its tags) before the next `start`. Without this, a new owner could bind a
row with a single write and inherit the previous owner's remaining elements.
Public B elements stay valid across epochs. A configure and an A write on the
same clock edge belong to the new epoch. While `security_fault` is set, the
ready outputs are low and configure, A and B writes are ignored.

Edge cases in the tagged build:

- A `start` on the same edge as an accepted `config_we` is refused with
  `job_error`: the configure clears every A binding, so there is nothing valid
  to run.
- An A write without a simultaneous `trusted_tag_we` is ignored. Only trusted
  ingress can place activation data.
- Binding a row to a different tag within one epoch raises `security_fault`.
  A change of owner needs a new configure.
- `start` is checked against the state before its edge. An A or B write on the
  start edge does not make a refused job runnable. When the job does start, a
  same-owner A write on that edge is included in it.
- `trusted_abort` flushes all work and raises the sticky `security_fault`, even
  when idle. Only `reset` returns the accelerator to service.
- A result handshake on the same edge as `trusted_abort` or `reset` completes.
  Nothing is exported after that edge.
- `result_row`, `result_col`, `result_data` and `trusted_result_tag` read zero
  whenever `result_valid` is low. OBuff keeps partial sums and flushed results
  across abort and reset, and the port never shows them.

In every build, host writes whose coordinates exceed `MAX_M`, `MAX_K` or `MAX_N`
are ignored. The coordinate ports can encode those values, and without the range
check a synthesized buffer would truncate the address and overwrite a real row.

## Tag policy

The baseline policy is deliberately narrow:

- A first contribution starts with no OBuff tag and resolves to its row tag.
- A later contribution requires a valid stored OBuff tag equal to that row tag.
- `TAG 0` weights are public and compatible with any protected row tag.
- Different nonzero tags, a missing tag for a valid partial, an invalid commit
  tap, or an export lacking a tag all fail closed.

The RTL does not inspect fields inside a tag. It stores, compares, and propagates
the entire 96-bit value as opaque metadata.

## Directory layout

| File | Purpose |
| --- | --- |
| `weight_stationary_accelerator.sv` | Numerical controller plus tagged integration and fault handling. |
| `secure_tags.sv` | Tag policy resolver, single shared queue, and protected OBuff tag store. |
| `pe.sv`, `sysarr.sv` | Banked stationary-weight PE and generated numerical mesh. |
| `buffers.sv` | IBuff, WBuff, and numerical OBuff primitives. |
| `secure_tagging_tb.sv` | End-to-end multi-user, tiling, fault, reset, abort, and randomized regression. |
| `secure_tags_tb.sv` | Unit tests for policy resolution, queue timing, and tag-store concurrency. |
| `tenant_key_regfile.sv`, `tenant_key_regfile_tb.sv` | Trusted key provisioning, lookup, IV reservation, and adversarial unit tests. |
| `aes_primitives.sv`, `aes_key_expand.sv`, `aes_encrypt_block.sv` | Pipelined forward AES-128/256 and rolling key expansion. |
| `aes_encrypt_block_tb.sv` | Independent AES vectors, throughput, backpressure, and zeroization checks. |
| `gf128_mul.sv`, `ghash_core.sv`, `ghash_core_tb.sv` | Ordered wide GHASH primitive and independent arithmetic/NIST-vector tests. |
| `gctr_core.sv`, `gctr_core_tb.sv` | Wide pipelined counter transform, partial bytes, counter limits, and independent vectors. |
| `aes_gcm_engine.sv`, `aes_gcm_engine_tb.sv` | Bounded AES-GCM encryption/decryption, AAD framing, quarantine, and adversarial stream tests. |
| `tests/run_gcm.py`, `tests/run_gcm_negative.py` | Independent OpenSSL EVP GCM oracle and invalid-configuration checks. |
| `tenant_gcm_port.sv`, `tenant_gcm_cluster.sv` | Three trusted tenant-aware crypto paths, shared key management, fresh encryption IVs, and automatic authenticated metadata. |
| `tenant_gcm_cluster_tb.sv`, `tests/run_tenant_gcm.py`, `tests/run_tenant_gcm_negative.py` | Independent record oracle, concurrent tenants, key lifecycle/nonce races, tampering, and negative controls. |
| `weight_stationary_accelerator_tb.sv` | Original numerical end-to-end regression. |
| `pe_tb.sv`, `pe_stress_tb.sv`, `buffers_tb.sv`, `buffers_stress_tb.sv`, `sysarr_stress_tb.sv` | Unit and stress benches for the PE, the buffers, and the generated mesh. |
| `secure_tags_stress_tb.sv` | Randomized stress of the shared tag queue and tag store. |
| `aes_primitives_tb.sv`, `gf128_mul_tb.sv`, `tenant_key_stress_tb.sv` | Primitive unit tests and key-file stress. |
| `tests/run_rigorous.py` | Extended campaign: independent AES oracle, parameter and stress sweeps, configuration rejections, and mutation controls. |
| `authenticated_row_stager.sv`, `authenticated_row_stager_tb.sv` | Collects an authenticated row and commits it to IBuff/WBuff atomically. |
| `secure_memory_accelerator.sv` | Secure-memory top level: encrypted A/B loads, tagged compute, encrypted C stores with acknowledgement-gated retirement. |
| `secure_memory_accelerator_tb.sv`, `tests/run_secure_memory.py`, `tests/run_secure_memory_negative.py` | End-to-end OpenSSL record oracle, tampering, cancellation, storage retry, reset/abort lifecycle, and mutation controls. |
| `verilator_waivers.vlt` | Documented, narrowly scoped waivers for `make verilator-lint`. |
| `docs/shared-tag-queue-timing.png` | The shared-queue timing diagram used above. |

## How it is verified

Every risk below is covered by at least two independent methods.

| Method | How | Result |
| --- | --- | --- |
| Directed and random simulation | Each output is compared with an independent model: a plain matrix formula, never a copy of the RTL schedule. | Plain build 24 cases on 9 shapes plus random sweeps; tagged build 30 cases on 6 shapes. |
| In-simulation monitors | `$fatal` assertions in the RTL and testbenches check scheduler and security invariants on every cycle. | No violations. |
| Crypto oracles | AES, GHASH, GCTR and GCM against NIST vectors and OpenSSL EVP, including forged tags, bad framing and cancellation. | 2,432 GCM transactions, 828 forged-tag rejections; 3,522 tenant-wrapper transactions. |
| End to end | Python seals A and B records with OpenSSL; the RTL decrypts, computes and re-encrypts C; Python opens C with OpenSSL and checks it against its own matrix multiply. | 4 configurations, 440k to 514k checks each. |
| Mutation | A known bug is planted in a copy of the RTL and the suite must fail. | 25 planted bugs, 25 caught (`make rigorous-ci`). |
| Formal (outside the make flow) | Yosys to AIGER, ABC PDR/BMC; every input free after reset. | Row stager S1–S4 proved; tagged core T1–T4 and P1–P3 proved at 2×2 and 2×3 after the race fix; key-file IV reuse bounded to depth 9 under the provisioning contract. |
| Blind tests (outside the make flow) | A red team and a random-command fuzzer with its own Python security model, written from the spec text, a threat model and the port list, never the RTL. | About 75 attacks on 7 shapes and 5,000 fuzz runs of 500 cycles: no violations. Both rediscovered the race on the pre-fix RTL. |
| Coverage (Verilator) | Repository testbenches with coverage enabled, RTL only. | About 98% of lines and 96% of branches on the plain and tagged builds; every miss is defensive code. |

The formal, blind, coverage and synthesis harnesses are not part of this
directory's make flow; their results are recorded here and in the
[verification matrix](docs/verification.md).

## Build and verification

Requires Icarus Verilog 13 or newer (the suite is verified with 13.0; the
Ubuntu-packaged 12.0 drops values on unpacked-array output ports and hangs
`run-w1`). GCM and secure-memory tests also require Python 3 and a shared
OpenSSL `libcrypto`; no third-party Python packages. `make verilator-lint`
additionally needs Verilator 5.

```sh
cd tagged_sys_arr_multi_weight_stationary

# Numerical baseline: macro disabled, no tag hardware elaborated.
make ci

# Tagged unit regression and default end-to-end secure suite.
make test-secure-tags
make tagged

# Tagged shape/weight sweep: 1x1, 1x4, 2x2 W=1/W=4, 3x5, and 4x3.
make tagged-sweep

# Key file, AES, GHASH, GCTR, and independent AES-GCM verification.
make test-crypto

# GCM-only oracle/tamper/framing suite and 4096-bit bus smoke sweep.
make test-gcm
make test-gcm-wide

# Trusted key/nonce integration and three independent crypto paths.
make test-tenant-gcm
make test-tenant-gcm-mutations

# Encrypted-record accelerator, end to end against OpenSSL.
make test-secure-memory
make test-secure-memory-mutations

# Compile-only checks for all elaborations, plus Verilator lint.
make lint
make tagged-lint
make secure-memory-lint
make verilator-lint

# Complete repository-local verification gate.
make full-ci

# Extended independent oracles, parameter/stress campaigns, and mutation checks.
# Also requires the OpenSSL CLI; no Python packages or network access.
make rigorous-ci
```

The [verification matrix](docs/verification.md) lists the per-module checks,
reproduction commands, and limits of simulation coverage.

The tagged suite (30 cases on each of 6 shapes) covers one, two, three, and
per-row-distinct users; K and N tiling; partial N tiles; resident-weight banks;
full capacities; back-to-back jobs; result backpressure; reset; trusted abort;
missing tags; conflicting row tags; epoch isolation; out-of-range host writes;
same-edge configure/A-write and configure/start; a blank result port after
abort or reset; and verification-only fault injection for missing feedback
metadata and invalid commit taps. Monitors check on every cycle that each
export carries a valid tag, nothing is exported while faulted, a stalled result
does not change, and the result port reads zero without `result_valid`.

`SECURE_TAG_TEST_HOOKS` is defined only by tagged simulation targets. It adds
internal verification hooks, not production ports, for negative testing.

## Parameters

| Parameter | Meaning |
| --- | --- |
| `ROWS`, `COLS` | Physical PE-array shape. |
| `WEIGHTS_PER_PE` | Number of resident stationary-weight slots per PE. |
| `DATA_WIDTH`, `ACC_WIDTH` | Signed operand and accumulated-result widths. |
| `MAX_M`, `MAX_K`, `MAX_N` | Bounded logical matrix capacities. |
| `TAG_WIDTH` | Protected tag width; defaults to 96. |

`WEIGHTS_PER_PE` affects local weight capacity and reload frequency. It does
not change queue depth or tap positions for a single compute pass.

## Limitations and intended next integration

- No replay freshness: record authentication binds tenant, type, length and
  row, but not time, so an old valid record for the same context is accepted.
  Candidate fixes are a job epoch in the AAD, a fresh key per job, or per-row
  versions.
- Only the secure-memory build encrypts and authenticates memory transfers;
  the plain and tagged builds remain plaintext at their interfaces.
- The tenant key file is volatile. The trusted provisioner must never restart
  a retired key/IV sequence after reset or power loss (see
  [crypto implementation status](docs/crypto-primitives.md)).
- Architectural connectivity prevents ordinary software from using tags; it
  does not address physical probing, scan access, fault injection, or
  side-channel leakage.
- The trusted ports should be connected through a production trusted-ingress /
  trusted-egress wrapper before integration into a software-visible system.
- Synthesis is not part of the repository flow. Out-of-repo Yosys/nextpnr
  estimates for ECP5 are FPGA-only: the plain build closes at 33.5 MHz, and the
  default secure build (about 647k LUT4) is far beyond a single ECP5. There is
  no ASIC flow, SRAM macro, or power estimate.
- The tagged build stores a full 96-bit tag beside every C entry, which
  dominates its area; one tag per row would carry the same ownership.
- `trusted_abort` always leaves a sticky fault, so recovery needs a reset.
