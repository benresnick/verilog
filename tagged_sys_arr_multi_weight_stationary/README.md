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

> The accelerator's memory and result interfaces still carry plaintext.
> AES-GCM includes quarantined authenticated decryption. A trusted wrapper now
> connects three crypto paths to protected tenant keys, automatic encryption
> IV reservation, and authenticated record metadata. Accelerator buffer/tag
> adapters and DRAM record commit are not yet connected. See
> [crypto implementation status](docs/crypto-primitives.md) for their contracts
> and the remaining integration work.

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
| `docs/shared-tag-queue-timing.png` | The shared-queue timing diagram used above. |

## Build and verification

Requires Icarus Verilog with SystemVerilog support. GCM tests also require
Python 3 and a shared OpenSSL `libcrypto`; no third-party Python packages.

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

# Compile-only checks for both elaborations.
make lint
make tagged-lint

# Complete repository-local verification gate.
make full-ci

# Extended independent oracles, parameter/stress campaigns, and mutation checks.
# Also requires the OpenSSL CLI; no Python packages or network access.
make rigorous-ci
```

The [verification matrix](docs/verification.md) lists the per-module checks,
reproduction commands, and limits of simulation coverage.

The secure suite covers one, two, three, and per-row-distinct users; K and N
tiling; partial N tiles; resident-weight banks; full capacities; back-to-back
jobs; result backpressure; reset; trusted abort; missing tags; conflicting row
tags; and verification-only fault injection for missing feedback metadata and
invalid commit taps.

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

- The accelerator does not yet encrypt or authenticate its memory transfers.
  The crypto cluster now includes protected key/nonce handling, authenticated
  metadata, three private engines, and decryption quarantine. DRAM record
  framing and atomic authenticated buffer/tenant-tag commit still need wiring.
- Architectural connectivity prevents ordinary software from using tags; it
  does not address physical probing, scan access, fault injection, or
  side-channel leakage.
- The trusted ports should be connected through a production trusted-ingress /
  trusted-egress wrapper before integration into a software-visible system.
- No synthesis/area comparison is included because no synthesis tool is part
  of this repository-local flow.
