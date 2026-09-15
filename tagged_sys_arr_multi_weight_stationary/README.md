# Parameterized Weight-Stationary Systolic Array

A synthesizable SystemVerilog matrix-multiplication accelerator that computes
signed `C = A × B` using a parameterized weight-stationary systolic array.

For an interactive explanation of the mapping, loading order, and dataflow,
see the [Weight-Stationary Array Lab walkthrough](https://weight-stationary-array-lab.benjamin-resnick1.chatgpt.site/).

## Architecture

The accelerator uses a blocking weight-stationary schedule:

- **PE array:** physical rows represent K indices; physical columns represent
  a tile of N output columns.
- **IBuff:** replays the selected A slice with row skew.
- **WBuff:** loads weights top-to-bottom through each column, issuing target
  rows bottom-first so every PE captures the intended stationary weight slot.
- **OBuff:** stores partial sums between local-bank and resident-K-set passes;
  it feeds each saved partial back into the top edge of the corresponding PE
  column.
- **Controller:** advances N tiles, resident K sets, local weight banks, and
  result-stream coordinates.

`WEIGHTS_PER_PE` controls the number of resident stationary-weight slots in
each PE.  One resident K set covers:

```text
ARRAY_ROWS × WEIGHTS_PER_PE
```

logical K values.  Larger K values are handled by loading later resident sets;
larger N values are handled by output-column tiles.

## Main files

| File | Purpose |
| --- | --- |
| `pe.sv` | Banked stationary-weight processing element. |
| `sysarr.sv` | Generated PE mesh and physical edge wiring. |
| `buffers.sv` | Multi-read IBuff/WBuff and multi-write OBuff primitives. |
| `weight_stationary_accelerator.sv` | Host interface, buffers, scheduler, and array integration. |
| `*_tb.sv` | Self-checking PE, buffer, and end-to-end tests. |
| `Makefile` | Repeatable simulation, sweep, and CI commands. |

## Host interface

While idle, `config_ready`, `a_ready`, and `b_ready` are asserted. A host:

1. Writes positive runtime dimensions with `config_we`.
2. Writes every required `A[m,k]` with `a_we` and `B[k,n]` with `b_we`.
3. Pulses `start`.
4. Accepts results through `result_valid` / `result_ready`.

Each result includes `result_row`, `result_col`, and signed `result_data`.
`done` pulses only after the last result handshake. Missing data, zero-sized
jobs, and out-of-capacity dimensions are rejected with `job_error`.

## Running tests

Requires Icarus Verilog with SystemVerilog support (`iverilog -g2012`).

```sh
# Core regression: PE, buffers, W=1..5, array-shape, and corner sweeps
make regress

# Full CI regression, including two 10-case constrained-random sweeps
make ci

# Run only the extra randomized parameter configurations
make random-sweep

# Parameter corner cases: ROWS=1 and non-power-of-two dimensions
make sweep

# Extra reproducible random cases for WEIGHTS_PER_PE=4
make random-w4

# Detailed OBuff commit logging or a VCD waveform
make verbose-w4
make vcd-w1
```

## Secure 96-bit row tags

The normal targets build the original public numerical interface.  A separate
compile-time build enables the protected metadata plane:

```sh
make tagged
make tagged-sweep
```

This passes `-DENABLE_SECURE_TAGS`, which adds only trusted-integration ports:
`trusted_tag_we`, `trusted_tag_row`, and `trusted_tag_data` at ingress, plus
trusted egress tag observation and a sanitized `security_fault` status.  They
are deliberately absent from the untagged build and must not be connected to a
software/MMIO interface.  The trusted tag binds atomically to each A write;
weights are public (tag zero).  A single `ROWS + COLS - 1` stage queue carries
row tags, with output-column `pc` tapping stage `ROWS - 1 + pc`.  A protected
OBuff tag store mirrors concurrent numerical commits and validates every
partial-sum feedback and final export.  Missing, stale, or incompatible tags
latch `security_fault`, flush protected state, and suppress output until reset.

This RTL connectivity models architectural isolation, not protection against
physical probing, scan access, or side-channel attacks.

`trusted_abort` is a trusted-only cancellation input in the tagged build. It
flushes queue and secure-OBuff validity and latches the sanitized fault status;
reset is required before accepting another request. `SECURE_TAG_TEST_HOOKS` is
used only by the simulation regression to inject missing-feedback-tag and
invalid-tap conditions. It is never defined by normal or synthesis targets.

The end-to-end testbench includes directed, signed, zero, sparse, partial-tile,
multiple-K-set, result-backpressure, reset-abort, invalid-job, and seeded
randomized cases. The build sweeps `WEIGHTS_PER_PE=1..5`, width-one and
non-power-of-two arrays, tall/narrow arrays, and two additional randomized
array/weight-capacity configurations. It prints high-level phases plus
tile/set/bank progress while running.

## Parameters

Important top-level parameters include:

| Parameter | Meaning |
| --- | --- |
| `ROWS` | Number of physical PE rows. |
| `COLS` | Number of physical PE columns. |
| `WEIGHTS_PER_PE` | Resident stationary-weight slots per PE. |
| `DATA_WIDTH` | Signed activation and weight width. |
| `ACC_WIDTH` | Signed partial-sum/result width. |
| `MAX_M`, `MAX_K`, `MAX_N` | Bounded matrix-storage capacities. |

Choose `ACC_WIDTH` large enough for the intended operand range and maximum K.
For full-precision signed products, it must be at least `2 * DATA_WIDTH`.
