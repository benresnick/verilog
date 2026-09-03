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
