# Verification gate for the tagged accelerator, AES-GCM, and encrypted memory

The scope is every production module in `tagged_sys_arr_multi_weight_stationary`,
including the AES primitives package. Historical accelerator directories are
separate prototypes; their working-tree moves are not part of this change.
The gate covers the GCM transaction engine, its three-path trusted tenant
wrapper, the accelerator, and the secure-memory integration: encrypted DRAM
records loaded through the authenticated row stager into IBuff/WBuff and their
row tags, tagged computation, and encrypted output records retired by storage
acknowledgement.

```sh
cd tagged_sys_arr_multi_weight_stationary
make rigorous-ci
```

`rigorous-ci` runs the existing numerical/tagged/crypto regression, the extended
campaign, wide GCM smoke tests, and all top-level compile configurations.
Requirements: Icarus Verilog 13 or newer (results below are from 13.0; the
Ubuntu-packaged 12.0 drops values on unpacked-array output ports and hangs
`run-w1`), Python 3, the OpenSSL CLI, and a shared OpenSSL `libcrypto` for the
EVP GCM oracle. `make verilator-lint` additionally needs Verilator 5. No Python
packages or network are required.

The existing extended campaign passed **58/58 cases**, including all 11
configuration rejections and all seven mutation controls. The OpenSSL campaigns
checked 812 AES-128 and 944 AES-256 completed blocks including embedded vectors;
the 4096-bit GHASH stress case checked 68 completed messages.
The standalone GCTR sweep passed 448 transactions across both key sizes and
128/384/512-bit buses. All 17 GCM configuration/mutation checks passed.
The full GCM sweep passed all six configurations: **2,288 transactions** from
496 EVP vector cases, including 828 authentication rejections, 132 framing
rejections, 48 oversized commands, 144 cancellations, and 124 continuous bursts.
Both 4096-bit smoke configurations also passed, adding 144 transactions and
eight continuous bursts. Total GCM coverage is **2,432 transactions**; the wide
smoke scope is detailed below. Baseline, tagged, and GCM compile checks passed.

The trusted tenant-wrapper sweep passed **8/8 configurations**, checking
**3,522 transactions** from 512 independent OpenSSL records: 2,090 successful
transactions and 1,432 expected rejections, plus 160 cancellation scenarios.
The default eight-slot smoke run added 233 checked transactions and 20
cancellation scenarios. All 17 wrapper parameter checks and six security
mutations passed; details and reproduction commands follow below.

The secure-memory integration passed **4/4 configurations** (AES-128/256 with
128/384-bit buses, four matrix shapes each, 440,000 to 514,000 checks per
configuration). Each configuration made 128 authenticated loads, rejected 88
tampered or misdirected loads, made 23 output attempts and retired 13 output
rows. Three additional quick runs passed at 3x1 (one bank), 1x3 (three banks),
and 3x3 with 16-bit data and 64-bit accumulators. The secure-memory negative
runner passed 30/30 cases without mutations and 40/40 with them, including all
three integration mutations. The row stager passed 78 records at each of the
8/16/128/384-bit widths. The plain accelerator passed 24/24 cases at each of
nine array shapes, and the tagged suite 26/26 at each of six shapes. Verilator
lint passed for all three builds.

## Coverage matrix

| Production module | Independent checking and stress coverage |
| --- | --- |
| `pe` | Every 8-bit signed operand pair (65,536), overflowing 16-bit sums, 4-bit/8-bit variants, 1/3/5 weight banks, invalid selectors/targets, invalid loads, forwarding, and reset priority. |
| `sysarr` | Direct column dot-product oracle across 1x1, 1x5, 3x1, 3x5 and 1/3/5 banks; signed arithmetic, bank replacement, and reset. Controller suites separately check transient skew and tiling. |
| `matrix_input_buffer` | Independent stored-word/validity model, every cell read after each cycle, signed data, overwrite, and reset-versus-write priority. |
| `matrix_output_buffer` | Independent data/valid/final model, partial-to-final and final-to-partial replacement, reset/clear-versus-write priority. |
| `multi_read_matrix_buffer` | Simultaneous distinct and aliased asynchronous reads checked against a write-history model. This primitive has no reset or valid port. |
| `multi_write_output_buffer` | Simultaneous writes, highest-port collision behavior, read coherence, partial/final flags, reset and clear priority. |
| `weight_stationary_accelerator` | Mathematical matrix-multiplication oracle, zero/oversized dimensions in every axis, missing data, full capacity, signed extrema and accumulator wrap, tiling/underfill, back-to-back jobs, busy host writes/config/start, long stalls, reset, transaction conservation, out-of-range host writes (port monitor), and `debug_mac_count == M*K*N` on every case. Tagged builds add epoch isolation (a new owner cannot inherit a previous owner's A elements), same-edge configure/binding, refusal of a start on a configure edge, and a blank result port after abort or reset flushes a stalled result. Simulation assertions stop on any out-of-range buffer write, colliding OBuff commits, or a DRAIN longer than one cycle. |
| `tag_policy_resolver` | All eight validity/prior-partial combinations crossed with equal, zero, low-bit-mismatched, and high-bit-mismatched tags. |
| `shared_tag_queue` | Expected taps from accepted-token history; holds, bubbles, reset/flush priority, singleton/rectangular shapes, empty state, and erasure. |
| `secure_obuff_tag_store` | Every cell/port checked against an independent store model; concurrent distinct/aliased writes, clear/reset priority, and zeroization at 1-bit and 96-bit tag widths. |
| `tenant_key_regfile` | Directed adversarial cases plus 1,200 model-checked cycles per stress configuration; 1/3/5/8 slots, 128/256-bit keys, 1/3/4 lookup ports; busy/collision priorities, all entry fields, nonce reservation/exhaustion/rollback, duplicate rejection, reset, and zeroization. |
| `aes_primitives` package | Exhaustive algebraic S-box and polynomial xtime oracle, all 128 ShiftRows/MixColumns basis states; full cipher vectors also cover SubBytes/SubWord/RotWord/Rcon composition. |
| `aes_key_expand` | Every round key and rolling window checked against independent whole-schedule expansion for 24 keys per width (48 schedules). |
| `aes_encrypt_block` | NIST and embedded OpenSSL vectors plus fresh OpenSSL walking-bit/random campaigns: 512 AES-128 and 640 AES-256 pairs; adjacent key changes, bubbles/stalls, latency/throughput, cancellation at every pipeline stage, internal zeroization, and conservation of accepted/completed/canceled work. |
| `gf128_mul` | All 16,384 pairs of polynomial basis vectors plus 256 random algebra cases; 17,920 independent product comparisons, commutativity, distributivity, identity and zero. |
| `ghash_core` | NIST intermediates and independent polynomial oracle; 128/256/384/512/1024/2048/4096-bit widths, every legal final lane count, random intermediate packing, ignored lanes, every encodable illegal count, bubbles/stalls, output/start overlap, reset/clear, and zeroization. |
| `gctr_core` | Independent embedded OpenSSL keystream vectors; both AES widths, 128/384/512-bit buses, low-word counter wrap, every final byte count, no-stall latency/throughput, bubbles/stalls, malformed masks, injected block-limit boundary/exhaustion, cancellation, and private AES/data erasure. |
| `aes_gcm_engine` | OpenSSL EVP oracle checked against stored NIST vectors; encrypt/decrypt, empty messages, partial AAD/payload and bus boundaries, dirty ignored bytes, changing command pins, bounded lengths, tag/ciphertext/AAD/key/IV tampering, stream stalls, cancellation/recovery, quarantine, and zeroization. |
| `tenant_gcm_port`, `tenant_gcm_cluster` | Independently encoded authenticated records; tenant/key selection, generated IVs, fixed AAD binding, captured destination metadata, shared-slot ownership, provisioning/invalidation/start races, three simultaneous streams, cancellation, and hierarchy erasure. |
| `authenticated_row_stager` | Byte-level oracle at 8/16/128/384-bit widths; whole-row atomic commit, zero-filled tails, tenant/destination capture, held results, length and protocol errors, clear, and five mutations (premature commit, ignored finish error/tenant/destination, early finish acknowledgement). |
| `secure_memory_accelerator` | End-to-end OpenSSL record oracle and Python matrix multiply: every ciphertext byte and `TGR1` header of every output attempt; eleven load-fault classes on both ports (tag/IV/ciphertext tampering, bad magic, out-of-range or wrong row, wrong or unknown tenant, malformed keep/last); staging cancellation at three phases; atomic replacement; storage failure retry with a fresh IV and cookie, cleared acknowledgement, and stale/wrong cookies; reset with re-provisioning from persisted counters; abort mid-compute preserving keys, nonces and cookies; reconfiguration discarding a loaded epoch. |

The tagged end-to-end campaign adds full-range signed random matrices and
96-bit tenant tags with high bits set. Assertions check atomic numerical/tag
commit, inactive-column suppression, and stability of the entire output packet
through stalls and the eventual accepting edge. Reset and trusted abort are
tested while an output is blocked, followed by sticky-fault checks and a fresh
tenant transaction after reset.

## Reproduction and diagnostics

The extended runner contains 58 named cases. It writes one log per case and
`summary.json` under ignored `logs/rigorous/`. Every case has bounded simulation
and wall-clock time. A nonzero compiler/simulator status, an unexpected RTL
error, or a missing success marker fails a positive case. The runner exits
nonzero if any case fails.

```sh
# Extended campaign only (the numerical baseline is in full-ci).
make test-rigorous

# Re-run a named subset without repeating unrelated tests.
python3 tests/run_rigorous.py --match aes256-openssl
python3 tests/run_rigorous.py --match controller
python3 tests/run_rigorous.py --match reject-
```

OpenSSL fixtures are generated locally with deterministic SHA256-derived
key/block pairs plus walking-one inputs, then deleted with the temporary build
directory. The RTL is never its own AES oracle. GHASH reference multiplication
uses polynomial convolution and reduction, independently of the RTL's reflected
shift-right circuit. Random module scoreboards use fixed public xorshift seeds.
GHASH and tagged top-level tests also expose `+seed` and `+stress_iters` controls.
The runner records fixed seeds in its command construction, and tagged/GHASH
diagnostics identify their seeds.

## GCM differential and adversarial tests

```sh
make test-gctr
make test-gcm
make test-gcm-negative
make test-gcm-wide
make test-gcm-mutations

# Fast development checks or a single configuration.
python3 tests/run_gcm.py --oracle-only
python3 tests/run_gcm.py --keys 128 --widths 128 --quick
python3 tests/run_gcm.py --match gcm-aes256-w384
```

`tests/run_gcm.py` calls OpenSSL's EVP authenticated encryption and decryption
through Python `ctypes`. Four checked-in AES-128/256 NIST examples validate the
oracle first, including partial AAD/ciphertext. Additional deterministic vectors
use SHAKE-derived key/IV/data and cover every payload final byte count through
one bus beat in the default 128/384/512-bit sweep. AAD lengths cover independent
partials and boundaries. Boundary cases include both configured
odd capacities, 1031 payload bytes and 1033 AAD bytes. The testbench compares
every accepted output byte and tag against independent expected values.

Tampering must return authentication failure, zero output bytes, and no
calculated decryption tag. Tests also check held results, authenticated output
stalls, malformed stream framing, reset/clear, and recovery. The separate
4096-bit smoke sweep runs 36 independent vectors in both directions, checking
output data/tags, stalls, continuous bursts, and erasure. It skips the directed
tamper/framing/cancellation matrix already exercised at all six narrower
configurations, and is not exhaustive over all 512 final-byte positions.

Logs and per-configuration vector manifests are under ignored `logs/gcm/`.
The runner bounds simulation time and treats compiler/simulator failures as
test failures. `tests/run_gcm_negative.py` adds eight invalid configurations
that must compile and then fail with their expected diagnostic, plus four
legal minimal-capacity elaborations. Its evidence is in `logs/gcm-negative/`.
With `--mutations`, that runner also checks temporary copies with authentication
rejection bypassed, plaintext hashed instead of ciphertext, omitted AAD bit
length, or unchecked payload-last framing. Each must compile and then fail the
expected test assertion; an unmodified control run must pass first. Production
RTL is never edited by these checks.

## Trusted tenant wrapper tests

```sh
make test-tenant-gcm
make test-tenant-gcm-negative
make test-tenant-gcm-mutations
make tenant-gcm-lint

# Focused development run; the default command above runs the full matrix.
python3 tests/run_tenant_gcm.py --keys 128 --widths 128 --slots 3 --quick

# Smoke test of the default eight-slot key file.
python3 tests/run_tenant_gcm.py --keys 256 --widths 128 --slots 8 --quick
```

`tests/run_tenant_gcm.py` encodes the `TGC1` record header in Python and obtains
ciphertext/tags from OpenSSL EVP. Its oracle includes the expected IV-counter
values independently of the RTL. It also generates tags for deliberately wrong
header magic and authenticated payload lengths, testing the wrapper's actual
AAD construction instead of copying an RTL result into the reference.

The default configuration matrix covers AES-128/256 and 128/384/512-bit buses
with three slots, plus both key widths with one slot. Payload capacities are
odd-sized so the final bounded storage entry and byte masks are exercised.
The suite checks ordinary traffic, command-pin changes after acceptance,
reserved-IV/counter behavior, missing/duplicate/exhausted keys, malformed
payloads, metadata/ciphertext/tag tampering, shared and separate tenant slots,
busy key updates, per-path abort, reset, and inactive output masking. Hierarchical
checks inspect private AES/GHASH/GCTR state, quarantine, wrapper metadata, and
slot ownership; these are testbench observations, not production debug ports.
Directed arbitration checks own a nonzero key slot, block its mutation, and
allow a different-key reader to proceed while an output writer waits. Accepted
updates to an unrelated idle slot must preserve both active contexts. Clear
injection preserves stalled input beats on the other ports; reset scenarios
start all three ports together and check erasure across the entire cluster.
The AES-256/128-bit-bus/eight-slot smoke run passed 233 checked transactions
from 24 independent records, including 91 rejections and 20 cancellation
scenarios. A cancellation scenario is one clear or global-reset event; global
reset may cancel several ports together.

| AES key bits | Bus bits | Key slots | Checked transactions | Successful | Rejected | Oracle records |
| --- | --- | --- | --- | --- | --- | --- |
| 128 | 128 | 3 | 653 | 202 | 451 | 44 |
| 128 | 384 | 3 | 389 | 298 | 91 | 76 |
| 128 | 512 | 3 | 437 | 346 | 91 | 92 |
| 256 | 128 | 3 | 653 | 202 | 451 | 44 |
| 256 | 384 | 3 | 389 | 298 | 91 | 76 |
| 256 | 512 | 3 | 437 | 346 | 91 | 92 |
| 128 | 128 | 1 | 282 | 199 | 83 | 44 |
| 256 | 128 | 1 | 282 | 199 | 83 | 44 |

Every configuration also passed 20 cancellation scenarios. Both 128-bit-bus,
three-slot configurations reject flips of all 128 tag bits on both decrypt
paths, every record-type bit, and all 64 destination bits. The remaining
configurations repeat representative bit faults across their bus/slot shapes.
The key-file unit regression and all four model-based key stress configurations
also passed after integration.

The parameter runner requires invalid configurations to compile first and fail
with their expected runtime diagnostics; it also elaborates legal minimal
capacities. Its optional mutation campaign deliberately removes destination
binding, accepts caller-selected encryption IVs, releases ownership while a
result is held, bypasses key-update arbitration, stops nonce advancement, or
reports every owner as slot zero.
Each temporary faulty design must fail the intended assertion, while an
unmodified oracle control must pass. Logs are retained under `logs/tenant-gcm/`
and `logs/tenant-gcm-negative/`.

All **17 parameter checks and six security mutations passed**, with a passing
unmodified oracle control. The final control completed 170 transactions. The
sixth mutation and updated control were run as a focused follow-up; their
evidence is in `selected-summary.json`, alongside the earlier 23-case summary.
The complete runner now contains 24 cases. Compilation failures and watchdog
timeouts do not count as successful negative controls. Baseline, tagged, GCM,
and tenant-cluster compile checks passed; Icarus reports only its array-wide
`@*` sensitivity notices for the cluster.

Fixtures intentionally reset and reprovision known keys/IV sequences for
repeatable testing. This does not change the production requirement for a fresh
key/IV sequence after reset or retirement. The cluster's accepted-command
reservation and abort tests cover uniqueness within each live provisioned
sequence; persistent nonce history and replay freshness remain outside it.

## Secure-memory integration tests

```sh
make test-row-stager
make test-secure-memory
make test-secure-memory-negative
make test-secure-memory-mutations

# Fast development run of one configuration.
python3 tests/run_secure_memory.py --keys 128 --widths 128 --quick
```

`tests/run_secure_memory.py` builds a fixture with OpenSSL: encrypted A records
for two private tenants, public B records under tenant 0, and, for each C row,
the expected ciphertext and header at every nonce value the run can use. The
testbench drives that fixture through the real record interfaces and models
only the external storage controller. It tracks the key file's nonce
reservations independently, so retries and cancellations must consume fresh
IVs. The lifecycle sequence runs after real outputs, so reset re-provisioning
and abort preservation are checked with non-zero counters.

`tests/run_secure_memory_negative.py` adds parameter rejections, stager byte
oracles and mutations, and three integration mutations: ignoring the storage
cookie, retiring a row at header acceptance, and keeping data across a
reconfiguration. Each must fail its intended assertion after an unmodified
control passes.

## Primitive negative controls

Eleven invalid-configuration cases must compile and then fail explicitly with
the expected parameter diagnostic. A compilation error does not count as a
passing rejection test. These cover unsupported AES width/rounds, invalid GHASH
width/derived parameters, and invalid key-file widths/slot/port configuration.

Seven mutation cases compile temporary copies with one deliberate fault each:
an AES S-box entry, GF reduction constant, omitted GHASH lane, skipped nonce
counter value, tag queue advancing during a hold, ignored buffer clear, and
broken PE sign handling. Each must be caught by a simulation assertion. This
checks that the tests can detect those specific errors; production RTL files
are never changed by mutation testing.

## Interpretation and remaining limits

These are deterministic simulation results, not formal proofs or a measured
code/branch coverage percentage. Operand exhaustiveness applies to the listed
finite spaces, not every module state combination. Buffer address tests use
legal addresses.
The controller range-checks every host write, and simulation assertions stop
on any out-of-range buffer write. Invalid/uninitialized numerical data is not
required to be zero when its valid bit is clear. Key and protected metadata
erasure are checked explicitly.

The trusted provisioning lifecycle contract still applies after key retirement
or reset. GCM verification covers tamper rejection and authentication-before-
release from private quarantine. The tenant wrapper adds protected key/nonce
handling and three concurrent crypto paths, and the secure-memory build connects
them to atomic row/tag commit and acknowledged output records. Still outside
this gate: replay freshness (an old valid record with the same context is
accepted), the physical storage controller, persistent nonce history across
reset, and any synthesis, timing, area, physical side-channel, or power result.
