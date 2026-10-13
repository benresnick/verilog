RTL = pe.sv sysarr.sv buffers.sv secure_tags.sv weight_stationary_accelerator.sv
AES_RTL = aes_primitives.sv aes_key_expand.sv aes_encrypt_block.sv
GHASH_RTL = gf128_mul.sv ghash_core.sv
GCTR_RTL = $(AES_RTL) gctr_core.sv
GCM_RTL = $(AES_RTL) $(GHASH_RTL) gctr_core.sv aes_gcm_engine.sv
TENANT_GCM_RTL = $(GCM_RTL) tenant_key_regfile.sv tenant_gcm_port.sv tenant_gcm_cluster.sv
SECURE_MEMORY_RTL = $(RTL) $(TENANT_GCM_RTL) authenticated_row_stager.sv secure_memory_accelerator.sv
.PHONY: test-tenant-keys test-aes test-aes128 test-aes256 test-ghash test-crypto full-ci
.PHONY: test-rigorous rigorous-ci
.PHONY: test-gctr test-gcm test-gcm-wide test-gcm-negative test-gcm-mutations gcm-lint
.PHONY: test-tenant-gcm test-tenant-gcm-negative test-tenant-gcm-mutations tenant-gcm-lint
.PHONY: test-row-stager test-secure-memory test-secure-memory-negative test-secure-memory-mutations secure-memory-lint
test-pe:
	iverilog -g2012 -s pe_tb -o /tmp/ws_pe_tb pe.sv pe_tb.sv && vvp /tmp/ws_pe_tb
test-buffers:
	iverilog -g2012 -s buffers_tb -o /tmp/ws_buffers_tb buffers.sv buffers_tb.sv && vvp /tmp/ws_buffers_tb
lint:
	iverilog -g2012 -s weight_stationary_accelerator -o /tmp/ws_lint $(RTL)
tagged-lint:
	iverilog -g2012 -DENABLE_SECURE_TAGS -s weight_stationary_accelerator -o /tmp/ws_tagged_lint $(RTL)
test-secure-tags:
	iverilog -g2012 -DENABLE_SECURE_TAGS -s secure_tags_tb -o /tmp/ws_secure_tags secure_tags.sv secure_tags_tb.sv && vvp /tmp/ws_secure_tags
test-tenant-keys:
	iverilog -g2012 -s tenant_key_regfile_tb -o /tmp/ws_tenant_keys tenant_key_regfile.sv tenant_key_regfile_tb.sv && vvp /tmp/ws_tenant_keys
test-aes128:
	iverilog -g2012 -s aes_encrypt_block_tb -Paes_encrypt_block_tb.AES_KEY_W=128 -o /tmp/ws_aes128 $(AES_RTL) aes_encrypt_block_tb.sv && vvp /tmp/ws_aes128
test-aes256:
	iverilog -g2012 -s aes_encrypt_block_tb -Paes_encrypt_block_tb.AES_KEY_W=256 -o /tmp/ws_aes256 $(AES_RTL) aes_encrypt_block_tb.sv && vvp /tmp/ws_aes256
test-aes: test-aes128 test-aes256
test-ghash:
	@set -e; for width in 128 384 512 4096; do \
		iverilog -g2012 -s ghash_core_tb -Pghash_core_tb.MEM_DATA_W=$$width -o /tmp/ws_ghash_$$width $(GHASH_RTL) ghash_core_tb.sv; \
		vvp /tmp/ws_ghash_$$width; \
	done
test-gctr:
	@set -e; for bits in 128 256; do \
		for width in 128 384 512; do \
			iverilog -g2012 -s gctr_core_tb -Pgctr_core_tb.AES_KEY_W=$$bits -Pgctr_core_tb.MEM_DATA_W=$$width -o /tmp/ws_gctr_$${bits}_$$width $(GCTR_RTL) gctr_core_tb.sv; \
			vvp /tmp/ws_gctr_$${bits}_$$width; \
		done; \
	done
test-gcm:
	python3 tests/run_gcm.py
test-gcm-wide:
	python3 tests/run_gcm.py --widths 4096 --quick
test-gcm-negative:
	python3 tests/run_gcm_negative.py
test-gcm-mutations:
	python3 tests/run_gcm_negative.py --mutations
gcm-lint:
	iverilog -g2012 -Wall -s aes_gcm_engine -o /tmp/ws_gcm_lint $(GCM_RTL)
test-tenant-gcm:
	python3 tests/run_tenant_gcm.py
test-tenant-gcm-negative:
	python3 tests/run_tenant_gcm_negative.py
test-tenant-gcm-mutations:
	python3 tests/run_tenant_gcm_negative.py --mutations
tenant-gcm-lint:
	iverilog -g2012 -Wall -s tenant_gcm_cluster -o /tmp/ws_tenant_gcm_lint $(TENANT_GCM_RTL)
test-row-stager:
	@set -e; for width in 8 16 128 384; do \
		iverilog -g2012 -s authenticated_row_stager_tb -Pauthenticated_row_stager_tb.MEM_DATA_W=$$width -o /tmp/ws_stager_$$width authenticated_row_stager.sv authenticated_row_stager_tb.sv; \
		vvp /tmp/ws_stager_$$width; \
	done
test-secure-memory:
	python3 tests/run_secure_memory.py
test-secure-memory-negative:
	python3 tests/run_secure_memory_negative.py
test-secure-memory-mutations:
	python3 tests/run_secure_memory_negative.py --mutations
secure-memory-lint:
	iverilog -g2012 -Wall -DENABLE_SECURE_TAGS -DENABLE_SECURE_MEMORY -s secure_memory_accelerator -o /tmp/ws_secure_memory_lint $(SECURE_MEMORY_RTL)
test-crypto: test-tenant-keys test-aes test-ghash test-gctr test-gcm test-gcm-negative test-tenant-gcm test-tenant-gcm-negative
full-ci: ci test-secure-tags tagged-sweep test-crypto test-row-stager test-secure-memory test-secure-memory-negative
test-rigorous:
	python3 tests/run_rigorous.py
rigorous-ci: full-ci test-rigorous test-gcm-wide test-gcm-mutations test-tenant-gcm-mutations test-secure-memory-mutations lint tagged-lint gcm-lint tenant-gcm-lint secure-memory-lint
vcd-w1:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.W=1 -o /tmp/ws_vcd $(RTL) weight_stationary_accelerator_tb.sv && vvp /tmp/ws_vcd +vcd
verbose-w4:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.W=4 -o /tmp/ws_verbose $(RTL) weight_stationary_accelerator_tb.sv && vvp /tmp/ws_verbose +verbose
random-w4:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.W=4 -o /tmp/ws_random $(RTL) weight_stationary_accelerator_tb.sv && vvp /tmp/ws_random +random_iters=20
run-w1:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.W=1 -o sim_w1 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_w1
run-w4:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.W=4 -o sim_w4 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_w4
run-w2:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.W=2 -o sim_w2 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_w2
run-w3:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.W=3 -o sim_w3 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_w3
run-w5:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.W=5 -o sim_w5 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_w5
run-shape3:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.ROWS=3 -Pweight_stationary_accelerator_tb.COLS=3 -Pweight_stationary_accelerator_tb.W=4 -o sim_shape3 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_shape3
run-row1:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.ROWS=1 -Pweight_stationary_accelerator_tb.COLS=3 -Pweight_stationary_accelerator_tb.W=4 -o sim_row1 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_row1
run-nonpow:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.ROWS=3 -Pweight_stationary_accelerator_tb.COLS=5 -Pweight_stationary_accelerator_tb.W=3 -o sim_nonpow $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_nonpow
run-shape41:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.ROWS=4 -Pweight_stationary_accelerator_tb.COLS=1 -Pweight_stationary_accelerator_tb.W=2 -o sim_shape41 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_shape41
sweep-weights: run-w1 run-w2 run-w3 run-w4 run-w5
sweep-shapes: run-row1 run-shape3 run-nonpow run-shape41
sweep: sweep-weights sweep-shapes
random-sweep:
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.ROWS=2 -Pweight_stationary_accelerator_tb.COLS=3 -Pweight_stationary_accelerator_tb.W=2 -o sim_random_r2c3w2 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_random_r2c3w2 +random_iters=10
	iverilog -g2012 -s weight_stationary_accelerator_tb -Pweight_stationary_accelerator_tb.ROWS=3 -Pweight_stationary_accelerator_tb.COLS=2 -Pweight_stationary_accelerator_tb.W=5 -o sim_random_r3c2w5 $(RTL) weight_stationary_accelerator_tb.sv && vvp sim_random_r3c2w5 +random_iters=10
regress: test-pe test-buffers sweep
full-regress: regress random-sweep
ci:
	mkdir -p logs
	$(MAKE) full-regress > logs/regression.log 2>&1 || { tail -n 80 logs/regression.log; exit 1; }
	tail -n 20 logs/regression.log

# Tagged simulation is a distinct elaboration: no tag storage or tag ports
# exist in the ordinary targets above.
tagged:
	iverilog -g2012 -DENABLE_SECURE_TAGS -DSECURE_TAG_TEST_HOOKS -s secure_tagging_tb -o /tmp/ws_tagged $(RTL) secure_tagging_tb.sv && vvp /tmp/ws_tagged

tagged-sweep:
	iverilog -g2012 -DENABLE_SECURE_TAGS -DSECURE_TAG_TEST_HOOKS -s secure_tagging_tb -Psecure_tagging_tb.ROWS=1 -Psecure_tagging_tb.COLS=1 -Psecure_tagging_tb.W=1 -o /tmp/ws_tag_1x1 $(RTL) secure_tagging_tb.sv && vvp /tmp/ws_tag_1x1
	iverilog -g2012 -DENABLE_SECURE_TAGS -DSECURE_TAG_TEST_HOOKS -s secure_tagging_tb -Psecure_tagging_tb.ROWS=1 -Psecure_tagging_tb.COLS=4 -Psecure_tagging_tb.W=1 -o /tmp/ws_tag_1x4 $(RTL) secure_tagging_tb.sv && vvp /tmp/ws_tag_1x4
	iverilog -g2012 -DENABLE_SECURE_TAGS -DSECURE_TAG_TEST_HOOKS -s secure_tagging_tb -Psecure_tagging_tb.ROWS=2 -Psecure_tagging_tb.COLS=2 -Psecure_tagging_tb.W=1 -o /tmp/ws_tag_2x2w1 $(RTL) secure_tagging_tb.sv && vvp /tmp/ws_tag_2x2w1
	iverilog -g2012 -DENABLE_SECURE_TAGS -DSECURE_TAG_TEST_HOOKS -s secure_tagging_tb -Psecure_tagging_tb.ROWS=2 -Psecure_tagging_tb.COLS=2 -Psecure_tagging_tb.W=4 -o /tmp/ws_tag_2x2w4 $(RTL) secure_tagging_tb.sv && vvp /tmp/ws_tag_2x2w4
	iverilog -g2012 -DENABLE_SECURE_TAGS -DSECURE_TAG_TEST_HOOKS -s secure_tagging_tb -Psecure_tagging_tb.ROWS=3 -Psecure_tagging_tb.COLS=5 -Psecure_tagging_tb.W=2 -o /tmp/ws_tag_3x5 $(RTL) secure_tagging_tb.sv && vvp /tmp/ws_tag_3x5
	iverilog -g2012 -DENABLE_SECURE_TAGS -DSECURE_TAG_TEST_HOOKS -s secure_tagging_tb -Psecure_tagging_tb.ROWS=4 -Psecure_tagging_tb.COLS=3 -Psecure_tagging_tb.W=3 -o /tmp/ws_tag_4x3 $(RTL) secure_tagging_tb.sv && vvp /tmp/ws_tag_4x3
