RTL = pe.sv sysarr.sv buffers.sv secure_tags.sv weight_stationary_accelerator.sv
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
full-ci: ci test-secure-tags tagged-sweep
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
