`timescale 1ns/1ps

// DRAM-model end-to-end testbench.  The golden model deliberately uses the
// matrix equation directly, rather than replicating the accelerator schedule.
module weight_stationary_accelerator_tb;
    parameter int ROWS  = 2;
    parameter int COLS  = 2;
    parameter int W     = 1;
    parameter int MAX_M = 6;
    parameter int MAX_K = 10;
    parameter int MAX_N = 6;

    localparam int DW = 8;
    localparam int AW = 32;
    localparam int MW = $clog2(MAX_M + 1);
    localparam int KW = $clog2(MAX_K + 1);
    localparam int NW = $clog2(MAX_N + 1);

    logic clk = 0;
    logic reset, config_we, a_we, b_we, start, result_ready;
    logic [MW-1:0] config_m, a_row, result_row;
    logic [KW-1:0] config_k, a_col, b_row;
    logic [NW-1:0] config_n, b_col, result_col;
    logic signed [DW-1:0] a_data, b_data;
    logic busy, done, job_error, result_valid;
    logic config_ready, a_ready, b_ready;
    logic signed [AW-1:0] result_data;
    logic [3:0] phase;
    logic [31:0] loads, macs;

    logic signed [DW-1:0] dram_a [0:MAX_M-1][0:MAX_K-1];
    logic signed [DW-1:0] dram_b [0:MAX_K-1][0:MAX_N-1];
    logic signed [AW-1:0] golden [0:MAX_M-1][0:MAX_N-1];
    logic signed [AW-1:0] dram_c [0:MAX_M-1][0:MAX_N-1];
    logic result_received [0:MAX_M-1][0:MAX_N-1];
    integer cycles, errors, passed, failed;

    always #5 clk = ~clk;

    weight_stationary_accelerator #(
        .ROWS(ROWS), .COLS(COLS), .WEIGHTS_PER_PE(W),
        .MAX_M(MAX_M), .MAX_K(MAX_K), .MAX_N(MAX_N)
    ) dut (
        .*, .debug_weight_set_loads(loads), .debug_mac_count(macs)
    );

    // Optional, nonintrusive waveform: make ... run-w1 VCD=1 is not needed;
    // invoke the simulator with +vcd instead.
    initial if ($test$plusargs("vcd")) begin
        $dumpfile("weight_stationary_accelerator.vcd");
        $dumpvars(0, weight_stationary_accelerator_tb);
    end

    task automatic pulse_reset;
        begin
            reset = 1; config_we = 0; a_we = 0; b_we = 0;
            start = 0; result_ready = 1;
            repeat (2) @(posedge clk);
            reset = 0;
        end
    endtask

    task automatic run_case(
        input integer m, input integer k, input integer n,
        input integer seed, input logic stall_results, input integer data_mode,
        input string name
    );
        integer i, j, x, limit, saw_drain, saw_store, rng, result_count;
        logic result_held;
        logic [MW-1:0] held_row;
        logic [NW-1:0] held_col;
        logic signed [AW-1:0] held_data;
        integer last_phase, last_load_issue, last_commits;
        integer signed sum;
        begin
            // Populate behavioral DRAM using a reproducible pseudo-random
            // sequence, then independently calculate C=A*B.
            rng = seed;
            for (i = 0; i < MAX_M; i++)
                for (j = 0; j < MAX_K; j++)
                    if (i < m && j < k) begin
                        rng = $urandom(rng);
                        case (data_mode)
                            1: dram_a[i][j] = 0;
                            2: dram_a[i][j] = ((i + j) % 3 == 0) ?
                                                ($signed({1'b0, rng[2:0]}) - 4) : 0;
                            3: dram_a[i][j] = ((i + j) % 2) ? 8'sd127 : -8'sd128;
                            default: dram_a[i][j] = $signed({1'b0, rng[2:0]}) - 4;
                        endcase
                    end else dram_a[i][j] = 0;
            for (i = 0; i < MAX_K; i++)
                for (j = 0; j < MAX_N; j++)
                    if (i < k && j < n) begin
                        rng = $urandom(rng);
                        case (data_mode)
                            1: dram_b[i][j] = 0;
                            2: dram_b[i][j] = ((i + j) % 3 == 0) ?
                                                ($signed({1'b0, rng[2:0]}) - 4) : 0;
                            3: dram_b[i][j] = ((i + j) % 2) ? -8'sd128 : 8'sd127;
                            default: dram_b[i][j] = $signed({1'b0, rng[2:0]}) - 4;
                        endcase
                    end else dram_b[i][j] = 0;
            for (i = 0; i < MAX_M; i++)
                for (j = 0; j < MAX_N; j++) begin
                    sum = 0;
                    for (x = 0; x < k; x++) sum += dram_a[i][x] * dram_b[x][j];
                    golden[i][j] = sum;
                    dram_c[i][j] = 'x;
                    result_received[i][j] = 1'b0;
                end

            $display("[%0t] [PHASE] Loading from DRAM into buffers: %s", $time, name);
            @(negedge clk);
            config_we = 1; config_m = m; config_k = k; config_n = n;
            @(negedge clk); config_we = 0;
            for (i = 0; i < m; i++) for (j = 0; j < k; j++) begin
                @(negedge clk);
                a_we = 1; a_row = i; a_col = j; a_data = dram_a[i][j];
                @(negedge clk); a_we = 0;
            end
            for (i = 0; i < k; i++) for (j = 0; j < n; j++) begin
                @(negedge clk);
                b_we = 1; b_row = i; b_col = j; b_data = dram_b[i][j];
                @(negedge clk); b_we = 0;
            end

            $display("[%0t] [PHASE] Computing: %s", $time, name);
            @(negedge clk); start = 1;
            @(negedge clk); start = 0;
            limit = 0;
            saw_drain = 0;
            saw_store = 0;
            last_phase = -1;
            last_load_issue = -1;
            last_commits = 0;
            result_held = 1'b0;
            result_count = 0;
            while (!done && limit < 4000) begin
                // Deliberately withdraw ready on a repeatable cadence when
                // requested.  The result coordinate/data must remain stable
                // until the next accepted result handshake.
                result_ready = !stall_results || ((limit % 3) != 1);
                @(posedge clk);
                #1; // Observe registered controller state after this edge.
                cycles++;
                if (phase != last_phase) begin
                    case (phase)
                        1: $display("[%0t] [LOAD] N tile base=%0d, K set base=%0d; issuing %0d banks bottom-row-first",
                                    $time, dut.n_base, dut.kset_base, W);
                        2: $display("[%0t] [COMPUTE] N[%0d:%0d), K[%0d:%0d), selected PE weight bank %0d",
                                    $time, dut.n_base, dut.n_base + dut.active_cols,
                                    dut.kset_base + dut.bank * ROWS,
                                    dut.kset_base + dut.bank * ROWS + dut.active_rows,
                                    dut.bank);
                        4: $display("[%0t] [RESULT] Final OBuff contents ready for DRAM transfer", $time);
                    endcase
                    last_phase = phase;
                end
                if (phase == 1 && dut.load_issue != last_load_issue &&
                    dut.load_issue % ROWS == 0) begin
                    $display("[%0t] [LOAD] local bank %0d/%0d, starting at physical row %0d",
                             $time, dut.load_issue / ROWS + 1, W, ROWS - 1);
                    last_load_issue = dut.load_issue;
                end
                if (phase == 3 && !saw_drain) begin
                    $display("[%0t] [PHASE] Draining to OBuff: %s", $time, name);
                    saw_drain = 1;
                end
                if ((phase == 2 || phase == 3) && dut.commits != last_commits) begin
                    if ($test$plusargs("verbose") ||
                        dut.commits == dut.m_dim * dut.active_cols)
                        $display("[%0t] [OBUFF] %0d/%0d partial sums committed for this bank",
                                 $time, dut.commits, dut.m_dim * dut.active_cols);
                    last_commits = dut.commits;
                end
                if (result_held) begin
                    if (result_ready) begin
                        result_held = 1'b0;
                    end else if (!result_valid || result_row !== held_row || result_col !== held_col ||
                                 result_data !== held_data) begin
                        $fatal(1, "result changed while result_ready was low");
                    end
                end
                if (result_valid && !result_ready) begin
                    result_held = 1'b1;
                    held_row = result_row;
                    held_col = result_col;
                    held_data = result_data;
                end
                if (result_valid && result_ready) begin
                    if (!saw_store) begin
                        $display("[%0t] [PHASE] Storing outputs to DRAM: %s", $time, name);
                        saw_store = 1;
                    end
                    if (result_received[result_row][result_col]) begin
                        $error("%s duplicated result C[%0d,%0d]", name, result_row, result_col);
                        errors++;
                    end
                    result_received[result_row][result_col] = 1'b1;
                    result_count++;
                    dram_c[result_row][result_col] = result_data;
                    $display("[%0t] [RESULT] DRAM C[%0d,%0d] <- %0d",
                             $time, result_row, result_col, result_data);
                end
                limit++;
            end
            if (!done) begin
                $error("timeout %s state=%0d nbase=%0d kset=%0d bank=%0d commits=%0d",
                       name, phase, dut.n_base, dut.kset_base, dut.bank, dut.commits);
                $fatal;
            end

            $display("[%0t] [PHASE] Checking outputs: %s", $time, name);
            if (result_count != m * n) begin
                $error("%s expected %0d accepted results, received %0d", name, m * n, result_count);
                errors++;
            end
            for (i = 0; i < m; i++) for (j = 0; j < n; j++)
                if (dram_c[i][j] !== golden[i][j]) begin
                    $error("%s C[%0d,%0d] expected %0d got %0d", name, i, j,
                           golden[i][j], dram_c[i][j]);
                    errors++;
                end
            if (errors == 0) begin
                $display("[PASS] %s loads=%0d macs=%0d", name, loads, macs);
                passed++;
            end else begin
                $display("[FAIL] %s", name);
                failed++; errors = 0;
            end
        end
    endtask

    task automatic check_invalid_job(input integer m, input integer k, input integer n);
        begin
            @(negedge clk);
            config_we = 1; config_m = m; config_k = k; config_n = n;
            @(negedge clk); config_we = 0; start = 1;
            @(negedge clk); start = 0;
            @(posedge clk);
            if (!job_error || busy || done || result_valid) begin
                $error("invalid dimensions %0dx%0dx%0d were not cleanly rejected", m, k, n);
                failed++;
            end else begin
                $display("[PASS] invalid dimensions %0dx%0dx%0d rejected", m, k, n);
                passed++;
            end
        end
    endtask

    task automatic check_missing_data_job;
        begin
            // This is run before any valid matrix writes, so a legal shape
            // with no payload must be rejected instead of starting stale work.
            @(negedge clk);
            config_we = 1; config_m = 1; config_k = 1; config_n = 1;
            @(negedge clk); config_we = 0; start = 1;
            @(negedge clk); start = 0;
            @(posedge clk);
            if (!job_error || busy || done || result_valid) begin
                $error("missing A/B data job was not rejected");
                failed++;
            end else begin
                $display("[PASS] missing A/B data job rejected");
                passed++;
            end
        end
    endtask

    task automatic check_reset_during_compute;
        begin
            // Load a tiny legal job, then abort it after the scheduler begins.
            @(negedge clk);
            config_we = 1; config_m = 1; config_k = 1; config_n = 1;
            @(negedge clk); config_we = 0; a_we = 1; a_row = 0; a_col = 0; a_data = 3;
            @(negedge clk); a_we = 0; b_we = 1; b_row = 0; b_col = 0; b_data = -2;
            @(negedge clk); b_we = 0; start = 1;
            @(negedge clk); start = 0;
            wait (phase == 2);
            @(negedge clk); reset = 1;
            @(posedge clk);
            @(negedge clk); reset = 0;
            @(posedge clk);
            if (busy || done || result_valid || !config_ready) begin
                $error("reset during compute did not return cleanly to idle");
                failed++;
            end else begin
                $display("[PASS] reset during compute clears in-flight work");
                passed++;
            end
        end
    endtask

    // Simulation invariants.  These observe the internal scheduler only for
    // diagnosis; functional checking continues to use the public result port.
    logic done_seen;
    integer extra_random_cases;
    always @(posedge clk) if (!reset) begin
        // The blocking baseline never loads weights while computing.
        assert (!(dut.u_array.weight_load && dut.state == 2))
            else $fatal(1, "weight load overlapped compute");
        // A bottom-edge result can only be committed to an active N column.
        for (int assertion_col = 0; assertion_col < COLS; assertion_col++)
            if (dut.aov[assertion_col])
                assert (assertion_col < dut.active_cols)
                    else $fatal(1, "padded N column committed: pc=%0d", assertion_col);
        if (dut.state == 2 && dut.apv[0] && dut.kset_base != 0)
            assert (dut.obuf_read_valid[0] || dut.pass_cycle >= dut.m_dim)
                else $fatal(1, "nonzero K pass lacked OBuff feedback seed");
        if (result_valid) assert (result_row < dut.m_dim && result_col < dut.n_dim)
            else $fatal(1, "result coordinate out of range");
        if (done) assert (!result_valid) else $fatal(1, "done preceded final result acceptance");
        if (dut.state == 1) done_seen <= 1'b0;
        if (done_seen) assert (!result_valid) else $fatal(1, "result emitted after done");
        if (done) done_seen <= 1'b1;
    end

    initial begin
        cycles = 0; errors = 0; passed = 0; failed = 0; done_seen = 0;
        pulse_reset();
        check_invalid_job(0, 1, 1);
        check_invalid_job(MAX_M + 1, 1, 1);
        check_missing_data_job();
        check_reset_during_compute();
        run_case(1, 1, 1, 1, 0, 0, "scalar signed");
        run_case(3, 2, 2, 2, 0, 0, "M greater than rows");
        run_case(2, 8, 4, 3, 0, 0, "canonical 2x8 by 8x4");
        run_case(2, 8, 3, 7, 0, 0, "partial N tile");
        run_case(5, 9, 5, 4, 0, 0, "multi tile and K sets");
        run_case(3, 5, 4, 17, 0, 0, "random seed 17");
        run_case(4, 7, 5, 29, 0, 0, "random seed 29");
        run_case(1, 3, 5, 101, 0, 0, "random seed 101 edge M");
        run_case(5, 10, 1, 313, 0, 0, "random seed 313 edge N");
        run_case(2, 4, 2, 911, 0, 0, "random seed 911 resident boundary");
        run_case(3, 6, 4, 1201, 1, 0, "result backpressure");
        run_case(3, 4, 3, 2001, 0, 1, "all valid numeric zeros");
        run_case(4, 5, 4, 2002, 0, 2, "sparse matrix");
        run_case(2, 1, 3, 2003, 0, 3, "signed extrema");
        extra_random_cases = 0;
        void'($value$plusargs("random_iters=%d", extra_random_cases));
        for (int random_index = 0; random_index < extra_random_cases; random_index++)
            run_case(1 + (random_index % MAX_M), 1 + ((random_index * 3) % MAX_K),
                     1 + ((random_index * 5) % MAX_N), 3000 + random_index, 0, 0,
                     $sformatf("extra random seed %0d", 3000 + random_index));
        $display("SUITE: %0d passed, %0d failed, %0d cycles", passed, failed, cycles);
        if (failed) $fatal;
        $finish;
    end
endmodule
