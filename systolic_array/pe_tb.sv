`timescale 1ns/1ps

module pe_tb;

    // ------------------------------------------------------------
    // Parameters
    // ------------------------------------------------------------
    localparam DATA_WIDTH = 8;
    localparam ACC_WIDTH  = 32;

    // ------------------------------------------------------------
    // DUT inputs
    // ------------------------------------------------------------
    logic clk;
    logic reset;
    logic clear_acc;

    logic signed [DATA_WIDTH-1:0] activation_in;
    logic                         activation_valid_in;

    logic signed [DATA_WIDTH-1:0] weight_in;
    logic                         weight_valid_in;

    // ------------------------------------------------------------
    // DUT outputs
    // ------------------------------------------------------------
    logic signed [DATA_WIDTH-1:0] activation_out;
    logic                         activation_valid_out;

    logic signed [DATA_WIDTH-1:0] weight_out;
    logic                         weight_valid_out;

    logic signed [ACC_WIDTH-1:0] partial_sum;

    // ------------------------------------------------------------
    // Testbench bookkeeping
    // ------------------------------------------------------------
    logic signed [ACC_WIDTH-1:0] expected_partial_sum;

    integer error_count;
    integer i;

    logic signed [DATA_WIDTH-1:0] random_activation;
    logic signed [DATA_WIDTH-1:0] random_weight;
    logic                         random_activation_valid;
    logic                         random_weight_valid;
    logic                         random_clear;
    logic                         random_reset;


    // ============================================================
    // Instantiate DUT
    // ============================================================

    pe #(
        .DATA_WIDTH(DATA_WIDTH),
        .ACC_WIDTH(ACC_WIDTH)
    ) dut (
        .clk(clk),
        .reset(reset),
        .clear_acc(clear_acc),

        .activation_in(activation_in),
        .activation_valid_in(activation_valid_in),

        .weight_in(weight_in),
        .weight_valid_in(weight_valid_in),

        .activation_out(activation_out),
        .activation_valid_out(activation_valid_out),

        .weight_out(weight_out),
        .weight_valid_out(weight_valid_out),

        .partial_sum(partial_sum)
    );


    // ============================================================
    // Clock generation
    //
    // 10 ns clock period:
    //
    //      __    __    __
    // clk    |__|  |__|
    //
    //      5ns 5ns
    // ============================================================

    initial begin
        clk = 1'b0;
    end

    always #5 clk = ~clk;


    // ============================================================
    // Task: apply one cycle and automatically check the result
    // ============================================================

    task automatic apply_and_check(
        input logic                         rst,
        input logic                         clr,
        input logic signed [DATA_WIDTH-1:0] act,
        input logic                         act_valid,
        input logic signed [DATA_WIDTH-1:0] wgt,
        input logic                         wgt_valid,
        input string                        test_name
    );

        logic signed [(2*DATA_WIDTH)-1:0] expected_product;

        begin

            // ----------------------------------------------------
            // Change inputs on the falling edge.
            //
            // This gives them plenty of time to settle before
            // the PE samples them on the next rising edge.
            // ----------------------------------------------------
            @(negedge clk);

            reset               = rst;
            clear_acc           = clr;

            activation_in       = act;
            activation_valid_in = act_valid;

            weight_in           = wgt;
            weight_valid_in     = wgt_valid;

            expected_product = act * wgt;


            // ----------------------------------------------------
            // DUT samples inputs here
            // ----------------------------------------------------
            @(posedge clk);

            // Give nonblocking assignments time to update
            #1;


            // ====================================================
            // Reference model for partial_sum
            // ====================================================

            if (rst) begin
                expected_partial_sum = '0;
            end

            else if (clr) begin

                if (act_valid && wgt_valid)
                    expected_partial_sum = expected_product;
                else
                    expected_partial_sum = '0;

            end

            else if (act_valid && wgt_valid) begin

                expected_partial_sum =
                    expected_partial_sum + expected_product;

            end


            // ====================================================
            // Check activation forwarding
            // ====================================================

            if (rst) begin

                if (activation_out !== '0) begin
                    $error(
                        "%s: activation_out should reset to 0, got %0d",
                        test_name,
                        activation_out
                    );
                    error_count++;
                end

                if (activation_valid_out !== 1'b0) begin
                    $error(
                        "%s: activation_valid_out should reset to 0",
                        test_name
                    );
                    error_count++;
                end

            end

            else begin

                if (activation_out !== act) begin
                    $error(
                        "%s: activation forwarding failed. Expected %0d, got %0d",
                        test_name,
                        act,
                        activation_out
                    );
                    error_count++;
                end

                if (activation_valid_out !== act_valid) begin
                    $error(
                        "%s: activation valid forwarding failed. Expected %b, got %b",
                        test_name,
                        act_valid,
                        activation_valid_out
                    );
                    error_count++;
                end

            end


            // ====================================================
            // Check weight forwarding
            // ====================================================

            if (rst) begin

                if (weight_out !== '0) begin
                    $error(
                        "%s: weight_out should reset to 0, got %0d",
                        test_name,
                        weight_out
                    );
                    error_count++;
                end

                if (weight_valid_out !== 1'b0) begin
                    $error(
                        "%s: weight_valid_out should reset to 0",
                        test_name
                    );
                    error_count++;
                end

            end

            else begin

                if (weight_out !== wgt) begin
                    $error(
                        "%s: weight forwarding failed. Expected %0d, got %0d",
                        test_name,
                        wgt,
                        weight_out
                    );
                    error_count++;
                end

                if (weight_valid_out !== wgt_valid) begin
                    $error(
                        "%s: weight valid forwarding failed. Expected %b, got %b",
                        test_name,
                        wgt_valid,
                        weight_valid_out
                    );
                    error_count++;
                end

            end


            // ====================================================
            // Check partial sum
            // ====================================================

            if (partial_sum !== expected_partial_sum) begin

                $error(
                    "%s: partial_sum incorrect. Expected %0d, got %0d",
                    test_name,
                    expected_partial_sum,
                    partial_sum
                );

                error_count++;

            end

            else begin

                $display(
                    "PASS: %-35s | A=%4d V=%b | W=%4d V=%b | clear=%b reset=%b | psum=%0d",
                    test_name,
                    act,
                    act_valid,
                    wgt,
                    wgt_valid,
                    clr,
                    rst,
                    partial_sum
                );

            end

        end

    endtask


    // ============================================================
    // Main test sequence
    // ============================================================

    initial begin

        // --------------------------------------------------------
        // Initial values
        // --------------------------------------------------------
        reset               = 1'b0;
        clear_acc           = 1'b0;

        activation_in       = '0;
        activation_valid_in = 1'b0;

        weight_in           = '0;
        weight_valid_in     = 1'b0;

        expected_partial_sum = '0;
        error_count          = 0;


        $display("");
        $display("==========================================");
        $display("       Starting PE Testbench");
        $display("==========================================");
        $display("");


        // ========================================================
        // TEST 1: RESET
        // ========================================================

        apply_and_check(
            1'b1,
            1'b0,
            8'sd50,
            1'b1,
            -8'sd4,
            1'b1,
            "Reset clears PE"
        );


        // ========================================================
        // TEST 2: IDLE AFTER RESET
        // ========================================================

        apply_and_check(
            1'b0,
            1'b0,
            8'sd0,
            1'b0,
            8'sd0,
            1'b0,
            "Idle after reset"
        );


        // ========================================================
        // TEST 3: CLEAR + FIRST PRODUCT
        //
        // 3 * 4 = 12
        // ========================================================

        apply_and_check(
            1'b0,
            1'b1,
            8'sd3,
            1'b1,
            8'sd4,
            1'b1,
            "Start accumulation: 3 * 4"
        );


        // ========================================================
        // TEST 4: SECOND PRODUCT
        //
        // 12 + (2 * 5)
        // = 22
        // ========================================================

        apply_and_check(
            1'b0,
            1'b0,
            8'sd2,
            1'b1,
            8'sd5,
            1'b1,
            "Accumulate: + 2 * 5"
        );


        // ========================================================
        // TEST 5: THIRD PRODUCT
        //
        // 22 + (7 * 3)
        // = 43
        // ========================================================

        apply_and_check(
            1'b0,
            1'b0,
            8'sd7,
            1'b1,
            8'sd3,
            1'b1,
            "Accumulate: + 7 * 3"
        );


        // ========================================================
        // TEST 6: ACTIVATION VALID, WEIGHT INVALID
        //
        // No MAC should occur.
        // partial_sum should remain 43.
        //
        // Data itself should STILL be forwarded.
        // ========================================================

        apply_and_check(
            1'b0,
            1'b0,
            8'sd20,
            1'b1,
            8'sd10,
            1'b0,
            "Weight invalid - hold psum"
        );


        // ========================================================
        // TEST 7: WEIGHT VALID, ACTIVATION INVALID
        // ========================================================

        apply_and_check(
            1'b0,
            1'b0,
            8'sd10,
            1'b0,
            8'sd11,
            1'b1,
            "Activation invalid - hold psum"
        );


        // ========================================================
        // TEST 8: BOTH INVALID
        // ========================================================

        apply_and_check(
            1'b0,
            1'b0,
            8'sd100,
            1'b0,
            -8'sd100,
            1'b0,
            "Both invalid - hold psum"
        );


        // ========================================================
        // TEST 9: CLEAR WITHOUT VALID DATA
        //
        // clear_acc = 1
        // No valid operands
        //
        // partial_sum should become 0
        // ========================================================

        apply_and_check(
            1'b0,
            1'b1,
            8'sd5,
            1'b0,
            8'sd5,
            1'b0,
            "Clear accumulator without MAC"
        );


        // ========================================================
        // TEST 10: POSITIVE * NEGATIVE
        //
        // 7 * -3 = -21
        // ========================================================

        apply_and_check(
            1'b0,
            1'b1,
            8'sd7,
            1'b1,
            -8'sd3,
            1'b1,
            "Signed: positive * negative"
        );


        // ========================================================
        // TEST 11: NEGATIVE * NEGATIVE
        //
        // -2 * -4 = 8
        //
        // old psum = -21
        //
        // -21 + 8 = -13
        // ========================================================

        apply_and_check(
            1'b0,
            1'b0,
            -8'sd2,
            1'b1,
            -8'sd4,
            1'b1,
            "Signed: negative * negative"
        );


        // ========================================================
        // TEST 12: NEGATIVE * POSITIVE
        //
        // -5 * 6 = -30
        //
        // -13 - 30 = -43
        // ========================================================

        apply_and_check(
            1'b0,
            1'b0,
            -8'sd5,
            1'b1,
            8'sd6,
            1'b1,
            "Signed: negative * positive"
        );


        // ========================================================
        // TEST 13: CLEAR STARTS A NEW RESULT
        //
        // Old psum should be discarded.
        //
        // 10 * 10 = 100
        // ========================================================

        apply_and_check(
            1'b0,
            1'b1,
            8'sd10,
            1'b1,
            8'sd10,
            1'b1,
            "Clear and immediately MAC"
        );


        // ========================================================
        // TEST 14: MAXIMUM POSITIVE VALUES
        //
        // 127 * 127 = 16129
        // ========================================================

        apply_and_check(
            1'b0,
            1'b1,
            8'sd127,
            1'b1,
            8'sd127,
            1'b1,
            "Maximum positive operands"
        );


        // ========================================================
        // TEST 15: MOST NEGATIVE VALUES
        //
        // -128 * -128 = 16384
        //
        // This is a particularly important multiplication-width
        // test because 16384 requires the full product width.
        // ========================================================

        apply_and_check(
            1'b0,
            1'b1,
            8'sh80,
            1'b1,
            8'sh80,
            1'b1,
            "Minimum signed operands"
        );


        // ========================================================
        // TEST 16: -128 * 127
        //
        // = -16256
        // ========================================================

        apply_and_check(
            1'b0,
            1'b1,
            8'sh80,
            1'b1,
            8'sd127,
            1'b1,
            "Signed boundary mixed signs"
        );


        // ========================================================
        // TEST 17: RESET HAS HIGHEST PRIORITY
        //
        // reset = 1
        // clear = 1
        // both operands valid
        //
        // Entire PE should reset.
        // ========================================================

        apply_and_check(
            1'b1,
            1'b1,
            8'sd20,
            1'b1,
            8'sd20,
            1'b1,
            "Reset priority over clear/MAC"
        );


        // ========================================================
        // TEST 18: RANDOMIZED TESTING
        //
        // The exact same reference model is used to predict
        // what the DUT should do.
        // ========================================================

        $display("");
        $display("------------------------------------------");
        $display("Starting randomized tests");
        $display("------------------------------------------");
        $display("");

        for (i = 0; i < 100; i++) begin

            // Random 8-bit patterns automatically include
            // both positive and negative signed numbers.
            random_activation = $urandom;
            random_weight     = $urandom;

            random_activation_valid = $urandom_range(0, 1);
            random_weight_valid     = $urandom_range(0, 1);

            // Roughly 10% of cycles clear the accumulator
            random_clear = ($urandom_range(0, 9) == 0);

            // Roughly 2% of cycles perform a full reset
            random_reset = ($urandom_range(0, 49) == 0);

            apply_and_check(
                random_reset,
                random_clear,
                random_activation,
                random_activation_valid,
                random_weight,
                random_weight_valid,
                $sformatf("Random test %0d", i)
            );

        end


        // ========================================================
        // Final result
        // ========================================================

        $display("");
        $display("==========================================");

        if (error_count == 0) begin
            $display("ALL TESTS PASSED!");
        end
        else begin
            $display("TESTBENCH FAILED WITH %0d ERRORS", error_count);
        end

        $display("==========================================");
        $display("");

        $finish;

    end


    // ============================================================
    // Waveform generation
    // ============================================================

    initial begin

        $dumpfile("pe_tb.vcd");
        $dumpvars(0, pe_tb);

    end

endmodule