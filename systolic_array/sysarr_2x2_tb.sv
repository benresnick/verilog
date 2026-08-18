`timescale 1ns/1ps

module sysarr_2x2_tb;

    // ============================================================
    // Parameters
    // ============================================================

    localparam DATA_WIDTH = 8;
    localparam ACC_WIDTH  = 32;


    // ============================================================
    // DUT Inputs
    // ============================================================

    logic clk;
    logic reset;
    logic clear_acc;

    // Activations enter from the left side of each row
    logic signed [DATA_WIDTH-1:0] activation_in_00;
    logic                         activation_valid_in_00;

    logic signed [DATA_WIDTH-1:0] activation_in_10;
    logic                         activation_valid_in_10;

    // Weights enter from the top of each column
    logic signed [DATA_WIDTH-1:0] weight_in_00;
    logic                         weight_valid_in_00;

    logic signed [DATA_WIDTH-1:0] weight_in_01;
    logic                         weight_valid_in_01;


    // ============================================================
    // DUT Outputs
    // ============================================================

    logic signed [ACC_WIDTH-1:0] partial_sum_00;
    logic signed [ACC_WIDTH-1:0] partial_sum_01;
    logic signed [ACC_WIDTH-1:0] partial_sum_10;
    logic signed [ACC_WIDTH-1:0] partial_sum_11;


    // ============================================================
    // Testbench bookkeeping
    // ============================================================

    integer error_count;
    integer i;

    logic signed [DATA_WIDTH-1:0] random_a00;
    logic signed [DATA_WIDTH-1:0] random_a01;
    logic signed [DATA_WIDTH-1:0] random_a10;
    logic signed [DATA_WIDTH-1:0] random_a11;

    logic signed [DATA_WIDTH-1:0] random_b00;
    logic signed [DATA_WIDTH-1:0] random_b01;
    logic signed [DATA_WIDTH-1:0] random_b10;
    logic signed [DATA_WIDTH-1:0] random_b11;


    // ============================================================
    // Instantiate DUT
    // ============================================================

    sysarr_2x2 #(
        .DATA_WIDTH(DATA_WIDTH),
        .ACC_WIDTH(ACC_WIDTH)
    ) dut (
        .clk(clk),
        .reset(reset),
        .clear_acc(clear_acc),

        .activation_in_00(activation_in_00),
        .activation_valid_in_00(activation_valid_in_00),

        .activation_in_10(activation_in_10),
        .activation_valid_in_10(activation_valid_in_10),

        .weight_in_00(weight_in_00),
        .weight_valid_in_00(weight_valid_in_00),

        .weight_in_01(weight_in_01),
        .weight_valid_in_01(weight_valid_in_01),

        .partial_sum_00(partial_sum_00),
        .partial_sum_01(partial_sum_01),
        .partial_sum_10(partial_sum_10),
        .partial_sum_11(partial_sum_11)
    );


    // ============================================================
    // Clock generation
    //
    // 10 ns clock period
    // ============================================================

    initial begin
        clk = 1'b0;
    end

    always #5 clk = ~clk;


    // ============================================================
    // TASK: Drive one complete clock cycle
    //
    // Inputs change on the falling edge.
    // The DUT samples them on the next rising edge.
    // ============================================================

    task automatic drive_cycle(
        input logic rst,
        input logic clr,

        input logic signed [DATA_WIDTH-1:0] act_row0,
        input logic                         act_row0_valid,

        input logic signed [DATA_WIDTH-1:0] act_row1,
        input logic                         act_row1_valid,

        input logic signed [DATA_WIDTH-1:0] wgt_col0,
        input logic                         wgt_col0_valid,

        input logic signed [DATA_WIDTH-1:0] wgt_col1,
        input logic                         wgt_col1_valid
    );

        begin

            @(negedge clk);

            reset     = rst;
            clear_acc = clr;

            activation_in_00       = act_row0;
            activation_valid_in_00 = act_row0_valid;

            activation_in_10       = act_row1;
            activation_valid_in_10 = act_row1_valid;

            weight_in_00       = wgt_col0;
            weight_valid_in_00 = wgt_col0_valid;

            weight_in_01       = wgt_col1;
            weight_valid_in_01 = wgt_col1_valid;

            @(posedge clk);

            // Allow nonblocking assignments in the DUT to update
            #1;

        end

    endtask


    // ============================================================
    // TASK: Check all four stationary outputs
    // ============================================================

    task automatic check_partial_sums(
        input longint signed expected_00,
        input longint signed expected_01,
        input longint signed expected_10,
        input longint signed expected_11,

        input string test_name
    );

        begin

            if ($signed(partial_sum_00) !== expected_00) begin
                $error(
                    "%s: C00 incorrect. Expected %0d, got %0d",
                    test_name,
                    expected_00,
                    $signed(partial_sum_00)
                );
                error_count++;
            end

            if ($signed(partial_sum_01) !== expected_01) begin
                $error(
                    "%s: C01 incorrect. Expected %0d, got %0d",
                    test_name,
                    expected_01,
                    $signed(partial_sum_01)
                );
                error_count++;
            end

            if ($signed(partial_sum_10) !== expected_10) begin
                $error(
                    "%s: C10 incorrect. Expected %0d, got %0d",
                    test_name,
                    expected_10,
                    $signed(partial_sum_10)
                );
                error_count++;
            end

            if ($signed(partial_sum_11) !== expected_11) begin
                $error(
                    "%s: C11 incorrect. Expected %0d, got %0d",
                    test_name,
                    expected_11,
                    $signed(partial_sum_11)
                );
                error_count++;
            end

        end

    endtask


    // ============================================================
    // TASK: Clear all accumulators
    //
    // clear_acc is asserted on an EMPTY cycle.
    //
    // This is important because clear_acc is broadcast to all PEs.
    // ============================================================

    task automatic clear_array;

        begin

            drive_cycle(
                1'b0,          // reset
                1'b1,          // clear_acc

                '0, 1'b0,      // row 0 activation
                '0, 1'b0,      // row 1 activation

                '0, 1'b0,      // column 0 weight
                '0, 1'b0       // column 1 weight
            );

            check_partial_sums(
                0, 0,
                0, 0,
                "clear_acc"
            );

        end

    endtask


    // ============================================================
    // TASK: Perform a complete 2x2 matrix multiplication
    //
    //
    //            | a00 a01 |       | b00 b01 |
    //        A = |         |   B = |         |
    //            | a10 a11 |       | b10 b11 |
    //
    //
    //                      C = A * B
    //
    //
    // C00 = a00*b00 + a01*b10
    // C01 = a00*b01 + a01*b11
    // C10 = a10*b00 + a11*b10
    // C11 = a10*b01 + a11*b11
    //
    //
    // Systolic input schedule:
    //
    // Cycle 1:
    //
    //      row0 = a00
    //      row1 = invalid
    //      col0 = b00
    //      col1 = invalid
    //
    //
    // Cycle 2:
    //
    //      row0 = a01
    //      row1 = a10
    //      col0 = b10
    //      col1 = b01
    //
    //
    // Cycle 3:
    //
    //      row0 = invalid
    //      row1 = a11
    //      col0 = invalid
    //      col1 = b11
    //
    //
    // Cycle 4:
    //
    //      all external inputs invalid
    //
    //      This allows a11 and b11 to reach PE11.
    //
    // ============================================================

    task automatic run_matrix_test(
        input logic signed [DATA_WIDTH-1:0] a00,
        input logic signed [DATA_WIDTH-1:0] a01,
        input logic signed [DATA_WIDTH-1:0] a10,
        input logic signed [DATA_WIDTH-1:0] a11,

        input logic signed [DATA_WIDTH-1:0] b00,
        input logic signed [DATA_WIDTH-1:0] b01,
        input logic signed [DATA_WIDTH-1:0] b10,
        input logic signed [DATA_WIDTH-1:0] b11,

        input string test_name
    );

        // Widen operands before doing reference arithmetic.
        longint signed la00;
        longint signed la01;
        longint signed la10;
        longint signed la11;

        longint signed lb00;
        longint signed lb01;
        longint signed lb10;
        longint signed lb11;

        longint signed expected_00;
        longint signed expected_01;
        longint signed expected_10;
        longint signed expected_11;

        integer errors_before;

        begin

            errors_before = error_count;

            // ----------------------------------------------------
            // Convert operands to wide signed integers
            // ----------------------------------------------------

            la00 = a00;
            la01 = a01;
            la10 = a10;
            la11 = a11;

            lb00 = b00;
            lb01 = b01;
            lb10 = b10;
            lb11 = b11;


            // ----------------------------------------------------
            // Software/reference matrix multiplication
            // ----------------------------------------------------

            expected_00 = la00 * lb00 + la01 * lb10;
            expected_01 = la00 * lb01 + la01 * lb11;

            expected_10 = la10 * lb00 + la11 * lb10;
            expected_11 = la10 * lb01 + la11 * lb11;


            // ----------------------------------------------------
            // Start with clean stationary accumulators
            // ----------------------------------------------------

            clear_array();


            // ----------------------------------------------------
            // SYSTOLIC CYCLE 1
            //
            // PE00 receives:
            //
            //      a00 * b00
            // ----------------------------------------------------

            drive_cycle(
                1'b0,
                1'b0,

                a00, 1'b1,
                '0,  1'b0,

                b00, 1'b1,
                '0,  1'b0
            );


            // ----------------------------------------------------
            // SYSTOLIC CYCLE 2
            //
            // PE00: a01 * b10
            // PE01: a00 * b01
            // PE10: a10 * b00
            // ----------------------------------------------------

            drive_cycle(
                1'b0,
                1'b0,

                a01, 1'b1,
                a10, 1'b1,

                b10, 1'b1,
                b01, 1'b1
            );


            // ----------------------------------------------------
            // SYSTOLIC CYCLE 3
            //
            // PE01: a01 * b11
            // PE10: a11 * b10
            // PE11: a10 * b01
            // ----------------------------------------------------

            drive_cycle(
                1'b0,
                1'b0,

                '0,  1'b0,
                a11, 1'b1,

                '0,  1'b0,
                b11, 1'b1
            );


            // ----------------------------------------------------
            // SYSTOLIC CYCLE 4
            //
            // No new external data.
            //
            // Internally:
            //
            // PE11 receives a11 * b11
            // ----------------------------------------------------

            drive_cycle(
                1'b0,
                1'b0,

                '0, 1'b0,
                '0, 1'b0,

                '0, 1'b0,
                '0, 1'b0
            );


            // ----------------------------------------------------
            // Check final matrix
            // ----------------------------------------------------

            check_partial_sums(
                expected_00,
                expected_01,
                expected_10,
                expected_11,
                test_name
            );


            if (error_count == errors_before) begin

                $display(
                    "PASS: %-35s | C = [[%0d, %0d], [%0d, %0d]]",
                    test_name,
                    expected_00,
                    expected_01,
                    expected_10,
                    expected_11
                );

            end

        end

    endtask


    // ============================================================
    // Main Test Sequence
    // ============================================================

    initial begin

        // --------------------------------------------------------
        // Initialize signals
        // --------------------------------------------------------

        reset     = 1'b0;
        clear_acc = 1'b0;

        activation_in_00       = '0;
        activation_valid_in_00 = 1'b0;

        activation_in_10       = '0;
        activation_valid_in_10 = 1'b0;

        weight_in_00       = '0;
        weight_valid_in_00 = 1'b0;

        weight_in_01       = '0;
        weight_valid_in_01 = 1'b0;

        error_count = 0;


        $display("");
        $display("================================================");
        $display("          Starting 2x2 Systolic Array TB");
        $display("================================================");
        $display("");


        // ========================================================
        // TEST 1: GLOBAL RESET
        // ========================================================

        drive_cycle(
            1'b1,
            1'b0,

            8'sd10, 1'b1,
            8'sd20, 1'b1,

            8'sd30, 1'b1,
            8'sd40, 1'b1
        );

        check_partial_sums(
            0, 0,
            0, 0,
            "Global reset"
        );


        // Check that reset also cleared pipeline valid bits

        if (dut.act_valid_00_to_01 !== 1'b0) begin
            $error("Reset failed to clear act_valid_00_to_01");
            error_count++;
        end

        if (dut.act_valid_10_to_11 !== 1'b0) begin
            $error("Reset failed to clear act_valid_10_to_11");
            error_count++;
        end

        if (dut.weight_valid_00_to_10 !== 1'b0) begin
            $error("Reset failed to clear weight_valid_00_to_10");
            error_count++;
        end

        if (dut.weight_valid_01_to_11 !== 1'b0) begin
            $error("Reset failed to clear weight_valid_01_to_11");
            error_count++;
        end


        // ========================================================
        // TEST 2: RESET PRIORITY
        //
        // reset = 1
        // clear = 1
        // all operands valid
        //
        // Reset should still win.
        // ========================================================

        drive_cycle(
            1'b1,
            1'b1,

            8'sd5, 1'b1,
            8'sd6, 1'b1,

            8'sd7, 1'b1,
            8'sd8, 1'b1
        );

        check_partial_sums(
            0, 0,
            0, 0,
            "Reset priority"
        );


        // ========================================================
        // TEST 3: BROADCAST CLEAR
        // ========================================================

        clear_array();


        // ========================================================
        // TEST 4: EXPLICIT CYCLE-BY-CYCLE SYSTOLIC TEST
        //
        //
        //       A                B
        //
        //     | 1 2 |          | 5 6 |
        //     | 3 4 |          | 7 8 |
        //
        //
        // Expected:
        //
        //       C
        //
        //     | 19 22 |
        //     | 43 50 |
        //
        //
        // This test checks INTERMEDIATE partial sums too.
        // ========================================================

        $display("");
        $display("-----------------------------------------------");
        $display("Cycle-by-cycle systolic timing test");
        $display("-----------------------------------------------");


        clear_array();


        // --------------------------------------------------------
        // Cycle 1
        //
        // PE00:
        //      1 * 5 = 5
        //
        // All other PEs should still be zero.
        // --------------------------------------------------------

        drive_cycle(
            1'b0,
            1'b0,

            8'sd1, 1'b1,
            8'sd0, 1'b0,

            8'sd5, 1'b1,
            8'sd0, 1'b0
        );

        check_partial_sums(
            5, 0,
            0, 0,
            "Canonical matrix - cycle 1"
        );


        // Check that data was registered toward neighbors

        if ($signed(dut.act_00_to_01) !== 1 ||
            dut.act_valid_00_to_01 !== 1'b1) begin

            $error(
                "Cycle 1: A00 was not forwarded correctly from PE00 to PE01"
            );

            error_count++;

        end


        if ($signed(dut.weight_00_to_10) !== 5 ||
            dut.weight_valid_00_to_10 !== 1'b1) begin

            $error(
                "Cycle 1: B00 was not forwarded correctly from PE00 to PE10"
            );

            error_count++;

        end


        // --------------------------------------------------------
        // Cycle 2
        //
        // PE00:
        //      5 + 2*7 = 19
        //
        // PE01:
        //      1*6 = 6
        //
        // PE10:
        //      3*5 = 15
        //
        // PE11:
        //      still 0
        // --------------------------------------------------------

        drive_cycle(
            1'b0,
            1'b0,

            8'sd2, 1'b1,
            8'sd3, 1'b1,

            8'sd7, 1'b1,
            8'sd6, 1'b1
        );

        check_partial_sums(
            19, 6,
            15, 0,
            "Canonical matrix - cycle 2"
        );


        // --------------------------------------------------------
        // Check forwarding after cycle 2
        // --------------------------------------------------------

        if ($signed(dut.act_00_to_01) !== 2 ||
            dut.act_valid_00_to_01 !== 1'b1) begin

            $error(
                "Cycle 2: A01 was not forwarded correctly toward PE01"
            );

            error_count++;

        end


        if ($signed(dut.act_10_to_11) !== 3 ||
            dut.act_valid_10_to_11 !== 1'b1) begin

            $error(
                "Cycle 2: A10 was not forwarded correctly toward PE11"
            );

            error_count++;

        end


        if ($signed(dut.weight_00_to_10) !== 7 ||
            dut.weight_valid_00_to_10 !== 1'b1) begin

            $error(
                "Cycle 2: B10 was not forwarded correctly toward PE10"
            );

            error_count++;

        end


        if ($signed(dut.weight_01_to_11) !== 6 ||
            dut.weight_valid_01_to_11 !== 1'b1) begin

            $error(
                "Cycle 2: B01 was not forwarded correctly toward PE11"
            );

            error_count++;

        end


        // --------------------------------------------------------
        // Cycle 3
        //
        // PE00 = done = 19
        //
        // PE01:
        //      6 + 2*8 = 22
        //
        // PE10:
        //      15 + 4*7 = 43
        //
        // PE11:
        //      3*6 = 18
        // --------------------------------------------------------

        drive_cycle(
            1'b0,
            1'b0,

            8'sd0, 1'b0,
            8'sd4, 1'b1,

            8'sd0, 1'b0,
            8'sd8, 1'b1
        );

        check_partial_sums(
            19, 22,
            43, 18,
            "Canonical matrix - cycle 3"
        );


        // --------------------------------------------------------
        // Cycle 4: flush
        //
        // PE11 receives:
        //
        //      4 * 8
        //
        // Therefore:
        //
        //      18 + 32 = 50
        // --------------------------------------------------------

        drive_cycle(
            1'b0,
            1'b0,

            '0, 1'b0,
            '0, 1'b0,

            '0, 1'b0,
            '0, 1'b0
        );

        check_partial_sums(
            19, 22,
            43, 50,
            "Canonical matrix - final"
        );

        $display(
            "PASS: Canonical cycle-by-cycle systolic movement"
        );


        // ========================================================
        // TEST 5: NORMAL POSITIVE MATRIX
        // ========================================================

        run_matrix_test(
            8'sd1, 8'sd2,
            8'sd3, 8'sd4,

            8'sd5, 8'sd6,
            8'sd7, 8'sd8,

            "Positive matrix multiplication"
        );


        // ========================================================
        // TEST 6: SIGNED MATRIX
        //
        // A = [-1   2]
        //     [ 3  -4]
        //
        // B = [ 5  -6]
        //     [-7   8]
        //
        // C = [-19   22]
        //     [ 43  -50]
        // ========================================================

        run_matrix_test(
            -8'sd1,  8'sd2,
             8'sd3, -8'sd4,

             8'sd5, -8'sd6,
            -8'sd7,  8'sd8,

            "Signed matrix multiplication"
        );


        // ========================================================
        // TEST 7: ZERO MATRIX
        // ========================================================

        run_matrix_test(
            8'sd0, 8'sd0,
            8'sd0, 8'sd0,

            8'sd5,  8'sd6,
            8'sd7, -8'sd8,

            "Zero A matrix"
        );


        // ========================================================
        // TEST 8: IDENTITY MATRIX
        //
        // A * I should equal A
        // ========================================================

        run_matrix_test(
             8'sd12, -8'sd7,
             8'sd25,  8'sd9,

             8'sd1, 8'sd0,
             8'sd0, 8'sd1,

            "Multiply by identity"
        );


        // ========================================================
        // TEST 9: ALL ONES
        //
        // Each output should be 2
        // ========================================================

        run_matrix_test(
            8'sd1, 8'sd1,
            8'sd1, 8'sd1,

            8'sd1, 8'sd1,
            8'sd1, 8'sd1,

            "All ones"
        );


        // ========================================================
        // TEST 10: MAXIMUM POSITIVE OPERANDS
        //
        // 127*127 + 127*127 = 32258
        // ========================================================

        run_matrix_test(
            8'sd127, 8'sd127,
            8'sd127, 8'sd127,

            8'sd127, 8'sd127,
            8'sd127, 8'sd127,

            "Maximum positive values"
        );


        // ========================================================
        // TEST 11: MINIMUM SIGNED OPERANDS
        //
        // (-128)*(-128) + (-128)*(-128)
        //
        // = 32768
        //
        // This tests that the product and accumulator widths
        // preserve the full signed result.
        // ========================================================

        run_matrix_test(
            8'sh80, 8'sh80,
            8'sh80, 8'sh80,

            8'sh80, 8'sh80,
            8'sh80, 8'sh80,

            "Minimum signed values"
        );


        // ========================================================
        // TEST 12: VALID GATING -- ACTIVATIONS ONLY
        //
        // Even though activations move through the array,
        // no weight is valid, so NO PE should accumulate.
        // ========================================================

        clear_array();

        drive_cycle(
            1'b0, 1'b0,
            8'sd10, 1'b1,
            8'sd20, 1'b1,
            '0, 1'b0,
            '0, 1'b0
        );

        drive_cycle(
            1'b0, 1'b0,
            8'sd30, 1'b1,
            8'sd40, 1'b1,
            '0, 1'b0,
            '0, 1'b0
        );

        drive_cycle(
            1'b0, 1'b0,
            '0, 1'b0,
            '0, 1'b0,
            '0, 1'b0,
            '0, 1'b0
        );

        check_partial_sums(
            0, 0,
            0, 0,
            "Activations only"
        );


        // ========================================================
        // TEST 13: VALID GATING -- WEIGHTS ONLY
        //
        // No activation valid -> no MAC.
        // ========================================================

        clear_array();

        drive_cycle(
            1'b0, 1'b0,
            '0, 1'b0,
            '0, 1'b0,
            8'sd10, 1'b1,
            8'sd20, 1'b1
        );

        drive_cycle(
            1'b0, 1'b0,
            '0, 1'b0,
            '0, 1'b0,
            8'sd30, 1'b1,
            8'sd40, 1'b1
        );

        drive_cycle(
            1'b0, 1'b0,
            '0, 1'b0,
            '0, 1'b0,
            '0, 1'b0,
            '0, 1'b0
        );

        check_partial_sums(
            0, 0,
            0, 0,
            "Weights only"
        );


        // ========================================================
        // TEST 14: INVALID BUBBLE PROPAGATION
        //
        // Start from canonical matrix:
        //
        // A = [1 2]
        //     [3 4]
        //
        // B = [5 6]
        //     [7 8]
        //
        // But intentionally mark B10 = 7 INVALID.
        //
        // Therefore:
        //
        // C00 only gets 1*5       = 5
        // C01 remains             = 22
        // C10 only gets 3*5       = 15
        // C11 remains             = 50
        //
        // This verifies that weight_valid moves DOWN with B10.
        // ========================================================

        clear_array();


        // Cycle 1

        drive_cycle(
            1'b0, 1'b0,

            8'sd1, 1'b1,
            '0,    1'b0,

            8'sd5, 1'b1,
            '0,    1'b0
        );


        // Cycle 2
        //
        // B10 has value 7 but valid = 0

        drive_cycle(
            1'b0, 1'b0,

            8'sd2, 1'b1,
            8'sd3, 1'b1,

            8'sd7, 1'b0,
            8'sd6, 1'b1
        );


        // Cycle 3

        drive_cycle(
            1'b0, 1'b0,

            '0,    1'b0,
            8'sd4, 1'b1,

            '0,    1'b0,
            8'sd8, 1'b1
        );


        // Cycle 4: flush

        drive_cycle(
            1'b0, 1'b0,

            '0, 1'b0,
            '0, 1'b0,

            '0, 1'b0,
            '0, 1'b0
        );


        check_partial_sums(
            5, 22,
            15, 50,
            "Invalid weight bubble propagation"
        );


        // ========================================================
        // TEST 15: CLEAR REMOVES PREVIOUS RESULT
        //
        // Run one computation, clear, then run another.
        // The second result must NOT contain the first.
        // ========================================================

        run_matrix_test(
            8'sd10, 8'sd20,
            8'sd30, 8'sd40,

            8'sd2, 8'sd3,
            8'sd4, 8'sd5,

            "First matrix before reuse"
        );

        run_matrix_test(
            8'sd1, 8'sd0,
            8'sd0, 8'sd1,

            8'sd9,  8'sd10,
            8'sd11, 8'sd12,

            "Reuse after clear"
        );


        // ========================================================
        // TEST 16: RANDOMIZED MATRIX MULTIPLICATION
        //
        // Generate 100 random signed 8-bit matrices.
        //
        // Each one is compared to a software/reference
        // matrix multiplication.
        // ========================================================

        $display("");
        $display("-----------------------------------------------");
        $display("Starting 100 randomized matrix tests");
        $display("-----------------------------------------------");
        $display("");


        for (i = 0; i < 100; i++) begin

            random_a00 = $urandom;
            random_a01 = $urandom;
            random_a10 = $urandom;
            random_a11 = $urandom;

            random_b00 = $urandom;
            random_b01 = $urandom;
            random_b10 = $urandom;
            random_b11 = $urandom;

            run_matrix_test(
                random_a00,
                random_a01,
                random_a10,
                random_a11,

                random_b00,
                random_b01,
                random_b10,
                random_b11,

                $sformatf("Random matrix %0d", i)
            );

        end


        // ========================================================
        // Final result
        // ========================================================

        $display("");
        $display("================================================");

        if (error_count == 0) begin

            $display("ALL 2x2 SYSTOLIC ARRAY TESTS PASSED!");

        end
        else begin

            $display(
                "TESTBENCH FAILED WITH %0d ERRORS",
                error_count
            );

        end

        $display("================================================");
        $display("");

        $finish;

    end


    // ============================================================
    // Waveform generation
    // ============================================================

    initial begin

        $dumpfile("sysarr_2x2_tb.vcd");
        $dumpvars(0, sysarr_2x2_tb);

    end

endmodule