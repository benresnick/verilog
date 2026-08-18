`timescale 1ns/1ps

// Regression testbench for multiple systolic-array shapes.  INNER_DIM is the
// number of MAC terms in each output; it is independent of the array shape.
module sysarr_sized_tb #(
    parameter integer ROWS      = 2,
    parameter integer COLS      = 2,
    parameter integer INNER_DIM = 2,
    parameter integer DATA_WIDTH = 8,
    parameter integer ACC_WIDTH  = 32
)(
    output logic done,
    output logic passed
);

    logic clk;
    logic reset;
    logic clear_acc;

    logic signed [DATA_WIDTH-1:0] activation_in [0:ROWS-1];
    logic                         activation_valid_in [0:ROWS-1];
    logic signed [DATA_WIDTH-1:0] weight_in [0:COLS-1];
    logic                         weight_valid_in [0:COLS-1];
    logic signed [ACC_WIDTH-1:0] partial_sum [0:ROWS-1][0:COLS-1];

    logic signed [DATA_WIDTH-1:0] a_matrix [0:ROWS-1][0:INNER_DIM-1];
    logic signed [DATA_WIDTH-1:0] b_matrix [0:INNER_DIM-1][0:COLS-1];
    longint signed expected [0:ROWS-1][0:COLS-1];
    integer error_count;

    sysarr #(
        .ROWS(ROWS),
        .COLS(COLS),
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
        .partial_sum(partial_sum)
    );

    initial clk = 1'b0;
    always #5 clk = ~clk;

    task automatic drive_empty(input logic rst, input logic clr);
        integer r;
        integer c;
        begin
            @(negedge clk);
            reset = rst;
            clear_acc = clr;
            for (r = 0; r < ROWS; r++) begin
                activation_in[r] = '0;
                activation_valid_in[r] = 1'b0;
            end
            for (c = 0; c < COLS; c++) begin
                weight_in[c] = '0;
                weight_valid_in[c] = 1'b0;
            end
            @(posedge clk);
            #1;
        end
    endtask

    task automatic check_results(input string test_name);
        integer r;
        integer c;
        begin
            for (r = 0; r < ROWS; r++) begin
                for (c = 0; c < COLS; c++) begin
                    if ($signed(partial_sum[r][c]) !== expected[r][c]) begin
                        $error(
                            "%0dx%0d, K=%0d, %s: C[%0d][%0d] expected %0d, got %0d",
                            ROWS, COLS, INNER_DIM, test_name, r, c,
                            expected[r][c], $signed(partial_sum[r][c])
                        );
                        error_count++;
                    end
                end
            end
        end
    endtask

    task automatic check_all_zero(input string test_name);
        integer r;
        integer c;
        begin
            for (r = 0; r < ROWS; r++) begin
                for (c = 0; c < COLS; c++) begin
                    expected[r][c] = 0;
                end
            end
            check_results(test_name);
        end
    endtask

    // test_kind 0: mixed signed values; 1: identity-like B; 2: all ones.
    task automatic build_matrices(input integer test_kind);
        integer r;
        integer c;
        integer k;
        begin
            for (r = 0; r < ROWS; r++) begin
                for (k = 0; k < INNER_DIM; k++) begin
                    if (test_kind == 2)
                        a_matrix[r][k] = 1;
                    else
                        a_matrix[r][k] = ((r * 5 + k * 3 + 2) % 15) - 7;
                end
            end

            for (k = 0; k < INNER_DIM; k++) begin
                for (c = 0; c < COLS; c++) begin
                    if (test_kind == 2)
                        b_matrix[k][c] = 1;
                    else if (test_kind == 1)
                        b_matrix[k][c] = (k == c) ? 1 : 0;
                    else
                        b_matrix[k][c] = ((k * 7 + c * 4 + 1) % 17) - 8;
                end
            end

            for (r = 0; r < ROWS; r++) begin
                for (c = 0; c < COLS; c++) begin
                    expected[r][c] = 0;
                    for (k = 0; k < INNER_DIM; k++) begin
                        expected[r][c] = expected[r][c]
                                       + $signed(a_matrix[r][k]) * $signed(b_matrix[k][c]);
                    end
                end
            end
        end
    endtask

    task automatic run_matrix_test(input integer test_kind, input string test_name);
        integer r;
        integer c;
        integer k;
        integer cycle;
        begin
            build_matrices(test_kind);
            drive_empty(1'b0, 1'b1);

            // At cycle t, row r receives A[r][t-r] and column c receives
            // B[t-c][c].  This diagonal skew makes operands meet at PE[r][c].
            for (cycle = 0; cycle <= INNER_DIM + ROWS + COLS - 3; cycle++) begin
                @(negedge clk);
                reset = 1'b0;
                clear_acc = 1'b0;
                for (r = 0; r < ROWS; r++) begin
                    k = cycle - r;
                    activation_valid_in[r] = (k >= 0 && k < INNER_DIM);
                    activation_in[r] = activation_valid_in[r] ? a_matrix[r][k] : '0;
                end
                for (c = 0; c < COLS; c++) begin
                    k = cycle - c;
                    weight_valid_in[c] = (k >= 0 && k < INNER_DIM);
                    weight_in[c] = weight_valid_in[c] ? b_matrix[k][c] : '0;
                end
                @(posedge clk);
                #1;
            end
            check_results(test_name);
        end
    endtask

    initial begin
        reset = 1'b0;
        clear_acc = 1'b0;
        done = 1'b0;
        passed = 1'b0;
        error_count = 0;

        // Reset is deliberately issued with no data, then checked at every PE.
        drive_empty(1'b1, 1'b0);
        check_all_zero("global reset");
        drive_empty(1'b0, 1'b1);
        check_all_zero("broadcast clear");

        run_matrix_test(0, "mixed signed matrix multiplication");
        run_matrix_test(1, "identity-like matrix multiplication");
        run_matrix_test(2, "all ones matrix multiplication");

        passed = (error_count == 0);
        if (passed)
            $display("PASS: %0dx%0d systolic array (K=%0d)", ROWS, COLS, INNER_DIM);
        else
            $display("FAIL: %0dx%0d systolic array (K=%0d): %0d errors", ROWS, COLS, INNER_DIM, error_count);
        done = 1'b1;
    end
endmodule

module sysarr_multisize_tb;
    logic done_1x1, done_2x2, done_4x4, done_8x8, done_16x16, done_32x32;
    logic done_2x4, done_4x2, done_4x8, done_8x4;
    logic pass_1x1, pass_2x2, pass_4x4, pass_8x8, pass_16x16, pass_32x32;
    logic pass_2x4, pass_4x2, pass_4x8, pass_8x4;

    // Conventional square array sizes.
    sysarr_sized_tb #(.ROWS(1),  .COLS(1),  .INNER_DIM(1))  test_1x1  (.done(done_1x1),  .passed(pass_1x1));
    sysarr_sized_tb #(.ROWS(2),  .COLS(2),  .INNER_DIM(2))  test_2x2  (.done(done_2x2),  .passed(pass_2x2));
    sysarr_sized_tb #(.ROWS(4),  .COLS(4),  .INNER_DIM(4))  test_4x4  (.done(done_4x4),  .passed(pass_4x4));
    sysarr_sized_tb #(.ROWS(8),  .COLS(8),  .INNER_DIM(8))  test_8x8  (.done(done_8x8),  .passed(pass_8x8));
    sysarr_sized_tb #(.ROWS(16), .COLS(16), .INNER_DIM(16)) test_16x16(.done(done_16x16), .passed(pass_16x16));
    sysarr_sized_tb #(.ROWS(32), .COLS(32), .INNER_DIM(32)) test_32x32(.done(done_32x32), .passed(pass_32x32));

    // Rectangular cases verify ROWS and COLS can vary independently.
    sysarr_sized_tb #(.ROWS(2), .COLS(4), .INNER_DIM(3)) test_2x4(.done(done_2x4), .passed(pass_2x4));
    sysarr_sized_tb #(.ROWS(4), .COLS(2), .INNER_DIM(3)) test_4x2(.done(done_4x2), .passed(pass_4x2));
    sysarr_sized_tb #(.ROWS(4), .COLS(8), .INNER_DIM(5)) test_4x8(.done(done_4x8), .passed(pass_4x8));
    sysarr_sized_tb #(.ROWS(8), .COLS(4), .INNER_DIM(5)) test_8x4(.done(done_8x4), .passed(pass_8x4));

    initial begin
        wait (done_1x1 && done_2x2 && done_4x4 && done_8x8 && done_16x16 && done_32x32 &&
              done_2x4 && done_4x2 && done_4x8 && done_8x4);
        if (pass_1x1 && pass_2x2 && pass_4x4 && pass_8x8 && pass_16x16 && pass_32x32 &&
            pass_2x4 && pass_4x2 && pass_4x8 && pass_8x4)
            $display("ALL MULTI-SIZE SYSTOLIC ARRAY TESTS PASSED!");
        else
            $display("MULTI-SIZE SYSTOLIC ARRAY TESTS FAILED!");
        $finish;
    end

endmodule
