`timescale 1ns/1ps

// Self-checking unit test for the reusable buffer storage contracts.
module buffers_tb;
    localparam int DATA_WIDTH = 8;
    localparam int ACC_WIDTH = 32;

    logic clk = 0;
    logic reset;

    logic input_we;
    logic [1:0] input_wr_row, input_rd_row;
    logic [1:0] input_wr_col, input_rd_col;
    logic signed [DATA_WIDTH-1:0] input_wr_data, input_rd_data;
    logic input_rd_valid;

    logic output_clear, output_we, output_final;
    logic [1:0] output_wr_row, output_rd_row;
    logic [1:0] output_wr_col, output_rd_col;
    logic signed [ACC_WIDTH-1:0] output_wr_data, output_rd_data;
    logic output_rd_valid, output_rd_final;

    always #5 clk = ~clk;

    matrix_input_buffer #(.ROWS(3), .COLS(3), .DATA_WIDTH(DATA_WIDTH)) u_ibuff (
        .clk(clk), .reset(reset), .write_enable(input_we),
        .write_row(input_wr_row), .write_col(input_wr_col), .write_data(input_wr_data),
        .read_row(input_rd_row), .read_col(input_rd_col),
        .read_data(input_rd_data), .read_valid(input_rd_valid)
    );

    matrix_output_buffer #(.ROWS(3), .COLS(3), .ACC_WIDTH(ACC_WIDTH)) u_obuf (
        .clk(clk), .reset(reset), .clear_valids(output_clear), .write_enable(output_we),
        .write_row(output_wr_row), .write_col(output_wr_col), .write_data(output_wr_data),
        .write_final(output_final), .read_row(output_rd_row), .read_col(output_rd_col),
        .read_data(output_rd_data), .read_valid(output_rd_valid), .read_final(output_rd_final)
    );

    initial begin
        reset = 1;
        input_we = 0; input_wr_row = 0; input_wr_col = 0; input_wr_data = 0;
        input_rd_row = 0; input_rd_col = 0;
        output_clear = 0; output_we = 0; output_final = 0;
        output_wr_row = 0; output_wr_col = 0; output_wr_data = 0;
        output_rd_row = 0; output_rd_col = 0;
        repeat (2) @(posedge clk);
        reset = 0;

        @(negedge clk);
        input_we = 1; input_wr_row = 2; input_wr_col = 1; input_wr_data = -8'sd7;
        output_we = 1; output_wr_row = 1; output_wr_col = 2;
        output_wr_data = -32'sd101; output_final = 0;
        @(negedge clk);
        input_we = 0; output_we = 0;
        input_rd_row = 2; input_rd_col = 1;
        output_rd_row = 1; output_rd_col = 2;
        #1;
        if (!input_rd_valid || input_rd_data !== -8'sd7)
            $fatal(1, "IBuff write/read contract failed");
        if (!output_rd_valid || output_rd_final || output_rd_data !== -32'sd101)
            $fatal(1, "OBuff partial write/read contract failed");

        @(negedge clk);
        output_we = 1; output_wr_data = 32'sd44; output_final = 1;
        @(negedge clk);
        output_we = 0;
        #1;
        if (!output_rd_valid || !output_rd_final || output_rd_data !== 32'sd44)
            $fatal(1, "OBuff final write/read contract failed");

        @(negedge clk);
        output_clear = 1;
        @(negedge clk);
        output_clear = 0;
        #1;
        if (output_rd_valid || output_rd_final)
            $fatal(1, "OBuff clear did not invalidate stored result");

        $display("PASS: reusable buffer regression");
        $finish;
    end
endmodule
