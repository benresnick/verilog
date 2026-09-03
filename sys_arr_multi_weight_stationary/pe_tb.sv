`timescale 1ns/1ps

// Focused PE regression: slot selection, signed arithmetic, and padded rows.
module pe_tb;
    localparam int DATA_WIDTH = 8;
    localparam int ACC_WIDTH = 32;
    localparam int WEIGHTS_PER_PE = 4;

    logic clk = 0;
    logic reset, activation_valid_in, weight_load, weight_valid_in, psum_valid_in;
    logic signed [DATA_WIDTH-1:0] activation_in, weight_in;
    logic signed [ACC_WIDTH-1:0] psum_in;
    logic [1:0] weight_slot_in, selected_slot;
    logic [0:0] weight_target_row_in, weight_target_row_out;
    logic signed [DATA_WIDTH-1:0] activation_out, weight_out;
    logic activation_valid_out, weight_valid_out;
    logic signed [ACC_WIDTH-1:0] psum_out;
    logic psum_valid_out;

    always #5 clk = ~clk;

    pe #(
        .DATA_WIDTH(DATA_WIDTH),
        .ACC_WIDTH(ACC_WIDTH),
        .WEIGHTS_PER_PE(WEIGHTS_PER_PE),
        .ROW_ID(0),
        .SLOT_WIDTH(2)
    ) dut (
        .clk(clk), .reset(reset),
        .activation_in(activation_in), .activation_valid_in(activation_valid_in),
        .weight_load(weight_load), .weight_in(weight_in), .weight_valid_in(weight_valid_in),
        .weight_slot_in(weight_slot_in), .weight_target_row_in(weight_target_row_in),
        .selected_slot(selected_slot), .psum_in(psum_in), .psum_valid_in(psum_valid_in),
        .activation_out(activation_out), .activation_valid_out(activation_valid_out),
        .weight_out(weight_out), .weight_valid_out(weight_valid_out),
        .weight_slot_out(), .weight_target_row_out(weight_target_row_out),
        .psum_out(psum_out), .psum_valid_out(psum_valid_out)
    );

    task automatic step(
        input logic load,
        input logic [1:0] slot,
        input logic signed [DATA_WIDTH-1:0] loaded_weight,
        input logic signed [DATA_WIDTH-1:0] activation,
        input logic input_psum_valid
    );
        begin
            @(negedge clk);
            weight_load = load;
            weight_slot_in = slot;
            weight_in = loaded_weight;
            weight_valid_in = load;
            activation_in = activation;
            activation_valid_in = 1'b1;
            psum_in = 7;
            psum_valid_in = input_psum_valid;
            @(posedge clk);
            #1;
        end
    endtask

    initial begin
        reset = 1; weight_load = 0; weight_valid_in = 0;
        activation_valid_in = 0; psum_valid_in = 0;
        activation_in = 0; weight_in = 0; psum_in = 0;
        weight_slot_in = 0; selected_slot = 0; weight_target_row_in = 0;
        repeat (2) @(posedge clk);
        reset = 0;

        step(1, 0, -3, 0, 0);
        step(1, 1, 5, 0, 0);

        selected_slot = 0;
        step(0, 0, 0, 4, 1);
        if (!psum_valid_out || psum_out !== -5)
            $fatal(1, "slot 0 signed MAC failed: %0d", psum_out);

        selected_slot = 1;
        step(0, 0, 0, 4, 1);
        if (!psum_valid_out || psum_out !== 27)
            $fatal(1, "slot 1 signed MAC failed: %0d", psum_out);

        selected_slot = 2;
        step(0, 0, 0, 4, 1);
        if (!psum_valid_out || psum_out !== 7)
            $fatal(1, "invalid slot must pass psum: %0d", psum_out);

        $display("PASS: PE banked-weight regression");
        $finish;
    end
endmodule
