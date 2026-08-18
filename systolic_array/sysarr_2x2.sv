module sysarr_2x2 #(
    parameter DATA_WIDTH = 8,
    parameter ACC_WIDTH = 32
)(
    input logic clk,
    input logic reset,
    input logic clear_acc,

    input logic signed [DATA_WIDTH-1:0] activation_in_00,
    input logic                         activation_valid_in_00,

    input logic signed [DATA_WIDTH-1:0] activation_in_10,
    input logic                         activation_valid_in_10,

    input logic signed [DATA_WIDTH-1:0] weight_in_00,
    input logic                         weight_valid_in_00,

    input logic signed [DATA_WIDTH-1:0] weight_in_01,
    input logic                         weight_valid_in_01,



    output logic signed [ACC_WIDTH-1:0] partial_sum_00,
    output logic signed [ACC_WIDTH-1:0] partial_sum_01,
    output logic signed [ACC_WIDTH-1:0] partial_sum_10,
    output logic signed [ACC_WIDTH-1:0] partial_sum_11
);


    logic signed [DATA_WIDTH-1:0] act_00_to_01;
    logic                         act_valid_00_to_01;

    logic signed [DATA_WIDTH-1:0] act_10_to_11;
    logic                         act_valid_10_to_11;

    logic signed [DATA_WIDTH-1:0] weight_00_to_10;
    logic                         weight_valid_00_to_10;

    logic signed [DATA_WIDTH-1:0] weight_01_to_11;
    logic                         weight_valid_01_to_11;

    pe #(
        .DATA_WIDTH(DATA_WIDTH),
        .ACC_WIDTH(ACC_WIDTH)
    ) u00 (
        .clk(clk),
        .reset(reset),
        .clear_acc(clear_acc),
        .activation_in(activation_in_00), 
        .activation_valid_in(activation_valid_in_00),
        .weight_in(weight_in_00),
        .weight_valid_in(weight_valid_in_00),
        .activation_out(act_00_to_01),
        .activation_valid_out(act_valid_00_to_01),
        .weight_out(weight_00_to_10),
        .weight_valid_out(weight_valid_00_to_10),
        .partial_sum(partial_sum_00));

    pe #(
        .DATA_WIDTH(DATA_WIDTH),
        .ACC_WIDTH(ACC_WIDTH)
    ) u01 (
        .clk(clk),
        .reset(reset),
        .clear_acc(clear_acc),
        .activation_in(act_00_to_01), 
        .activation_valid_in(act_valid_00_to_01),
        .weight_in(weight_in_01),
        .weight_valid_in(weight_valid_in_01),
        .activation_out(),
        .activation_valid_out(),
        .weight_out(weight_01_to_11),
        .weight_valid_out(weight_valid_01_to_11),
        .partial_sum(partial_sum_01));
    
    pe #(
        .DATA_WIDTH(DATA_WIDTH),
        .ACC_WIDTH(ACC_WIDTH)
    ) u10 (
        .clk(clk),
        .reset(reset),
        .clear_acc(clear_acc),
        .activation_in(activation_in_10), 
        .activation_valid_in(activation_valid_in_10),
        .weight_in(weight_00_to_10),
        .weight_valid_in(weight_valid_00_to_10),
        .activation_out(act_10_to_11),
        .activation_valid_out(act_valid_10_to_11),
        .weight_out(),
        .weight_valid_out(),
        .partial_sum(partial_sum_10));
        
    pe #(
        .DATA_WIDTH(DATA_WIDTH),
        .ACC_WIDTH(ACC_WIDTH)
    ) u11 (
        .clk(clk),
        .reset(reset),
        .clear_acc(clear_acc),
        .activation_in(act_10_to_11), 
        .activation_valid_in(act_valid_10_to_11),
        .weight_in(weight_01_to_11),
        .weight_valid_in(weight_valid_01_to_11),
        .activation_out(),
        .activation_valid_out(),
        .weight_out(),
        .weight_valid_out(),
        .partial_sum(partial_sum_11));

    endmodule