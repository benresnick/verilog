module sysarr #(
    parameter ROWS = 2,
    parameter COLS = 2,
    parameter DATA_WIDTH = 8,
    parameter ACC_WIDTH = 32
)(
    input logic clk,
    input logic reset,
    input logic clear_acc,

    input logic signed [DATA_WIDTH-1:0] activation_in [0:ROWS-1],
    input logic                         activation_valid_in [0:ROWS-1],

    input logic signed [DATA_WIDTH-1:0] weight_in [0:COLS-1],
    input logic                         weight_valid_in [0:COLS-1],

    output logic signed [ACC_WIDTH-1:0] partial_sum [0:ROWS-1][0:COLS-1]
);

    logic signed [DATA_WIDTH-1:0] activation [0:ROWS-1][0:COLS];
    logic                         activation_valid [0:ROWS-1][0:COLS];

    logic signed [DATA_WIDTH-1:0] weight [0:ROWS][0:COLS-1];
    logic                         weight_valid [0:ROWS][0:COLS-1];

    genvar r, c;
    generate
        for (r = 0; r < ROWS; r++) begin : ACT_BOUNDARY
            assign activation[r][0] = activation_in[r];
            assign activation_valid[r][0] = activation_valid_in[r];
        end
        for (c = 0; c < COLS; c++) begin : WEIGHT_BOUNDARY
            assign weight[0][c] = weight_in[c];
            assign weight_valid[0][c] = weight_valid_in[c];
        end
    endgenerate

    genvar row, col;
    generate
        for (row = 0; row < ROWS; row++) begin : PE_ROWS
            for (col = 0; col < COLS; col++) begin : PE_COLS
                    pe #(
                        .DATA_WIDTH(DATA_WIDTH),
                        .ACC_WIDTH(ACC_WIDTH)
                    ) u_pe (
                        .clk(clk),
                        .reset(reset),
                        .clear_acc(clear_acc),
                        .activation_in(activation[row][col]),
                        .activation_valid_in(activation_valid[row][col]),
                        .weight_in(weight[row][col]),
                        .weight_valid_in(weight_valid[row][col]),
                        .activation_out(activation[row][col+1]),
                        .activation_valid_out(activation_valid[row][col+1]),
                        .weight_out(weight[row+1][col]),
                        .weight_valid_out(weight_valid[row+1][col]),
                        .partial_sum(partial_sum[row][col]));
            end
        end
    endgenerate

endmodule
