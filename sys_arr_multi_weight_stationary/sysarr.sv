// Physical weight-stationary PE array.
//
// Physical row pr represents one K index for the selected local bank, while
// physical column pc represents logical output column n_base + pc.  The
// controller supplies row/column-skewed activation and psum inputs; this
// wrapper only creates the registered inter-PE links.
module sysarr #(
    parameter int ROWS = 2,
    parameter int COLS = 2,
    parameter int DATA_WIDTH = 8,
    parameter int ACC_WIDTH = 32,
    parameter int WEIGHTS_PER_PE = 1,
    parameter int SLOT_WIDTH = (WEIGHTS_PER_PE <= 1) ? 1 : $clog2(WEIGHTS_PER_PE),
    parameter int ROW_WIDTH = (ROWS <= 1) ? 1 : $clog2(ROWS)
) (
    input logic clk,
    input logic reset,
    input logic weight_load,

    input logic signed [DATA_WIDTH-1:0] activation_in [0:ROWS-1],
    input logic activation_valid_in [0:ROWS-1],

    input logic signed [DATA_WIDTH-1:0] weight_in [0:COLS-1],
    input logic weight_valid_in [0:COLS-1],
    input logic [SLOT_WIDTH-1:0] weight_slot_in [0:COLS-1],
    input logic [ROW_WIDTH-1:0] weight_target_row_in [0:COLS-1],
    input logic [SLOT_WIDTH-1:0] selected_slot,

    input logic signed [ACC_WIDTH-1:0] psum_in [0:COLS-1],
    input logic psum_valid_in [0:COLS-1],
    output logic signed [ACC_WIDTH-1:0] psum_out [0:COLS-1],
    output logic psum_valid_out [0:COLS-1]
);
    logic signed [DATA_WIDTH-1:0] activation [0:ROWS-1][0:COLS];
    logic activation_valid [0:ROWS-1][0:COLS];

    logic signed [DATA_WIDTH-1:0] weight [0:ROWS][0:COLS-1];
    logic weight_valid [0:ROWS][0:COLS-1];
    logic [SLOT_WIDTH-1:0] weight_slot [0:ROWS][0:COLS-1];
    logic [ROW_WIDTH-1:0] weight_target_row [0:ROWS][0:COLS-1];

    logic signed [ACC_WIDTH-1:0] psum [0:ROWS][0:COLS-1];
    logic psum_valid [0:ROWS][0:COLS-1];

    genvar row;
    genvar col;
    generate
        for (row = 0; row < ROWS; row++) begin : G_ACTIVATION_EDGE
            assign activation[row][0] = activation_in[row];
            assign activation_valid[row][0] = activation_valid_in[row];
        end

        for (col = 0; col < COLS; col++) begin : G_COLUMN_EDGES
            assign weight[0][col] = weight_in[col];
            assign weight_valid[0][col] = weight_valid_in[col];
            assign weight_slot[0][col] = weight_slot_in[col];
            assign weight_target_row[0][col] = weight_target_row_in[col];

            assign psum[0][col] = psum_in[col];
            assign psum_valid[0][col] = psum_valid_in[col];
            assign psum_out[col] = psum[ROWS][col];
            assign psum_valid_out[col] = psum_valid[ROWS][col];
        end

        for (row = 0; row < ROWS; row++) begin : G_ROWS
            for (col = 0; col < COLS; col++) begin : G_COLS
                pe #(
                    .DATA_WIDTH(DATA_WIDTH),
                    .ACC_WIDTH(ACC_WIDTH),
                    .WEIGHTS_PER_PE(WEIGHTS_PER_PE),
                    .ROW_ID(row),
                    .SLOT_WIDTH(SLOT_WIDTH),
                    .ROW_WIDTH(ROW_WIDTH)
                ) u_pe (
                    .clk(clk),
                    .reset(reset),
                    .activation_in(activation[row][col]),
                    .activation_valid_in(activation_valid[row][col]),
                    .weight_load(weight_load),
                    .weight_in(weight[row][col]),
                    .weight_valid_in(weight_valid[row][col]),
                    .weight_slot_in(weight_slot[row][col]),
                    .weight_target_row_in(weight_target_row[row][col]),
                    .selected_slot(selected_slot),
                    .psum_in(psum[row][col]),
                    .psum_valid_in(psum_valid[row][col]),
                    .activation_out(activation[row][col + 1]),
                    .activation_valid_out(activation_valid[row][col + 1]),
                    .weight_out(weight[row + 1][col]),
                    .weight_valid_out(weight_valid[row + 1][col]),
                    .weight_slot_out(weight_slot[row + 1][col]),
                    .weight_target_row_out(weight_target_row[row + 1][col]),
                    .psum_out(psum[row + 1][col]),
                    .psum_valid_out(psum_valid[row + 1][col])
                );
            end
        end
    endgenerate
endmodule
