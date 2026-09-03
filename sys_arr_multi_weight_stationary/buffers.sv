// Reusable bounded buffer primitives for the accelerator's IBuff, WBuff, and
// OBuff roles.  The current top-level keeps its arrays local for multi-port
// array scheduling; these modules provide the same synthesizable storage
// contracts for a future memory-macro or independently pipelined integration.

module matrix_input_buffer #(
    parameter int ROWS = 8,
    parameter int COLS = 8,
    parameter int DATA_WIDTH = 8,
    parameter int ROW_WIDTH = (ROWS <= 1) ? 1 : $clog2(ROWS),
    parameter int COL_WIDTH = (COLS <= 1) ? 1 : $clog2(COLS)
) (
    input logic clk,
    input logic reset,
    input logic write_enable,
    input logic [ROW_WIDTH-1:0] write_row,
    input logic [COL_WIDTH-1:0] write_col,
    input logic signed [DATA_WIDTH-1:0] write_data,
    input logic [ROW_WIDTH-1:0] read_row,
    input logic [COL_WIDTH-1:0] read_col,
    output logic signed [DATA_WIDTH-1:0] read_data,
    output logic read_valid
);
    logic signed [DATA_WIDTH-1:0] data [0:ROWS-1][0:COLS-1];
    logic valid [0:ROWS-1][0:COLS-1];

    assign read_data = data[read_row][read_col];
    assign read_valid = valid[read_row][read_col];

    always_ff @(posedge clk) begin
        if (reset) begin
            for (int row = 0; row < ROWS; row++)
                for (int col = 0; col < COLS; col++) valid[row][col] <= 1'b0;
        end else if (write_enable) begin
            data[write_row][write_col] <= write_data;
            valid[write_row][write_col] <= 1'b1;
        end
    end
endmodule

module matrix_output_buffer #(
    parameter int ROWS = 8,
    parameter int COLS = 8,
    parameter int ACC_WIDTH = 32,
    parameter int ROW_WIDTH = (ROWS <= 1) ? 1 : $clog2(ROWS),
    parameter int COL_WIDTH = (COLS <= 1) ? 1 : $clog2(COLS)
) (
    input logic clk,
    input logic reset,
    input logic clear_valids,
    input logic write_enable,
    input logic [ROW_WIDTH-1:0] write_row,
    input logic [COL_WIDTH-1:0] write_col,
    input logic signed [ACC_WIDTH-1:0] write_data,
    input logic write_final,
    input logic [ROW_WIDTH-1:0] read_row,
    input logic [COL_WIDTH-1:0] read_col,
    output logic signed [ACC_WIDTH-1:0] read_data,
    output logic read_valid,
    output logic read_final
);
    logic signed [ACC_WIDTH-1:0] data [0:ROWS-1][0:COLS-1];
    logic valid [0:ROWS-1][0:COLS-1];
    logic final_valid [0:ROWS-1][0:COLS-1];

    assign read_data = data[read_row][read_col];
    assign read_valid = valid[read_row][read_col];
    assign read_final = final_valid[read_row][read_col];

    always_ff @(posedge clk) begin
        if (reset || clear_valids) begin
            for (int row = 0; row < ROWS; row++)
                for (int col = 0; col < COLS; col++) begin
                    valid[row][col] <= 1'b0;
                    final_valid[row][col] <= 1'b0;
                end
        end else if (write_enable) begin
            data[write_row][write_col] <= write_data;
            valid[write_row][write_col] <= 1'b1;
            final_valid[write_row][write_col] <= write_final;
        end
    end
endmodule

// Multi-read variant used by the systolic scheduler.  It permits all physical
// rows (IBuff) or all physical columns (WBuff) to read in one cycle while the
// host still has one simple write port.
module multi_read_matrix_buffer #(
    parameter int ROWS = 8,
    parameter int COLS = 8,
    parameter int DATA_WIDTH = 8,
    parameter int READ_PORTS = 1,
    parameter int ROW_WIDTH = (ROWS <= 1) ? 1 : $clog2(ROWS),
    parameter int COL_WIDTH = (COLS <= 1) ? 1 : $clog2(COLS)
) (
    input logic clk,
    input logic write_enable,
    input logic [ROW_WIDTH-1:0] write_row,
    input logic [COL_WIDTH-1:0] write_col,
    input logic signed [DATA_WIDTH-1:0] write_data,
    input logic [ROW_WIDTH-1:0] read_row [0:READ_PORTS-1],
    input logic [COL_WIDTH-1:0] read_col [0:READ_PORTS-1],
    output logic signed [DATA_WIDTH-1:0] read_data [0:READ_PORTS-1]
);
    logic signed [DATA_WIDTH-1:0] data [0:ROWS-1][0:COLS-1];

    for (genvar port = 0; port < READ_PORTS; port++) begin : G_READ_PORTS
        assign read_data[port] = data[read_row[port]][read_col[port]];
    end

    always_ff @(posedge clk) begin
        if (write_enable) data[write_row][write_col] <= write_data;
    end
endmodule

// OBuff implementation for the systolic array.  Each physical column owns a
// write port, so two diagonally adjacent C values may commit in the same cycle.
// READ_PORTS normally equals WRITE_PORTS + 1: one feedback read per column plus
// one independent result-stream read.
module multi_write_output_buffer #(
    parameter int ROWS = 8,
    parameter int COLS = 8,
    parameter int ACC_WIDTH = 32,
    parameter int WRITE_PORTS = 2,
    parameter int READ_PORTS = 3,
    parameter int ROW_WIDTH = (ROWS <= 1) ? 1 : $clog2(ROWS),
    parameter int COL_WIDTH = (COLS <= 1) ? 1 : $clog2(COLS)
) (
    input logic clk,
    input logic reset,
    input logic clear_valids,
    input logic write_enable [0:WRITE_PORTS-1],
    input logic [ROW_WIDTH-1:0] write_row [0:WRITE_PORTS-1],
    input logic [COL_WIDTH-1:0] write_col [0:WRITE_PORTS-1],
    input logic signed [ACC_WIDTH-1:0] write_data [0:WRITE_PORTS-1],
    input logic write_final [0:WRITE_PORTS-1],
    input logic [ROW_WIDTH-1:0] read_row [0:READ_PORTS-1],
    input logic [COL_WIDTH-1:0] read_col [0:READ_PORTS-1],
    output logic signed [ACC_WIDTH-1:0] read_data [0:READ_PORTS-1],
    output logic read_valid [0:READ_PORTS-1],
    output logic read_final [0:READ_PORTS-1]
);
    logic signed [ACC_WIDTH-1:0] data [0:ROWS-1][0:COLS-1];
    logic valid [0:ROWS-1][0:COLS-1];
    logic final_valid [0:ROWS-1][0:COLS-1];

    for (genvar port = 0; port < READ_PORTS; port++) begin : G_READ_PORTS
        assign read_data[port] = data[read_row[port]][read_col[port]];
        assign read_valid[port] = valid[read_row[port]][read_col[port]];
        assign read_final[port] = final_valid[read_row[port]][read_col[port]];
    end

    always_ff @(posedge clk) begin
        if (reset || clear_valids) begin
            for (int row = 0; row < ROWS; row++)
                for (int col = 0; col < COLS; col++) begin
                    valid[row][col] <= 1'b0;
                    final_valid[row][col] <= 1'b0;
                end
        end else begin
            for (int port = 0; port < WRITE_PORTS; port++) begin
                if (write_enable[port]) begin
                    data[write_row[port]][write_col[port]] <= write_data[port];
                    valid[write_row[port]][write_col[port]] <= 1'b1;
                    final_valid[write_row[port]][write_col[port]] <= write_final[port];
                end
            end
        end
    end
endmodule
