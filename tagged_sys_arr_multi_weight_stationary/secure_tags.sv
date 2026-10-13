// Trusted-only metadata plane.  This file is elaborated only in tagged builds;
// it deliberately has no host/MMIO-facing ports.
`ifdef ENABLE_SECURE_TAGS
// Public weights contribute tag zero.  A pre-existing numerical partial must
// therefore carry the same protected row tag; otherwise fail closed.
module tag_policy_resolver #(
    parameter int TAG_WIDTH = 96
) (
    input logic incoming_valid,
    input logic [TAG_WIDTH-1:0] incoming_tag,
    input logic has_prior_partial,
    input logic stored_tag_valid,
    input logic [TAG_WIDTH-1:0] stored_tag,
    output logic resolved_valid,
    output logic [TAG_WIDTH-1:0] resolved_tag,
    output logic fault
);
    always_comb begin
        resolved_valid = incoming_valid;
        resolved_tag = incoming_tag;
        fault = has_prior_partial && (!stored_tag_valid || !incoming_valid || stored_tag != incoming_tag);
    end
endmodule

module shared_tag_queue #(
    parameter int ROWS = 2, COLS = 2, TAG_WIDTH = 96,
    parameter int DEPTH = ROWS + COLS - 1
) (
    input logic clk, reset, flush, advance,
    input logic in_valid, input logic [TAG_WIDTH-1:0] in_tag,
    output logic tap_valid [0:COLS-1],
    output logic [TAG_WIDTH-1:0] tap_tag [0:COLS-1],
    output logic empty
);
    logic valid [0:DEPTH-1];
    logic [TAG_WIDTH-1:0] tag [0:DEPTH-1];
    always_comb begin
        empty = 1'b1;
        for (int i = 0; i < DEPTH; i++) empty &= !valid[i];
        for (int c = 0; c < COLS; c++) begin
            tap_valid[c] = valid[ROWS - 1 + c];
            tap_tag[c] = tag[ROWS - 1 + c];
        end
    end
    always_ff @(posedge clk) begin
        if (reset || flush) begin
            for (int i = 0; i < DEPTH; i++) begin valid[i] <= 1'b0; tag[i] <= '0; end
        end else if (advance) begin
            valid[0] <= in_valid; tag[0] <= in_tag;
            for (int i = 1; i < DEPTH; i++) begin valid[i] <= valid[i-1]; tag[i] <= tag[i-1]; end
        end
    end
endmodule

// Logical tag memory matching OBuff's coordinate map and write concurrency.
module secure_obuff_tag_store #(
    parameter int ROWS = 8, COLS = 8, TAG_WIDTH = 96, WRITE_PORTS = 2,
    parameter int ROW_WIDTH = (ROWS <= 1) ? 1 : $clog2(ROWS),
    parameter int COL_WIDTH = (COLS <= 1) ? 1 : $clog2(COLS)
) (
    input logic clk, reset, clear_valids,
    input logic write_enable [0:WRITE_PORTS-1],
    input logic [ROW_WIDTH-1:0] write_row [0:WRITE_PORTS-1],
    input logic [COL_WIDTH-1:0] write_col [0:WRITE_PORTS-1],
    input logic [TAG_WIDTH-1:0] write_tag [0:WRITE_PORTS-1],
    input logic [ROW_WIDTH-1:0] read_row [0:WRITE_PORTS],
    input logic [COL_WIDTH-1:0] read_col [0:WRITE_PORTS],
    output logic read_valid [0:WRITE_PORTS],
    output logic [TAG_WIDTH-1:0] read_tag [0:WRITE_PORTS]
`ifdef ENABLE_SECURE_MEMORY
    , input logic secure_retire_row_valid,
    input logic [ROW_WIDTH-1:0] secure_retire_row
`endif
);
    logic valid [0:ROWS-1][0:COLS-1];
    logic [TAG_WIDTH-1:0] tag [0:ROWS-1][0:COLS-1];
    for (genvar p = 0; p <= WRITE_PORTS; p++) begin
        assign read_valid[p] = valid[read_row[p]][read_col[p]];
        assign read_tag[p] = tag[read_row[p]][read_col[p]];
    end
    always_ff @(posedge clk) begin
        if (reset || clear_valids) begin
            for (int r = 0; r < ROWS; r++) for (int c = 0; c < COLS; c++) begin
                valid[r][c] <= 1'b0; tag[r][c] <= '0;
            end
`ifdef ENABLE_SECURE_MEMORY
        end else if (secure_retire_row_valid && secure_retire_row < ROWS) begin
            for (int c = 0; c < COLS; c++) begin
                valid[secure_retire_row][c] <= 1'b0;
                tag[secure_retire_row][c] <= '0;
            end
`endif
        end else for (int p = 0; p < WRITE_PORTS; p++) if (write_enable[p]) begin
            valid[write_row[p]][write_col[p]] <= 1'b1;
            tag[write_row[p]][write_col[p]] <= write_tag[p];
        end
    end
endmodule
`endif
