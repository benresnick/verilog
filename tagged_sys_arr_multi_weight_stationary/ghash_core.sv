// Trusted GHASH block stream, SP 800-38D section 6.4 (Algorithm 2).
// A GCM controller must supply padded AAD, padded ciphertext, then the
// {aad_bit_length[63:0], ciphertext_bit_length[63:0]} block. Padding each
// section independently and generating that length block are caller duties.
// Lane 0 is in_data[MEM_DATA_W-1 -: 128], followed by descending lanes.
// in_blocks selects 1..LANES leading blocks; unused lanes are ignored.
//
// One unrolled chain computes the ordered multi-block recurrence each cycle.
// This supports one beat/clock functionally, but chain delay grows with width;
// no target clock frequency is claimed without synthesis/timing analysis.
// hash_out and hash_subkey are trusted internal signals, never public CSRs.
module ghash_core #(
    parameter int MEM_DATA_W = 128,
    parameter int LANES = MEM_DATA_W / 128,
    parameter int COUNT_W = (LANES <= 1) ? 1 : $clog2(LANES + 1)
) (
    input  logic clk, reset, clear,
    input  logic start_valid,
    output wire  start_ready,
    input  logic [127:0] hash_subkey,
    input  logic in_valid,
    output wire  in_ready,
    input  logic [MEM_DATA_W-1:0] in_data,
    input  logic [COUNT_W-1:0] in_blocks,
    input  logic in_last,
    output wire  out_valid,
    input  logic out_ready,
    output wire  [127:0] hash_out,
    output logic protocol_error
);
    logic active, result_valid;
    logic [127:0] h_reg, accumulator, result_reg;
    wire [127:0] chain [0:LANES];

    initial begin
        if (MEM_DATA_W < 128 || MEM_DATA_W % 128 != 0)
            $fatal(1, "GHASH MEM_DATA_W must be a positive multiple of 128");
        if (LANES != MEM_DATA_W / 128 || COUNT_W < $clog2(LANES + 1))
            $fatal(1, "GHASH derived parameters do not match memory width");
    end

    assign start_ready = !reset && !clear && !active && (!result_valid || out_ready);
    assign in_ready = !reset && !clear && active;
    assign out_valid = !reset && !clear && result_valid;
    assign hash_out = out_valid ? result_reg : 128'b0;
    assign chain[0] = accumulator;
    for (genvar lane = 0; lane < LANES; lane++) begin : g_lane
        wire [127:0] product;
        gf128_mul mul (
            .x(chain[lane] ^ in_data[MEM_DATA_W-1-128*lane -: 128]),
            .y(h_reg), .product(product)
        );
        assign chain[lane+1] = (lane < in_blocks) ? product : chain[lane];
    end

    always_ff @(posedge clk) begin
        if (reset || clear) begin
            active <= 1'b0;
            result_valid <= 1'b0;
            protocol_error <= 1'b0;
            h_reg <= '0;
            accumulator <= '0;
            result_reg <= '0;
        end else begin
            protocol_error <= 1'b0;
            if (out_valid && out_ready) begin
                result_valid <= 1'b0;
                result_reg <= '0;
            end
            if (start_valid && start_ready) begin
                active <= 1'b1;
                h_reg <= hash_subkey;
                accumulator <= '0;
            end
            if (in_valid && in_ready) begin
                if (in_blocks == 0 || in_blocks > LANES) begin
                    // Abort malformed work without producing a valid hash.
                    active <= 1'b0;
                    h_reg <= '0;
                    accumulator <= '0;
                    result_valid <= 1'b0;
                    result_reg <= '0;
                    protocol_error <= 1'b1;
                end else if (in_last) begin
                    result_reg <= chain[LANES];
                    result_valid <= 1'b1;
                    active <= 1'b0;
                    h_reg <= '0;
                    accumulator <= '0;
                end else begin
                    accumulator <= chain[LANES];
                end
            end
        end
    end
endmodule
