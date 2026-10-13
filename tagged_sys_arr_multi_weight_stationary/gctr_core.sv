// Streaming GCTR transform. This core provides confidentiality only; GCM must
// authenticate ciphertext before committing decrypted bytes to trusted memory.
// Byte zero is the most significant byte, with the corresponding high keep bit.
// Non-final beats must be full; final keep is a nonempty leading run of ones.
// inc32 wraps only the low counter word, and each transaction is limited to
// 2^32-2 AES blocks (including a partially used final block).
//
// Every 128-bit lane has an AES pipeline. Data and byte enables advance with
// those pipelines, accepting one memory beat per cycle when output can advance.
// A blocked output freezes legal data transfers. A malformed input can still
// be accepted to abort and erase the transaction, even under backpressure.
// clear/reset mask handshakes immediately and synchronously erase working state.
module gctr_core #(
    parameter int AES_KEY_W = 256,
    parameter int MEM_DATA_W = 128
) (
    input logic clk,
    input logic reset,
    input logic clear,
    input logic start_valid,
    output wire start_ready,
    input logic [AES_KEY_W-1:0] key_in,
    input logic [127:0] initial_counter,
    input logic in_valid,
    output wire in_ready,
    input logic [MEM_DATA_W-1:0] in_data,
    input logic [MEM_DATA_W/8-1:0] in_keep,
    input logic in_last,
    output wire out_valid,
    input logic out_ready,
    output wire [MEM_DATA_W-1:0] out_data,
    output wire [MEM_DATA_W/8-1:0] out_keep,
    output wire out_last,
    output wire protocol_error
);
    localparam int LANES = MEM_DATA_W / 128;
    localparam int BYTES = MEM_DATA_W / 8;
    localparam int ROUNDS = (AES_KEY_W == 128) ? 10 : 14;
    localparam logic [32:0] MAX_BLOCKS = 33'h0fffffffe;

    logic active, input_done, error_reg;
    logic [AES_KEY_W-1:0] key_reg;
    logic [127:0] counter_reg;
    logic [32:0] blocks_used;
    logic [ROUNDS:0] valid_pipe, last_pipe;
    logic [MEM_DATA_W-1:0] data_pipe [0:ROUNDS];
    logic [BYTES-1:0] keep_pipe [0:ROUNDS];
    wire [MEM_DATA_W-1:0] keystream;
    logic keep_valid, seen_zero;
    integer valid_bytes;
    logic [32:0] beat_blocks;

    wire advance = !valid_pipe[ROUNDS] || out_ready;
    wire malformed = !keep_valid || blocks_used + beat_blocks > MAX_BLOCKS;
    assign start_ready = !reset && !clear && !active;
    assign in_ready = !reset && !clear && active && !input_done && (advance || malformed);
    wire input_accept = in_valid && in_ready;
    // An abort needs no free pipeline slot. Keeping this independent of
    // out_ready also prevents a combinational ready-to-valid error-path loop.
    wire bad_accept = !reset && !clear && active && !input_done && in_valid && malformed;
    wire pipeline_reset = reset || clear || bad_accept;
    wire valid_accept = input_accept && !malformed;
    assign out_valid = !pipeline_reset && valid_pipe[ROUNDS];
    assign out_keep = out_valid ? keep_pipe[ROUNDS] : '0;
    assign out_last = out_valid && last_pipe[ROUNDS];
    assign protocol_error = !reset && !clear && error_reg;
    wire finish = out_valid && out_ready && out_last;

    // The validation uses byte positions rather than a sized shift, so widths
    // above 32/64 bits and a full final beat have the same precise semantics.
    always_comb begin
        valid_bytes = 0;
        seen_zero = 0;
        keep_valid = 1;
        for (int byte_index = 0; byte_index < BYTES; byte_index++) begin
            if (in_keep[BYTES-1-byte_index]) begin
                valid_bytes = valid_bytes + 1;
                if (seen_zero) keep_valid = 0;
            end else begin
                seen_zero = 1;
            end
        end
        if (valid_bytes == 0 || (!in_last && valid_bytes != BYTES)) keep_valid = 0;
        beat_blocks = 33'((valid_bytes + 15) / 16);
    end

    initial begin
        if (AES_KEY_W != 128 && AES_KEY_W != 256)
            $fatal(1, "AES_KEY_W must be 128 or 256");
        if (MEM_DATA_W < 128 || MEM_DATA_W % 128 != 0)
            $fatal(1, "MEM_DATA_W must be a positive multiple of 128");
    end

    generate
        for (genvar lane = 0; lane < LANES; lane++) begin : g_lane
            wire [127:0] lane_counter = {counter_reg[127:32], counter_reg[31:0] + 32'(lane)};
            wire unused_in_ready, unused_out_valid;
            aes_encrypt_block #(.AES_KEY_W(AES_KEY_W)) aes (
                .clk(clk), .reset(pipeline_reset),
                .in_valid(valid_accept), .in_ready(unused_in_ready),
                .block_in(lane_counter), .key_in(key_reg),
                .out_valid(unused_out_valid), .out_ready(out_ready),
                .block_out(keystream[MEM_DATA_W-1-128*lane -: 128])
            );
        end
        for (genvar byte_index = 0; byte_index < BYTES; byte_index++) begin : g_output
            assign out_data[MEM_DATA_W-1-8*byte_index -: 8] =
                out_valid && out_keep[BYTES-1-byte_index] ?
                data_pipe[ROUNDS][MEM_DATA_W-1-8*byte_index -: 8] ^
                keystream[MEM_DATA_W-1-8*byte_index -: 8] : 8'b0;
        end
    endgenerate

    always_ff @(posedge clk) begin
        if (pipeline_reset) begin
            active <= 0;
            input_done <= 0;
            error_reg <= !reset && !clear && bad_accept;
            key_reg <= '0;
            counter_reg <= '0;
            blocks_used <= '0;
            valid_pipe <= '0;
            last_pipe <= '0;
            for (int stage = 0; stage <= ROUNDS; stage++) begin
                data_pipe[stage] <= '0;
                keep_pipe[stage] <= '0;
            end
        end else begin
            error_reg <= 0;
            if (start_valid && start_ready) begin
                active <= 1;
                input_done <= 0;
                key_reg <= key_in;
                counter_reg <= initial_counter;
                blocks_used <= '0;
            end
            if (valid_accept) begin
                counter_reg <= {counter_reg[127:32], counter_reg[31:0] + beat_blocks[31:0]};
                blocks_used <= blocks_used + beat_blocks;
                if (in_last) begin
                    input_done <= 1;
                    key_reg <= '0;
                    counter_reg <= '0;
                    blocks_used <= '0;
                end
            end
            if (advance) begin
                valid_pipe[0] <= valid_accept;
                last_pipe[0] <= valid_accept && in_last;
                keep_pipe[0] <= valid_accept ? in_keep : '0;
                // Never store disabled trailing payload bytes.
                for (int byte_index = 0; byte_index < BYTES; byte_index++)
                    data_pipe[0][MEM_DATA_W-1-8*byte_index -: 8] <=
                        valid_accept && in_keep[BYTES-1-byte_index] ?
                        in_data[MEM_DATA_W-1-8*byte_index -: 8] : 8'b0;
                for (int stage = 1; stage <= ROUNDS; stage++) begin
                    valid_pipe[stage] <= valid_pipe[stage-1];
                    last_pipe[stage] <= last_pipe[stage-1];
                    keep_pipe[stage] <= keep_pipe[stage-1];
                    data_pipe[stage] <= data_pipe[stage-1];
                end
            end
            // All earlier stages are empty when the final output is consumed.
            // This advancing edge also zeros the final AES/data/keep stages.
            if (finish) begin
                active <= 0;
                input_done <= 0;
            end
        end
    end
endmodule
