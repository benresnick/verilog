// Synthesizable forward AES for use by GCM. This primitive alone provides
// neither authentication nor a secure DRAM boundary.
//
// An accepted block/key is stored after the initial AddRoundKey at edge E0.
// With no stalls, out_valid/block_out update after edge E10 for AES-128 or
// E14 for AES-256; the earliest output handshake is E11/E15. The initial
// register plus one register per round permit one accepted block per cycle.
//
// A blocked valid output freezes every stage and deasserts in_ready. Latency
// is therefore fixed in advancing pipeline cycles, not stalled wall clocks.
// Key windows travel with their blocks, allowing independent keys on adjacent
// cycles. A future transaction engine can cache expanded keys to save power;
// this standalone core recomputes the schedule for every accepted block.
module aes_encrypt_block #(
    parameter int AES_KEY_W = 256
) (
    input logic clk,
    input logic reset,
    input logic in_valid,
    output wire in_ready,
    input logic [127:0] block_in,
    input logic [AES_KEY_W-1:0] key_in,
    output wire out_valid,
    input logic out_ready,
    output wire [127:0] block_out
);
    import aes_primitives::*;

    localparam int AES_ROUNDS = (AES_KEY_W == 128) ? 10 : 14;
    localparam int AES_PIPE_LATENCY = AES_ROUNDS;

    logic [AES_ROUNDS:0] valid_pipe;
    logic [127:0] state_pipe [0:AES_ROUNDS];
    // The final ciphertext stage needs no key register.
    logic [AES_KEY_W-1:0] key_pipe [0:AES_ROUNDS-1];
    wire [AES_KEY_W-1:0] next_key [1:AES_ROUNDS];
    wire [127:0] next_state [1:AES_ROUNDS];
    wire advance = !valid_pipe[AES_ROUNDS] || out_ready;

    // Reset is synchronous for storage; externally visible handshakes and
    // ciphertext are suppressed while reset is asserted.
    assign in_ready = !reset && advance;
    assign out_valid = !reset && valid_pipe[AES_ROUNDS];
    assign block_out = out_valid ? state_pipe[AES_ROUNDS] : 128'b0;

    initial begin
        if (AES_KEY_W != 128 && AES_KEY_W != 256)
            $fatal(1, "AES_KEY_W must be 128 or 256");
    end

    generate
        for (genvar round_index = 1; round_index <= AES_ROUNDS; round_index++) begin : g_round
            wire [127:0] round_key;
            wire [127:0] shifted_state;
            aes_key_expand #(.AES_KEY_W(AES_KEY_W), .ROUND(round_index)) expand (
                .key_in(key_pipe[round_index-1]),
                .key_out(next_key[round_index]),
                .round_key(round_key)
            );
            assign shifted_state = aes_shift_rows(aes_sub_bytes(state_pipe[round_index-1]));
            if (round_index == AES_ROUNDS) begin : g_final
                assign next_state[round_index] = shifted_state ^ round_key;
            end else begin : g_full
                assign next_state[round_index] = aes_mix_columns(shifted_state) ^ round_key;
            end
        end
    endgenerate

    always_ff @(posedge clk) begin
        if (reset) begin
            valid_pipe <= '0;
            for (int stage = 0; stage <= AES_ROUNDS; stage++)
                state_pipe[stage] <= '0;
            for (int stage = 0; stage < AES_ROUNDS; stage++)
                key_pipe[stage] <= '0;
        end else if (advance) begin
            valid_pipe[0] <= in_valid;
            state_pipe[0] <= in_valid ? block_in ^ key_in[AES_KEY_W-1 -: 128] : 128'b0;
            key_pipe[0] <= in_valid ? key_in : '0;
            for (int stage = 1; stage <= AES_ROUNDS; stage++) begin
                valid_pipe[stage] <= valid_pipe[stage-1];
                state_pipe[stage] <= valid_pipe[stage-1] ? next_state[stage] : 128'b0;
            end
            for (int stage = 1; stage < AES_ROUNDS; stage++)
                key_pipe[stage] <= valid_pipe[stage-1] ? next_key[stage] : '0;
        end
    end
endmodule
