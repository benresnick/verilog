// One combinational step of FIPS 197 KEYEXPANSION. ROUND is an elaboration
// constant in 1..10 (AES-128) or 1..14 (AES-256). Chain consecutive steps
// starting with the original key to obtain the complete forward key schedule.
// AES-128 carries four words; AES-256 carries eight words. No full expanded
// key array is copied between pipeline stages.
module aes_key_expand #(
    parameter int AES_KEY_W = 256,
    parameter int ROUND = 1
) (
    input logic [AES_KEY_W-1:0] key_in,
    output wire [AES_KEY_W-1:0] key_out,
    output wire [127:0] round_key
);
    import aes_primitives::*;

    localparam int AES_ROUNDS = (AES_KEY_W == 128) ? 10 : 14;

    initial begin
        if (AES_KEY_W != 128 && AES_KEY_W != 256)
            $fatal(1, "AES_KEY_W must be 128 or 256");
        if (ROUND < 1 || ROUND > AES_ROUNDS)
            $fatal(1, "ROUND is outside the configured AES key schedule");
    end

    generate
        if (AES_KEY_W == 256 && ROUND == 1) begin : g_original_second_half
            // Round 0 consumed words 0..3; round 1 uses original words 4..7.
            assign key_out = key_in;
            assign round_key = key_in[127:0];
        end else begin : g_expand
            wire [31:0] transform;
            wire [31:0] w0, w1, w2, w3;

            if (AES_KEY_W == 128) begin : g_128
                assign transform = aes_sub_word(aes_rot_word(key_in[31:0])) ^
                                   {aes_rcon(ROUND), 24'b0};
            end else if ((ROUND % 2) == 0) begin : g_256_even
                assign transform = aes_sub_word(aes_rot_word(key_in[31:0])) ^
                                   {aes_rcon(ROUND / 2), 24'b0};
            end else begin : g_256_odd
                assign transform = aes_sub_word(key_in[31:0]);
            end

            assign w0 = key_in[AES_KEY_W-1 -: 32] ^ transform;
            assign w1 = key_in[AES_KEY_W-33 -: 32] ^ w0;
            assign w2 = key_in[AES_KEY_W-65 -: 32] ^ w1;
            assign w3 = key_in[AES_KEY_W-97 -: 32] ^ w2;
            assign round_key = {w0, w1, w2, w3};

            if (AES_KEY_W == 128) begin : g_four_word_window
                assign key_out = round_key;
            end else begin : g_eight_word_window
                assign key_out = {key_in[127:0], round_key};
            end
        end
    endgenerate
endmodule
