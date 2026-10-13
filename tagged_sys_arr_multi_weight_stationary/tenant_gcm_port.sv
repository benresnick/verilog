// One trusted tenant-record stream backed by an AES-GCM transaction engine.
// A shared key manager must provide cmd_key/cmd_slot and reserve cmd_iv on the
// same edge as a successful command handshake. The key is captured directly by
// engine on that edge; this wrapper does not create another key copy.
//
// Authentication binds a fixed 32-byte, MSB-first record header:
//   "TGC1" | tenant[95:0] | record_type[31:0] | payload_bytes[31:0] |
//   destination[63:0]
// No caller-controlled raw AAD stream is exposed. Decrypted payload and its
// captured destination/tenant metadata appear only after full authentication.
//
// Encryption ciphertext is tentative until a successful result is accepted.
// Its reserved IV is returned with that result, for the caller's record frame.
// Clear cancels any pending result; failed results return no IV. Neither case
// may reuse its reservation. Captured keys keep their slot busy through a held
// result and through the clearing edge, protecting the key slot until erase.
module tenant_gcm_port #(
    parameter int AES_KEY_W = 256,
    parameter int MEM_DATA_W = 128,
    parameter int MAX_TXN_BYTES = 4096,
    parameter int SLOT_W = 3,
    parameter bit DECRYPT = 1'b1
) (
    input logic clk, reset, clear,
    input logic cmd_valid,
    output wire cmd_ready,
    input logic [AES_KEY_W-1:0] cmd_key,
    input logic [SLOT_W-1:0] cmd_slot,
    input logic [95:0] cmd_iv,
    input logic [127:0] cmd_expected_tag,
    input logic [95:0] cmd_tenant_id,
    input logic [31:0] cmd_record_type,
    input logic [63:0] cmd_destination,
    input logic [31:0] cmd_payload_bytes,
    input logic [3:0] cmd_error,
    output wire key_busy,
    output wire [SLOT_W-1:0] key_slot,

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
    output wire [95:0] out_tenant_id,
    output wire [63:0] out_destination,

    output wire result_valid,
    input logic result_ready,
    output wire [3:0] result_error,
    output wire [127:0] result_tag,
    output wire [95:0] result_iv
);
    localparam int MEM_BYTES = MEM_DATA_W / 8;
    localparam logic [3:0] OK = 4'd0;
    typedef enum logic [1:0] {IDLE, ACTIVE, RESULT} state_t;
    state_t state;

    logic held_key;
    logic [SLOT_W-1:0] slot_reg;
    logic [255:0] aad_reg;
    logic [5:0] aad_remaining;
    logic [95:0] tenant_reg, iv_reg;
    logic [63:0] destination_reg;
    logic [3:0] result_error_reg;
    logic [127:0] result_tag_reg;
    logic [95:0] result_iv_reg;

    wire enabled = !reset && !clear;
    wire engine_start_ready, engine_aad_ready, engine_in_ready;
    wire engine_out_valid, engine_out_last, engine_result_valid;
    wire [MEM_DATA_W-1:0] engine_out_data;
    wire [MEM_BYTES-1:0] engine_out_keep;
    wire [127:0] engine_result_tag;
    wire [2:0] engine_result_error;
    logic [MEM_DATA_W-1:0] engine_aad_data;
    logic [MEM_BYTES-1:0] engine_aad_keep;
    wire engine_aad_valid = enabled && state == ACTIVE && aad_remaining != 0;
    wire engine_aad_last = aad_remaining <= MEM_BYTES;
    wire engine_result_ready = enabled && state == ACTIVE;

    assign cmd_ready = enabled && state == IDLE && engine_start_ready;
    wire command_fire = cmd_valid && cmd_ready;
    wire engine_start_valid = command_fire && cmd_error == OK;

    // These signals intentionally retain the registered context while clear
    // or reset is asserted before an edge. A key-manager write on that edge
    // must still observe the slot as owned until the engine erases its key.
    assign key_busy = held_key;
    assign key_slot = slot_reg;

    // Leading-byte packing also supports buses wider than the entire header:
    // unused bytes are zero and are excluded by the leading-one keep mask.
    always @* begin
        engine_aad_data = '0;
        engine_aad_keep = '0;
        for (int b = 0; b < MEM_BYTES; b++) begin
            if (b < 32 && b < aad_remaining) begin
                engine_aad_data[MEM_DATA_W-1-8*b -: 8] = aad_reg[255-8*b -: 8];
                engine_aad_keep[MEM_BYTES-1-b] = 1'b1;
            end
        end
    end

    aes_gcm_engine #(
        .AES_KEY_W(AES_KEY_W), .MEM_DATA_W(MEM_DATA_W),
        .MAX_TXN_BYTES(MAX_TXN_BYTES), .MAX_AAD_BYTES(32)
    ) engine (
        .clk(clk), .reset(reset), .clear(clear),
        .start_valid(engine_start_valid), .start_ready(engine_start_ready),
        .decrypt(DECRYPT), .key_in(cmd_key), .iv(cmd_iv),
        .expected_tag(cmd_expected_tag), .aad_bytes(32'd32),
        .payload_bytes(cmd_payload_bytes),
        .aad_valid(engine_aad_valid), .aad_ready(engine_aad_ready),
        .aad_data(engine_aad_data), .aad_keep(engine_aad_keep),
        .aad_last(engine_aad_last),
        .in_valid(enabled && state == ACTIVE && in_valid),
        .in_ready(engine_in_ready), .in_data(in_data),
        .in_keep(in_keep), .in_last(in_last),
        .out_valid(engine_out_valid),
        .out_ready(enabled && state == ACTIVE && out_ready),
        .out_data(engine_out_data), .out_keep(engine_out_keep),
        .out_last(engine_out_last), .result_valid(engine_result_valid),
        .result_ready(engine_result_ready), .result_tag(engine_result_tag),
        .result_error(engine_result_error)
    );

    assign in_ready = enabled && state == ACTIVE && engine_in_ready;
    assign out_valid = enabled && state == ACTIVE && engine_out_valid;
    assign out_data = out_valid ? engine_out_data : '0;
    assign out_keep = out_valid ? engine_out_keep : '0;
    assign out_last = out_valid && engine_out_last;
    assign out_tenant_id = out_valid ? tenant_reg : 96'b0;
    assign out_destination = out_valid ? destination_reg : 64'b0;
    assign result_valid = enabled && state == RESULT;
    assign result_error = result_valid ? result_error_reg : OK;
    assign result_tag = result_valid ? result_tag_reg : 128'b0;
    assign result_iv = result_valid ? result_iv_reg : 96'b0;

    initial begin
        if (AES_KEY_W != 128 && AES_KEY_W != 256)
            $fatal(1, "tenant_gcm_port AES_KEY_W must be 128 or 256");
        if (MEM_DATA_W < 128 || MEM_DATA_W % 128 != 0)
            $fatal(1, "tenant_gcm_port MEM_DATA_W must be a positive multiple of 128");
        if (MAX_TXN_BYTES < 1)
            $fatal(1, "tenant_gcm_port MAX_TXN_BYTES must be positive");
        if (SLOT_W < 1)
            $fatal(1, "tenant_gcm_port SLOT_W must be positive");
    end

    always_ff @(posedge clk) begin
        if (reset || clear) begin
            state <= IDLE;
            held_key <= 1'b0;
            slot_reg <= '0;
            aad_reg <= '0;
            aad_remaining <= '0;
            tenant_reg <= '0;
            destination_reg <= '0;
            iv_reg <= '0;
            result_error_reg <= OK;
            result_tag_reg <= '0;
            result_iv_reg <= '0;
        end else begin
            case (state)
                IDLE: if (command_fire) begin
                    if (cmd_error != OK) begin
                        // A rejected lookup/reservation never captures the
                        // proposed key, IV, slot, or authenticated metadata.
                        state <= RESULT;
                        result_error_reg <= cmd_error;
                        result_tag_reg <= '0;
                        result_iv_reg <= '0;
                    end else begin
                        state <= ACTIVE;
                        held_key <= 1'b1;
                        slot_reg <= cmd_slot;
                        aad_reg <= {32'h54474331, cmd_tenant_id,
                                    cmd_record_type, cmd_payload_bytes,
                                    cmd_destination};
                        aad_remaining <= 6'd32;
                        tenant_reg <= cmd_tenant_id;
                        destination_reg <= cmd_destination;
                        iv_reg <= DECRYPT ? 96'b0 : cmd_iv;
                    end
                end
                ACTIVE: begin
                    if (engine_aad_valid && engine_aad_ready) begin
                        if (engine_aad_last) begin
                            aad_reg <= '0;
                            aad_remaining <= '0;
                        end else begin
                            aad_reg <= aad_reg << MEM_DATA_W;
                            aad_remaining <= aad_remaining - 6'(MEM_BYTES);
                        end
                    end
                    if (engine_result_valid) begin
                        state <= RESULT;
                        result_error_reg <= {1'b0, engine_result_error};
                        result_tag_reg <= !DECRYPT && engine_result_error == 0 ?
                                          engine_result_tag : 128'b0;
                        result_iv_reg <= !DECRYPT && engine_result_error == 0 ?
                                         iv_reg : 96'b0;
                        // Completion follows output drain and core erasure.
                        // Only public result fields survive while held.
                        aad_reg <= '0;
                        aad_remaining <= '0;
                        tenant_reg <= '0;
                        destination_reg <= '0;
                        iv_reg <= '0;
                    end
                end
                RESULT: if (result_ready) begin
                    state <= IDLE;
                    held_key <= 1'b0;
                    slot_reg <= '0;
                    result_error_reg <= OK;
                    result_tag_reg <= '0;
                    result_iv_reg <= '0;
                end
                default: begin
                    state <= IDLE;
                    held_key <= 1'b0;
                    slot_reg <= '0;
                    aad_reg <= '0;
                    aad_remaining <= '0;
                    tenant_reg <= '0;
                    destination_reg <= '0;
                    iv_reg <= '0;
                    result_error_reg <= OK;
                    result_tag_reg <= '0;
                    result_iv_reg <= '0;
                end
            endcase
        end
    end
endmodule
