// Trusted, bounded AES-GCM transaction engine (NIST SP 800-38D).
// The caller supplies a protected key and a fresh 96-bit IV for encryption.
// This primitive does not perform tenant lookup, IV reservation, DRAM record
// commit, or atomic accelerator buffer/tag commit. See docs/crypto-primitives.md.
//
// All streams are MSB-byte first, with leading-one keep masks. Declared byte
// lengths require full intermediate beats and exactly one (possibly partial)
// final beat. Empty sections have no beats. AAD precedes payload. Decryption
// quarantines the entire bounded message and exposes data only after tag match.
module aes_gcm_engine #(
    parameter int AES_KEY_W = 256,
    parameter int MEM_DATA_W = 128,
    parameter int MAX_TXN_BYTES = 4096,
    parameter int MAX_AAD_BYTES = 4096
) (
    input logic clk, reset, clear,
    input logic start_valid,
    output wire start_ready,
    input logic decrypt,
    input logic [AES_KEY_W-1:0] key_in,
    input logic [95:0] iv,
    input logic [127:0] expected_tag,
    input logic [31:0] aad_bytes, payload_bytes,
    input logic aad_valid,
    output wire aad_ready,
    input logic [MEM_DATA_W-1:0] aad_data,
    input logic [MEM_DATA_W/8-1:0] aad_keep,
    input logic aad_last,
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
    output wire result_valid,
    input logic result_ready,
    output wire [127:0] result_tag,
    output wire [2:0] result_error
);
    localparam int MEM_BYTES = MEM_DATA_W / 8;
    localparam int LANES = MEM_DATA_W / 128;
    localparam int COUNT_W = (LANES <= 1) ? 1 : $clog2(LANES + 1);
    localparam int QUARANTINE_BEATS = (MAX_TXN_BYTES + MEM_BYTES - 1) / MEM_BYTES;
    localparam logic [2:0] OK = 0, AUTH_FAIL = 1, PROTOCOL_ERROR = 2, LENGTH_ERROR = 3;
    typedef enum logic [3:0] {
        IDLE, SETUP_H, SETUP_J, SETUP_WAIT, HASH_START, AAD,
        PAYLOAD, DRAIN, LENGTH, HASH_WAIT, RELEASE, WIPE, RESULT
    } state_t;
    state_t state;
    logic decrypt_reg, setup_first;
    logic [AES_KEY_W-1:0] key_reg;
    logic [95:0] iv_reg;
    logic [127:0] h_reg, tag_mask, expected_tag_reg, result_tag_reg;
    logic [2:0] result_error_reg;
    logic [31:0] aad_total, payload_total, aad_remaining, payload_remaining;
    logic [MEM_DATA_W-1:0] quarantine_data [0:QUARANTINE_BEATS-1];
    logic [MEM_BYTES-1:0] quarantine_keep [0:QUARANTINE_BEATS-1];
    logic quarantine_last [0:QUARANTINE_BEATS-1];
    integer unsigned write_index, read_index;

    wire enabled = !reset && !clear;
    // Idle/terminal states erase private pipelines. They can never hold a
    // previous transaction across the next command acceptance.
    wire core_clear = reset || clear || state == IDLE || state == WIPE || state == RESULT || state == RELEASE;
    wire setup_in_ready, setup_out_valid;
    wire [127:0] setup_out_data;
    wire setup_in_valid = enabled && (state == SETUP_H || state == SETUP_J);
    wire setup_out_ready = enabled && state == SETUP_WAIT;
    aes_encrypt_block #(.AES_KEY_W(AES_KEY_W)) setup_aes (
        .clk(clk), .reset(core_clear), .in_valid(setup_in_valid),
        .in_ready(setup_in_ready), .key_in(key_reg),
        .block_in(state == SETUP_J ? {iv_reg, 32'd1} : 128'b0),
        .out_valid(setup_out_valid), .out_ready(setup_out_ready), .block_out(setup_out_data)
    );

    wire ctr_start_ready, ctr_in_ready, ctr_out_valid, ctr_error;
    wire [MEM_DATA_W-1:0] ctr_out_data;
    wire [MEM_BYTES-1:0] ctr_out_keep;
    wire ctr_out_last, ctr_out_ready;
    wire hash_start_ready, hash_in_ready, hash_out_valid, hash_error;
    wire [127:0] hash_out;
    logic hash_in_valid, hash_in_last;
    logic [MEM_DATA_W-1:0] hash_in_data;
    logic [COUNT_W-1:0] hash_in_blocks;
    wire starts_ready = hash_start_ready && (payload_total == 0 || ctr_start_ready);
    wire start_cores = enabled && state == HASH_START && starts_ready;

    function automatic [MEM_BYTES-1:0] keep_for(input logic [31:0] remaining);
        for (int b = 0; b < MEM_BYTES; b++) keep_for[MEM_BYTES-1-b] = (b < remaining);
    endfunction
    function automatic [MEM_DATA_W-1:0] masked_data(
        input logic [MEM_DATA_W-1:0] value, input logic [MEM_BYTES-1:0] keep
    );
        for (int b = 0; b < MEM_BYTES; b++)
            masked_data[MEM_DATA_W-1-8*b -: 8] = keep[MEM_BYTES-1-b] ? value[MEM_DATA_W-1-8*b -: 8] : 8'b0;
    endfunction
    function automatic [COUNT_W-1:0] block_count(input logic [MEM_BYTES-1:0] keep);
        integer count;
        count = 0;
        for (int lane = 0; lane < LANES; lane++)
            if (keep[MEM_BYTES-1-16*lane]) count = count + 1;
        return COUNT_W'(count);
    endfunction

    assign start_ready = enabled && state == IDLE;
    assign aad_ready = enabled && state == AAD && hash_in_ready;
    wire payload_malformed = in_keep != keep_for(payload_remaining) ||
                             in_last != (payload_remaining <= MEM_BYTES);
    // A malformed offered beat can always terminate the transaction, even
    // with a stalled ciphertext output. This avoids a ready -> valid feedback
    // path on the error branch and prevents backpressure from hiding an abort.
    assign in_ready = enabled && state == PAYLOAD &&
        (payload_malformed || (ctr_in_ready && (!decrypt_reg || hash_in_ready)));
    wire bad_aad = aad_valid && aad_ready &&
        (aad_keep != keep_for(aad_remaining) || aad_last != (aad_remaining <= MEM_BYTES));
    wire bad_payload = enabled && state == PAYLOAD && in_valid && payload_malformed;
    wire framing_fault = bad_aad || bad_payload || ctr_error || hash_error;
    wire payload_fire = in_valid && in_ready && !framing_fault;
    wire payload_phase = state == PAYLOAD || state == DRAIN;

    // Ready does not depend on framing_fault: this keeps a malformed input
    // from creating a combinational ready/valid cycle through the AES stall.
    assign ctr_out_ready = enabled && payload_phase && (decrypt_reg || (out_ready && hash_in_ready));
    gctr_core #(.AES_KEY_W(AES_KEY_W), .MEM_DATA_W(MEM_DATA_W)) ctr (
        .clk(clk), .reset(reset), .clear(core_clear),
        .start_valid(start_cores && payload_total != 0), .start_ready(ctr_start_ready),
        .key_in(key_reg), .initial_counter({iv_reg,32'd2}),
        .in_valid(payload_fire), .in_ready(ctr_in_ready),
        .in_data(in_data), .in_keep(in_keep), .in_last(in_last),
        .out_valid(ctr_out_valid), .out_ready(ctr_out_ready),
        .out_data(ctr_out_data), .out_keep(ctr_out_keep), .out_last(ctr_out_last),
        .protocol_error(ctr_error)
    );
    ghash_core #(.MEM_DATA_W(MEM_DATA_W)) hash (
        .clk(clk), .reset(reset), .clear(core_clear),
        .start_valid(start_cores), .start_ready(hash_start_ready), .hash_subkey(h_reg),
        .in_valid(hash_in_valid), .in_ready(hash_in_ready),
        .in_data(hash_in_data), .in_blocks(hash_in_blocks), .in_last(hash_in_last),
        .out_valid(hash_out_valid), .out_ready(enabled && state == HASH_WAIT),
        .hash_out(hash_out), .protocol_error(hash_error)
    );

    always @* begin
        hash_in_valid = 1'b0;
        hash_in_data = '0;
        hash_in_blocks = '0;
        hash_in_last = 1'b0;
        if (enabled && !framing_fault) begin
            if (state == AAD) begin
                hash_in_valid = aad_valid;
                hash_in_data = masked_data(aad_data, aad_keep);
                hash_in_blocks = block_count(aad_keep);
            end else if (payload_phase && decrypt_reg) begin
                hash_in_valid = payload_fire;
                hash_in_data = masked_data(in_data, in_keep);
                hash_in_blocks = block_count(in_keep);
            end else if (payload_phase) begin
                hash_in_valid = ctr_out_valid && out_ready;
                hash_in_data = ctr_out_data;
                hash_in_blocks = block_count(ctr_out_keep);
            end else if (state == LENGTH) begin
                hash_in_valid = 1'b1;
                hash_in_data[MEM_DATA_W-1 -: 128] = {29'b0,aad_total,3'b0,29'b0,payload_total,3'b0};
                hash_in_blocks = COUNT_W'(1);
                hash_in_last = 1'b1;
            end
        end
    end

    wire encrypt_output = !decrypt_reg && payload_phase && ctr_out_valid && hash_in_ready;
    assign out_valid = enabled && !framing_fault && (state == RELEASE || encrypt_output);
    assign out_data = !out_valid ? '0 : state == RELEASE ? quarantine_data[read_index] : ctr_out_data;
    assign out_keep = !out_valid ? '0 : state == RELEASE ? quarantine_keep[read_index] : ctr_out_keep;
    assign out_last = out_valid && (state == RELEASE ? quarantine_last[read_index] : ctr_out_last);
    assign result_valid = enabled && state == RESULT;
    assign result_tag = result_valid ? result_tag_reg : 128'b0;
    assign result_error = result_valid ? result_error_reg : OK;
    wire [127:0] calculated_tag = hash_out ^ tag_mask;
    wire authentication_success = (calculated_tag == expected_tag_reg);
    // A positive, full-width match is required. Also fail closed on unknown
    // comparison results in simulation; hardware still uses ordinary equality.
    wire authentication_failure = state == HASH_WAIT && hash_out_valid && decrypt_reg &&
        (authentication_success !== 1'b1);
    wire bad_length = start_valid && start_ready &&
        (payload_bytes > MAX_TXN_BYTES || aad_bytes > MAX_AAD_BYTES);
    wire abort_transaction = framing_fault || authentication_failure || bad_length;

    initial begin
        if (AES_KEY_W != 128 && AES_KEY_W != 256)
            $fatal(1, "AES-GCM AES_KEY_W must be 128 or 256");
        if (MEM_DATA_W < 128 || MEM_DATA_W % 128 != 0)
            $fatal(1, "AES-GCM MEM_DATA_W must be a positive multiple of 128");
        if (MAX_TXN_BYTES < 1 || MAX_AAD_BYTES < 0)
            $fatal(1, "AES-GCM byte capacities must be positive payload and nonnegative AAD");
    end

    always_ff @(posedge clk) begin
        if (reset || clear || abort_transaction) begin
            if (reset || clear) state <= IDLE;
            else state <= WIPE;
            result_error_reg <= (reset || clear) ? OK : bad_length ? LENGTH_ERROR :
                                authentication_failure ? AUTH_FAIL : PROTOCOL_ERROR;
            result_tag_reg <= '0;
            decrypt_reg <= 1'b0;
            setup_first <= 1'b0;
            key_reg <= '0;
            iv_reg <= '0;
            h_reg <= '0;
            tag_mask <= '0;
            expected_tag_reg <= '0;
            aad_total <= '0;
            payload_total <= '0;
            aad_remaining <= '0;
            payload_remaining <= '0;
            write_index <= 0;
            read_index <= 0;
            for (int b = 0; b < QUARANTINE_BEATS; b++) begin
                quarantine_data[b] <= '0;
                quarantine_keep[b] <= '0;
                quarantine_last[b] <= 1'b0;
            end
        end else begin
            case (state)
                IDLE: if (start_valid && start_ready) begin
                    state <= SETUP_H;
                    decrypt_reg <= decrypt;
                    key_reg <= key_in;
                    iv_reg <= iv;
                    expected_tag_reg <= decrypt ? expected_tag : 128'b0;
                    aad_total <= aad_bytes;
                    payload_total <= payload_bytes;
                    aad_remaining <= aad_bytes;
                    payload_remaining <= payload_bytes;
                    setup_first <= 1'b1;
                    result_error_reg <= OK;
                end
                SETUP_H: if (setup_in_ready) state <= SETUP_J;
                SETUP_J: if (setup_in_ready) state <= SETUP_WAIT;
                SETUP_WAIT: if (setup_out_valid) begin
                    if (setup_first) begin
                        h_reg <= setup_out_data;
                        setup_first <= 1'b0;
                    end else begin
                        tag_mask <= setup_out_data;
                        state <= HASH_START;
                    end
                end
                HASH_START: if (start_cores) begin
                    key_reg <= '0;
                    iv_reg <= '0;
                    h_reg <= '0;
                    if (aad_total != 0) state <= AAD;
                    else if (payload_total != 0) state <= PAYLOAD;
                    else state <= LENGTH;
                end
                AAD: if (aad_valid && aad_ready) begin
                    if (aad_last) begin
                        aad_remaining <= '0;
                        if (payload_total != 0) state <= PAYLOAD;
                        else state <= LENGTH;
                    end else aad_remaining <= aad_remaining - MEM_BYTES;
                end
                PAYLOAD: if (payload_fire) begin
                    if (in_last) begin
                        payload_remaining <= '0;
                        state <= DRAIN;
                    end else payload_remaining <= payload_remaining - MEM_BYTES;
                end
                DRAIN: begin end
                LENGTH: if (hash_in_ready) state <= HASH_WAIT;
                HASH_WAIT: if (hash_out_valid) begin
                    // Full-width equality above has no early-exit byte loop.
                    // Never reveal a calculated tag for a decryption request.
                    result_tag_reg <= decrypt_reg ? 128'b0 : calculated_tag;
                    expected_tag_reg <= '0;
                    tag_mask <= '0;
                    aad_total <= '0;
                    payload_total <= '0;
                    if (decrypt_reg && write_index != 0) state <= RELEASE;
                    else state <= WIPE;
                end
                RELEASE: if (out_ready) begin
                    quarantine_data[read_index] <= '0;
                    quarantine_keep[read_index] <= '0;
                    quarantine_last[read_index] <= 1'b0;
                    if (quarantine_last[read_index]) begin
                        state <= WIPE;
                        write_index <= 0;
                        read_index <= 0;
                    end else read_index <= read_index + 1;
                end
                WIPE: state <= RESULT;
                RESULT: if (result_ready) begin
                    state <= IDLE;
                    result_tag_reg <= '0;
                    result_error_reg <= OK;
                    decrypt_reg <= 1'b0;
                end
                default: state <= IDLE;
            endcase
            if (payload_phase && ctr_out_valid && ctr_out_ready) begin
                if (decrypt_reg) begin
                    quarantine_data[write_index] <= ctr_out_data;
                    quarantine_keep[write_index] <= ctr_out_keep;
                    quarantine_last[write_index] <= ctr_out_last;
                    write_index <= write_index + 1;
                end
                if (ctr_out_last) state <= LENGTH;
            end
        end
    end
endmodule
