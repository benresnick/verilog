// Three independent trusted GCM paths sharing one protected tenant key file.
// Paths 0 and 1 decrypt activation/weight records; path 2 encrypts output.
// These are trusted scheduler/buffer-adapter ports, NOT software MMIO. Key
// lookup values are wired only to private engines. Encryption IVs
// always come from the key file; cmd_iv[2] and cmd_expected_tag[2] are ignored.
//
// The command supplies the EXPECTED logical record type/destination. The port
// authenticates those fields, tenant ID and payload length in a fixed AAD
// header. Ordinary software must not choose these trusted ownership fields.
// Physical buffer/tag commit and committed DRAM records remain adapter duties.
module tenant_gcm_cluster #(
    parameter int AES_KEY_W = 256,
    parameter int MEM_DATA_W = 128,
    parameter int MAX_TXN_BYTES = 4096,
    parameter int NUM_KEY_SLOTS = 8,
    parameter int SLOT_W = (NUM_KEY_SLOTS <= 1) ? 1 : $clog2(NUM_KEY_SLOTS)
) (
    input logic clk, reset,
    input logic [2:0] clear,
    input logic provision_valid,
    output wire provision_ready,
    input logic [SLOT_W-1:0] provision_slot,
    input logic [95:0] provision_tenant_id,
    input logic [AES_KEY_W-1:0] provision_key,
    input logic [31:0] provision_iv_fixed_field,
    input logic [63:0] provision_counter_start,
    output wire provision_error,
    input logic invalidate_valid,
    input logic [SLOT_W-1:0] invalidate_slot,
    output wire invalidate_ready,

    input logic [2:0] cmd_valid,
    output wire [2:0] cmd_ready,
    input logic [2:0][95:0] cmd_tenant_id,
    input logic [2:0][31:0] cmd_record_type,
    input logic [2:0][63:0] cmd_destination,
    input logic [2:0][31:0] cmd_payload_bytes,
    input logic [2:0][95:0] cmd_iv,
    input logic [2:0][127:0] cmd_expected_tag,

    input logic [2:0] in_valid,
    output wire [2:0] in_ready,
    input logic [2:0][MEM_DATA_W-1:0] in_data,
    input logic [2:0][MEM_DATA_W/8-1:0] in_keep,
    input logic [2:0] in_last,
    output wire [2:0] out_valid,
    input logic [2:0] out_ready,
    output wire [2:0][MEM_DATA_W-1:0] out_data,
    output wire [2:0][MEM_DATA_W/8-1:0] out_keep,
    output wire [2:0] out_last,
    // Trusted destination metadata. Never put these ownership pins on DRAM.
    output wire [2:0][95:0] out_tenant_id,
    output wire [2:0][63:0] out_destination,
    output wire [2:0] result_valid,
    input logic [2:0] result_ready,
    output wire [2:0][3:0] result_error,
    output wire [2:0][127:0] result_tag,
    output wire [2:0][95:0] result_iv
);
    localparam logic [3:0] OK = 0, LENGTH_ERROR = 3,
        KEY_MISSING = 4, KEY_DUPLICATE = 5, NONCE_EXHAUSTED = 6;

    wire [95:0] lookup_tenant_id [0:2];
    wire lookup_found [0:2], lookup_duplicate [0:2];
    wire [AES_KEY_W-1:0] lookup_key [0:2];
    wire [SLOT_W-1:0] lookup_slot [0:2];
    logic slot_busy [0:NUM_KEY_SLOTS-1];
    wire [2:0] port_cmd_ready, port_key_busy;
    wire [SLOT_W-1:0] port_key_slot [0:2];
    logic [2:0] admit;
    logic [2:0][3:0] command_error;
    wire reserve_iv_valid, reserve_iv_grant, nonce_exhausted;
    wire [95:0] reserved_iv;
    wire key_mutation = (provision_valid && provision_ready) ||
                        (invalidate_valid && invalidate_ready);
    wire commands_enabled = !reset && !key_mutation;
    wire output_candidate = commands_enabled && !clear[2] && cmd_valid[2] &&
        port_cmd_ready[2] && cmd_payload_bytes[2] <= MAX_TXN_BYTES &&
        lookup_found[2] && !lookup_duplicate[2];

    // Busy depends ONLY on registered ownership, including while clear is
    // asserted before its wiping edge. A slot cannot be changed on that edge.
    always @* begin
        for (int s = 0; s < NUM_KEY_SLOTS; s++) begin
            slot_busy[s] = 1'b0;
            for (int p = 0; p < 3; p++)
                if (port_key_busy[p] && port_key_slot[p] == SLOT_W'(s))
                    slot_busy[s] = 1'b1;
        end
    end

    // No dependency on cmd_ready: reserve -> grant -> ready is feed-forward.
    // Both the GCM key capture and the IV reservation occur on the command
    // accepting edge. Registered ownership becomes busy only after that edge.
    assign reserve_iv_valid = output_candidate;
    tenant_key_regfile #(
        .TENANT_ID_W(96), .AES_KEY_W(AES_KEY_W),
        .NUM_KEY_SLOTS(NUM_KEY_SLOTS), .LOOKUP_PORTS(3), .SLOT_W(SLOT_W)
    ) keys (
        .clk(clk), .reset(reset),
        .provision_valid(provision_valid), .provision_ready(provision_ready),
        .provision_slot(provision_slot), .provision_tenant_id(provision_tenant_id),
        .provision_key(provision_key), .provision_iv_fixed_field(provision_iv_fixed_field),
        .provision_counter_start(provision_counter_start), .provision_error(provision_error),
        .invalidate_valid(invalidate_valid), .invalidate_slot(invalidate_slot),
        .invalidate_ready(invalidate_ready), .slot_busy(slot_busy),
        .lookup_tenant_id(lookup_tenant_id), .lookup_found(lookup_found),
        .lookup_duplicate(lookup_duplicate), .lookup_key(lookup_key), .lookup_slot(lookup_slot),
        .reserve_iv_valid(reserve_iv_valid), .reserve_iv_slot(lookup_slot[2]),
        .reserve_iv_grant(reserve_iv_grant), .reserved_iv(reserved_iv),
        .nonce_exhausted(nonce_exhausted)
    );

    always @* begin
        admit = '0;
        command_error = '0;
        for (int p = 0; p < 3; p++) begin
            if (commands_enabled && !clear[p]) begin
                admit[p] = 1'b1;
                // A malformed command must not consume a nonce or capture a
                // key. Duplicate matches have priority over a missing match.
                if (cmd_payload_bytes[p] > MAX_TXN_BYTES)
                    command_error[p] = LENGTH_ERROR;
                else if (lookup_duplicate[p])
                    command_error[p] = KEY_DUPLICATE;
                else if (!lookup_found[p])
                    command_error[p] = KEY_MISSING;
                else if (p == 2) begin
                    if (nonce_exhausted) command_error[p] = NONCE_EXHAUSTED;
                    else admit[p] = reserve_iv_grant;
                end else begin
                    // Let existing readers drain for a waiting encryptor.
                    // Other keys remain independent; when the slot is idle,
                    // all three paths may capture it together on one edge.
                    for (int s = 0; s < NUM_KEY_SLOTS; s++)
                        if (output_candidate && slot_busy[s] &&
                            lookup_slot[2] == SLOT_W'(s) && lookup_slot[p] == SLOT_W'(s))
                            admit[p] = 1'b0;
                end
            end
        end
    end

    generate
        for (genvar p = 0; p < 3; p++) begin : g_port
            localparam bit IS_OUTPUT = (p == 2);
            assign lookup_tenant_id[p] = cmd_tenant_id[p];
            assign cmd_ready[p] = admit[p] && port_cmd_ready[p];
            tenant_gcm_port #(
                .AES_KEY_W(AES_KEY_W), .MEM_DATA_W(MEM_DATA_W),
                .MAX_TXN_BYTES(MAX_TXN_BYTES), .SLOT_W(SLOT_W), .DECRYPT(!IS_OUTPUT)
            ) port_engine (
                .clk(clk), .reset(reset), .clear(clear[p]),
                .cmd_valid(cmd_valid[p] && admit[p]), .cmd_ready(port_cmd_ready[p]),
                .cmd_key(lookup_key[p]), .cmd_slot(lookup_slot[p]),
                .cmd_iv(IS_OUTPUT ? reserved_iv : cmd_iv[p]),
                .cmd_expected_tag(IS_OUTPUT ? 128'b0 : cmd_expected_tag[p]),
                .cmd_tenant_id(cmd_tenant_id[p]), .cmd_record_type(cmd_record_type[p]),
                .cmd_destination(cmd_destination[p]), .cmd_payload_bytes(cmd_payload_bytes[p]),
                .cmd_error(command_error[p]), .key_busy(port_key_busy[p]), .key_slot(port_key_slot[p]),
                .in_valid(in_valid[p]), .in_ready(in_ready[p]), .in_data(in_data[p]),
                .in_keep(in_keep[p]), .in_last(in_last[p]),
                .out_valid(out_valid[p]), .out_ready(out_ready[p]), .out_data(out_data[p]),
                .out_keep(out_keep[p]), .out_last(out_last[p]),
                .out_tenant_id(out_tenant_id[p]), .out_destination(out_destination[p]),
                .result_valid(result_valid[p]), .result_ready(result_ready[p]),
                .result_error(result_error[p]), .result_tag(result_tag[p]), .result_iv(result_iv[p])
            );
        end
    endgenerate

    initial begin
        if (AES_KEY_W != 128 && AES_KEY_W != 256)
            $fatal(1, "Tenant GCM AES_KEY_W must be 128 or 256");
        if (MEM_DATA_W < 128 || MEM_DATA_W % 128 != 0)
            $fatal(1, "Tenant GCM MEM_DATA_W must be a positive multiple of 128");
        if (MAX_TXN_BYTES < 1 || NUM_KEY_SLOTS < 1)
            $fatal(1, "Tenant GCM transaction capacity and key slots must be positive");
        if (SLOT_W < ((NUM_KEY_SLOTS <= 1) ? 1 : $clog2(NUM_KEY_SLOTS)))
            $fatal(1, "Tenant GCM SLOT_W cannot address every key slot");
    end
endmodule
