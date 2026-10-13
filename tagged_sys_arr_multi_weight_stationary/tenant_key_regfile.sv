// Trusted-only active-tenant key store. Keys leave only through the engine
// lookup ports; there is no general read address/data interface.
//
// A valid/ready operation and an IV grant commit at the rising clock edge.
// Same-slot priority is invalidate > provision > reserve; different slots may
// operate concurrently. Lookups into a slot being changed are suppressed so
// an engine cannot capture the old key on that edge. An encryption engine
// captures both the key and granted IV on the SAME idle-slot edge, then asserts
// registered slot_busy; asserting busy before reserving would block its own
// reservation. Engines hold slot_busy until all captured-key use is finished.
//
// The current live key/IV sequence cannot be rolled back or aliased in another
// active slot. This volatile store does not retain the history of overwritten,
// invalidated, or reset keys. Trusted provisioning MUST ensure that a retired
// key/IV sequence is never restarted, including after reset/power loss. Use a
// fresh key, a globally fresh fixed field for that key, or a persistent counter.
module tenant_key_regfile #(
    parameter int TENANT_ID_W = 96,
    parameter int AES_KEY_W = 256,
    parameter int NUM_KEY_SLOTS = 8,
    parameter int LOOKUP_PORTS = 3,
    parameter int SLOT_W = (NUM_KEY_SLOTS <= 1) ? 1 : $clog2(NUM_KEY_SLOTS)
) (
    input logic clk, reset,
    input logic provision_valid,
    output logic provision_ready,
    input logic [SLOT_W-1:0] provision_slot,
    input logic [TENANT_ID_W-1:0] provision_tenant_id,
    input logic [AES_KEY_W-1:0] provision_key,
    input logic [31:0] provision_iv_fixed_field,
    input logic [63:0] provision_counter_start,
    output logic provision_error,
    input logic invalidate_valid,
    input logic [SLOT_W-1:0] invalidate_slot,
    output logic invalidate_ready,
    input logic slot_busy [0:NUM_KEY_SLOTS-1],
    input logic [TENANT_ID_W-1:0] lookup_tenant_id [0:LOOKUP_PORTS-1],
    output logic lookup_found [0:LOOKUP_PORTS-1],
    output logic lookup_duplicate [0:LOOKUP_PORTS-1],
    output logic [AES_KEY_W-1:0] lookup_key [0:LOOKUP_PORTS-1],
    output logic [SLOT_W-1:0] lookup_slot [0:LOOKUP_PORTS-1],
    input logic reserve_iv_valid,
    input logic [SLOT_W-1:0] reserve_iv_slot,
    output logic reserve_iv_grant,
    output logic [95:0] reserved_iv,
    output logic nonce_exhausted
);
    logic valid [0:NUM_KEY_SLOTS-1];
    logic [TENANT_ID_W-1:0] tenant_id [0:NUM_KEY_SLOTS-1];
    logic [AES_KEY_W-1:0] aes_key [0:NUM_KEY_SLOTS-1];
    logic [31:0] iv_fixed [0:NUM_KEY_SLOTS-1];
    logic [63:0] invocation_counter [0:NUM_KEY_SLOTS-1];
    logic duplicate_provision, duplicate_sequence, counter_rollback;
    logic invalidate_accept, provision_accept, reserve_duplicate;

    initial begin
        if (TENANT_ID_W < 1) $fatal(1, "TENANT_ID_W must be positive");
        if (AES_KEY_W != 128 && AES_KEY_W != 256)
            $fatal(1, "AES_KEY_W must be 128 or 256");
        if (NUM_KEY_SLOTS < 1) $fatal(1, "NUM_KEY_SLOTS must be positive");
        if (LOOKUP_PORTS < 1) $fatal(1, "LOOKUP_PORTS must be positive");
        if (SLOT_W < ((NUM_KEY_SLOTS <= 1) ? 1 : $clog2(NUM_KEY_SLOTS)))
            $fatal(1, "SLOT_W cannot address every key slot");
    end

    always_comb begin
        duplicate_provision = 1'b0;
        duplicate_sequence = 1'b0;
        counter_rollback = 1'b0;
        reserve_duplicate = 1'b0;
        provision_ready = 1'b0;
        provision_error = 1'b0;
        invalidate_ready = 1'b0;
        invalidate_accept = 1'b0;
        provision_accept = 1'b0;
        reserve_iv_grant = 1'b0;
        nonce_exhausted = 1'b0;
        reserved_iv = '0;

        // Check range before indexing arrays, including non-power-of-two sizes.
        if (!reset) begin
            if (invalidate_slot < NUM_KEY_SLOTS)
                invalidate_ready = !slot_busy[invalidate_slot];
            invalidate_accept = invalidate_valid && invalidate_ready;

            for (int i = 0; i < NUM_KEY_SLOTS; i++) begin
                if (i != provision_slot && valid[i]) begin
                    if (tenant_id[i] == provision_tenant_id)
                        duplicate_provision = 1'b1;
                    if (aes_key[i] == provision_key &&
                        iv_fixed[i] == provision_iv_fixed_field)
                        duplicate_sequence = 1'b1;
                end
            end
            if (provision_slot < NUM_KEY_SLOTS) begin
                counter_rollback = valid[provision_slot] &&
                    aes_key[provision_slot] == provision_key &&
                    iv_fixed[provision_slot] == provision_iv_fixed_field &&
                    provision_counter_start < invocation_counter[provision_slot];
                provision_ready = !slot_busy[provision_slot] &&
                    !duplicate_provision && !duplicate_sequence && !counter_rollback &&
                    !(invalidate_accept && invalidate_slot == provision_slot);
            end
            provision_error = provision_valid && !provision_ready;
            provision_accept = provision_valid && provision_ready;

            if (reserve_iv_slot < NUM_KEY_SLOTS) begin
                for (int i = 0; i < NUM_KEY_SLOTS; i++) begin
                    if (i != reserve_iv_slot && valid[i] &&
                        tenant_id[i] == tenant_id[reserve_iv_slot])
                        reserve_duplicate = 1'b1;
                end
                if (reserve_iv_valid && valid[reserve_iv_slot] && !reserve_duplicate &&
                    !slot_busy[reserve_iv_slot] &&
                    !(invalidate_accept && invalidate_slot == reserve_iv_slot) &&
                    !(provision_accept && provision_slot == reserve_iv_slot)) begin
                    nonce_exhausted = invocation_counter[reserve_iv_slot] == 64'hffff_ffff_ffff_ffff;
                    reserve_iv_grant = !nonce_exhausted;
                    if (reserve_iv_grant)
                        reserved_iv = {iv_fixed[reserve_iv_slot], invocation_counter[reserve_iv_slot]};
                end
            end
        end

        for (int p = 0; p < LOOKUP_PORTS; p++) begin
            lookup_found[p] = 1'b0;
            lookup_duplicate[p] = 1'b0;
            lookup_key[p] = '0;
            lookup_slot[p] = '0;
            if (!reset) begin
                for (int i = 0; i < NUM_KEY_SLOTS; i++) begin
                    if (valid[i] && tenant_id[i] == lookup_tenant_id[p]) begin
                        if (lookup_found[p]) lookup_duplicate[p] = 1'b1;
                        else begin
                            lookup_found[p] = 1'b1;
                            lookup_key[p] = aes_key[i];
                            lookup_slot[p] = SLOT_W'(i);
                        end
                    end
                end
                if (lookup_duplicate[p] ||
                    (invalidate_accept && invalidate_slot == lookup_slot[p]) ||
                    (provision_accept && provision_slot == lookup_slot[p])) begin
                    lookup_found[p] = 1'b0;
                    lookup_key[p] = '0;
                    lookup_slot[p] = '0;
                end
            end
        end
    end

    always_ff @(posedge clk) begin
        if (reset) begin
            for (int i = 0; i < NUM_KEY_SLOTS; i++) begin
                valid[i] <= 1'b0;
                tenant_id[i] <= '0;
                aes_key[i] <= '0;
                iv_fixed[i] <= '0;
                invocation_counter[i] <= '0;
            end
        end else begin
            if (provision_accept) begin
                valid[provision_slot] <= 1'b1;
                tenant_id[provision_slot] <= provision_tenant_id;
                aes_key[provision_slot] <= provision_key;
                iv_fixed[provision_slot] <= provision_iv_fixed_field;
                invocation_counter[provision_slot] <= provision_counter_start;
            end
            if (invalidate_accept) begin
                valid[invalidate_slot] <= 1'b0;
                tenant_id[invalidate_slot] <= '0;
                aes_key[invalidate_slot] <= '0;
                iv_fixed[invalidate_slot] <= '0;
                invocation_counter[invalidate_slot] <= '0;
            end
            // An aborted encryption may waste an IV but can never return it.
            if (reserve_iv_grant)
                invocation_counter[reserve_iv_slot] <= invocation_counter[reserve_iv_slot] + 1'b1;
        end
    end
endmodule
