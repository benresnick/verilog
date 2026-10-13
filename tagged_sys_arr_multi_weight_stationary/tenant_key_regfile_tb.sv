`timescale 1ns/1ps

module tenant_key_regfile_case #(
    parameter int S = 3,
    parameter int KEY_W = 256,
    parameter int SW = (S <= 1) ? 1 : $clog2(S)
) (input logic clk, output logic done);
    logic reset, provision_valid, invalidate_valid, reserve_iv_valid;
    wire provision_ready, provision_error, invalidate_ready, reserve_iv_grant, nonce_exhausted;
    logic [SW-1:0] provision_slot, invalidate_slot, reserve_iv_slot;
    logic [95:0] provision_tenant_id, lookup_tenant_id [0:2];
    wire [95:0] reserved_iv;
    logic [KEY_W-1:0] provision_key;
    wire [KEY_W-1:0] lookup_key [0:2];
    logic [31:0] provision_iv_fixed_field;
    logic [63:0] provision_counter_start;
    logic slot_busy [0:S-1];
    wire lookup_found [0:2], lookup_duplicate [0:2];
    wire [SW-1:0] lookup_slot [0:2];
    integer reservations;
    logic [KEY_W-1:0] seen_key [0:127];
    logic [95:0] seen_iv [0:127];
    logic [95:0] saved_tenant;
    logic [63:0] saved_counter;

    tenant_key_regfile #(.NUM_KEY_SLOTS(S), .AES_KEY_W(KEY_W), .LOOKUP_PORTS(3)) dut (.*);

    task automatic ck(input logic condition, input string message);
        if (condition !== 1'b1)
            $fatal(1, "key-regfile slots=%0d AES=%0d: %s", S, KEY_W, message);
    endtask

    // Cross-transaction scoreboard: even reservations for aborted work remain
    // in the history. Never include key material in a diagnostic or waveform.
    always @(posedge clk) begin
        if (!reset && reserve_iv_grant) begin
            for (int i = 0; i < reservations; i++)
                ck(!(seen_key[i] == dut.aes_key[reserve_iv_slot] && seen_iv[i] == reserved_iv),
                   "an accepted key/IV pair was reused");
            ck(reservations < 128, "reservation scoreboard capacity");
            seen_key[reservations] = dut.aes_key[reserve_iv_slot];
            seen_iv[reservations] = reserved_iv;
            reservations = reservations + 1;
        end
    end

    task automatic check_zero_slot(input int slot);
        ck(dut.valid[slot] === 1'b0 && dut.tenant_id[slot] === 96'b0 &&
           dut.aes_key[slot] === {KEY_W{1'b0}} && dut.iv_fixed[slot] === 32'b0 &&
           dut.invocation_counter[slot] === 64'b0, "all invalidated entry fields zeroized");
    endtask

    task automatic check_quiet_lookup(input int port_num);
        ck(!lookup_found[port_num] && lookup_key[port_num] === {KEY_W{1'b0}} &&
           lookup_slot[port_num] === {SW{1'b0}}, "failed lookup releases no key or slot");
    endtask

    task automatic provision(input int slot, input logic [95:0] tenant,
                             input logic [KEY_W-1:0] key, input logic [31:0] fixed_field,
                             input logic [63:0] counter_start, input logic accepted);
        @(negedge clk);
        provision_valid = 1;
        provision_slot = slot;
        provision_tenant_id = tenant;
        provision_key = key;
        provision_iv_fixed_field = fixed_field;
        provision_counter_start = counter_start;
        #1;
        ck(provision_ready === accepted && provision_error === !accepted,
           "provision acceptance/error before committing edge");
        @(posedge clk); #1;
        if (accepted) begin
            ck(dut.valid[slot] && dut.tenant_id[slot] == tenant && dut.aes_key[slot] == key &&
               dut.iv_fixed[slot] == fixed_field && dut.invocation_counter[slot] == counter_start,
               "provision writes every field atomically");
        end
        @(negedge clk);
        provision_valid = 0;
    endtask

    task automatic reserve(input int slot, input logic [95:0] expected_iv,
                           input logic accepted, input logic exhausted);
        @(negedge clk);
        reserve_iv_valid = 1;
        reserve_iv_slot = slot;
        #1;
        ck(reserve_iv_grant === accepted && nonce_exhausted === exhausted,
           "IV reservation grant/exhaustion");
        ck(reserved_iv === (accepted ? expected_iv : 96'b0), "reserved IV is qualified by grant");
        @(posedge clk); #1;
        @(negedge clk);
        reserve_iv_valid = 0;
    endtask

    initial begin
        done = 0;
        reservations = 0;
        reset = 1;
        provision_valid = 0;
        provision_slot = '0;
        provision_tenant_id = '0;
        provision_key = '0;
        provision_iv_fixed_field = '0;
        provision_counter_start = '0;
        invalidate_valid = 0;
        invalidate_slot = '0;
        reserve_iv_valid = 0;
        reserve_iv_slot = '0;
        for (int i = 0; i < S; i++) slot_busy[i] = 0;
        for (int p = 0; p < 3; p++) lookup_tenant_id[p] = 96'ha;
        repeat (2) @(posedge clk);
        #1;
        for (int i = 0; i < S; i++) check_zero_slot(i);
        ck(!provision_ready && !invalidate_ready && !reserve_iv_grant && !provision_error &&
           !nonce_exhausted && reserved_iv == 0, "reset gates handshake and IV outputs");
        @(negedge clk); reset = 0;
        reserve(0, '0, 0, 0);
        provision(0, 96'ha, 'h11, 32'h100, 64'd5, 1);
        #1;
        for (int p = 0; p < 3; p++)
            ck(lookup_found[p] && !lookup_duplicate[p] && lookup_key[p] == 'h11 && lookup_slot[p] == 0,
               "three concurrent lookups of the same key");
        lookup_tenant_id[2] = 96'hffff;
        #1;
        check_quiet_lookup(2);
        ck(!lookup_duplicate[2], "miss is distinguished from duplicate match");
        lookup_tenant_id[2] = 96'ha;
        reserve(0, {32'h100, 64'd5}, 1, 0);
        reserve(0, {32'h100, 64'd6}, 1, 0);

        // Holding valid represents separate accepted reservations on each edge.
        @(negedge clk); reserve_iv_valid = 1; reserve_iv_slot = 0;
        #1; ck(reserve_iv_grant && reserved_iv == {32'h100, 64'd7}, "first consecutive grant");
        @(posedge clk); #1;
        ck(reserve_iv_grant && reserved_iv == {32'h100, 64'd8}, "next consecutive grant");
        @(posedge clk); #1;
        ck(dut.invocation_counter[0] == 9, "each accepted grant advances exactly once");
        @(negedge clk); reserve_iv_valid = 0;

        // Busy blocks all mutations, including reservations, without hiding an
        // engine's existing combinational lookup result.
        slot_busy[0] = 1;
        provision(0, 96'hb, 'h22, 32'h999, 0, 0);
        reserve(0, '0, 0, 0);
        @(negedge clk); invalidate_valid = 1; invalidate_slot = 0;
        #1; ck(!invalidate_ready, "busy invalidation rejected");
        @(posedge clk); #1;
        ck(dut.valid[0] && dut.tenant_id[0] == 96'ha && dut.aes_key[0] == 'h11 &&
           dut.invocation_counter[0] == 9, "busy entry preserved");
        @(negedge clk); invalidate_valid = 0; slot_busy[0] = 0;

        provision(0, 96'ha, 'h11, 32'h100, 8, 0);
        provision(0, 96'hb, 'h11, 32'h100, 0, 0);
        ck(dut.tenant_id[0] == 96'ha && dut.invocation_counter[0] == 9,
           "counter rollback rejected even when renaming a tenant");
        provision(0, 96'ha, 'h11, 32'h100, 9, 1);
        provision(0, 96'ha, 'h11, 32'h100, 100, 1);
        reserve(0, {32'h100, 64'd100}, 1, 0);

        // A rejected mutation does not take priority over an eligible reserve.
        @(negedge clk);
        provision_valid = 1; provision_counter_start = 0;
        reserve_iv_valid = 1; reserve_iv_slot = 0;
        #1;
        ck(!provision_ready && provision_error && reserve_iv_grant &&
           reserved_iv == {32'h100, 64'd101}, "rejected rollback cannot block a valid reserve");
        @(posedge clk); #1;
        ck(dut.invocation_counter[0] == 102, "rejected provision cannot overwrite reserved counter");
        @(negedge clk); provision_valid = 0; reserve_iv_valid = 0;

        if (S > 1) begin
            provision(1, 96'ha, 'h22, 32'h200, 0, 0);
            check_zero_slot(1);
            provision(1, 96'hb, 'h11, 32'h100, 200, 0);
            check_zero_slot(1);
            // The same AES key can use distinct provisioned fixed fields.
            provision(1, 96'hb, 'h11, 32'h200, 0, 1);
            reserve(1, {32'h200, 64'd0}, 1, 0);
            for (int i = 2; i < S; i++)
                provision(i, 96'ha + i, 'h20 + i, 32'h300 + i, i, 1);
            for (int i = 0; i < S; i++) begin
                for (int p = 0; p < 3; p++) lookup_tenant_id[p] = 96'ha + ((i + p) % S);
                #1;
                for (int p = 0; p < 3; p++)
                    ck(lookup_found[p] && !lookup_duplicate[p] && lookup_slot[p] == ((i + p) % S) &&
                       lookup_key[p] == dut.aes_key[(i + p) % S], "every slot on every lookup port");
            end

            // Inject corrupted tenant state to exercise an otherwise unreachable
            // duplicate match. Normal provisioning cannot create this state.
            @(negedge clk);
            saved_tenant = dut.tenant_id[1];
            dut.tenant_id[1] = dut.tenant_id[0];
            for (int p = 0; p < 3; p++) lookup_tenant_id[p] = 96'ha;
            reserve_iv_slot = 0; reserve_iv_valid = 1;
            #1;
            for (int p = 0; p < 3; p++) begin
                check_quiet_lookup(p);
                ck(lookup_duplicate[p], "duplicate match reports fault on every port");
            end
            ck(!reserve_iv_grant && reserved_iv == 0, "duplicate tenant cannot reserve a nonce");
            saved_counter = dut.invocation_counter[0];
            @(posedge clk); #1;
            ck(dut.invocation_counter[0] == saved_counter, "duplicate reservation leaves counter unchanged");
            @(negedge clk);
            dut.tenant_id[1] = saved_tenant;
            reserve_iv_valid = 0;
        end

        // Unrepresentable slot encodings (one slot and non-power-of-two sizes).
        if (S < 2**SW) begin
            provision(S, 96'hff, 'hff, 32'hff, 0, 0);
            reserve(S, '0, 0, 0);
            @(negedge clk); invalidate_valid = 1; invalidate_slot = S;
            #1; ck(invalidate_ready === 1'b0, "out-of-range invalidation rejected");
            @(posedge clk); #1;
            ck(dut.valid[0], "out-of-range write preserves valid state");
            @(negedge clk); invalidate_valid = 0;
        end
        @(negedge clk);
        provision_valid = 1; provision_slot = 'x;
        invalidate_valid = 1; invalidate_slot = 'x;
        reserve_iv_valid = 1; reserve_iv_slot = 'x;
        #1;
        ck(provision_ready === 1'b0 && provision_error === 1'b1 && invalidate_ready === 1'b0 &&
           reserve_iv_grant === 1'b0 && nonce_exhausted === 1'b0 && reserved_iv === 96'b0,
           "unknown slot encodings fail closed");
        @(posedge clk); #1;
        @(negedge clk); provision_valid = 0; invalidate_valid = 0; reserve_iv_valid = 0;

        // Provision beats a same-slot reservation and masks old-key lookup.
        for (int p = 0; p < 3; p++) lookup_tenant_id[p] = 96'ha;
        provision_valid = 1; provision_slot = 0; provision_tenant_id = 96'ha;
        provision_key = 'h22; provision_iv_fixed_field = 32'h110; provision_counter_start = 10;
        reserve_iv_valid = 1; reserve_iv_slot = 0;
        #1;
        ck(provision_ready && !provision_error && !reserve_iv_grant && reserved_iv == 0,
           "same-slot provision wins over reservation");
        for (int p = 0; p < 3; p++) check_quiet_lookup(p);
        @(posedge clk); #1;
        ck(dut.aes_key[0] == 'h22 && dut.invocation_counter[0] == 10,
           "reservation cannot corrupt newly provisioned counter");
        @(negedge clk); provision_valid = 0; reserve_iv_valid = 0;
        reserve(0, {32'h110, 64'd10}, 1, 0);

        // Invalidation wins a three-way collision and scrubs every field.
        @(negedge clk);
        invalidate_valid = 1; invalidate_slot = 0;
        provision_valid = 1; provision_slot = 0; provision_key = 'h33;
        provision_iv_fixed_field = 32'h120; provision_counter_start = 15;
        reserve_iv_valid = 1; reserve_iv_slot = 0;
        #1;
        ck(invalidate_ready && !provision_ready && provision_error && !reserve_iv_grant && reserved_iv == 0,
           "invalidation wins same-slot three-way collision");
        for (int p = 0; p < 3; p++) check_quiet_lookup(p);
        @(posedge clk); #1; check_zero_slot(0);
        @(negedge clk); provision_valid = 0; invalidate_valid = 0; reserve_iv_valid = 0;
        #1; for (int p = 0; p < 3; p++) check_quiet_lookup(p);

        // Independent slots accept operations on the same edge.
        @(negedge clk);
        provision_valid = 1; provision_slot = 0; provision_tenant_id = 96'ha;
        provision_key = 'h33; provision_iv_fixed_field = 32'h120; provision_counter_start = 15;
        if (S > 1) begin invalidate_valid = 1; invalidate_slot = 1; end
        if (S > 2) begin reserve_iv_valid = 1; reserve_iv_slot = S-1; end
        #1;
        ck(provision_ready, "independent provision accepted");
        if (S > 1) ck(invalidate_ready, "independent invalidation accepted");
        if (S > 2) ck(reserve_iv_grant && reserved_iv == {32'(32'h300 + S - 1), 64'(S - 1)},
                      "independent reservation accepted");
        @(posedge clk); #1;
        ck(dut.valid[0] && dut.aes_key[0] == 'h33 && dut.invocation_counter[0] == 15,
           "independent provision committed");
        if (S > 1) check_zero_slot(1);
        if (S > 2) ck(dut.invocation_counter[S-1] == S, "independent reserve committed");
        @(negedge clk); provision_valid = 0; invalidate_valid = 0; reserve_iv_valid = 0;

        // The maximum counter is a terminal sentinel and is never granted.
        provision(0, 96'ha, 'h44, 32'h400, 64'hffff_ffff_ffff_fffe, 1);
        reserve(0, {32'h400, 64'hffff_ffff_ffff_fffe}, 1, 0);
        reserve(0, '0, 0, 1);
        reserve(0, '0, 0, 1);
        ck(dut.invocation_counter[0] == 64'hffff_ffff_ffff_ffff, "exhausted counter never wraps");
        provision(0, 96'ha, 'h44, 32'h400, 0, 0);
        provision(0, 96'ha, 'h44, 32'h400, 64'hffff_ffff_ffff_ffff, 1);
        reserve(0, '0, 0, 1);
        provision(0, 96'ha, 'h44, 32'h401, 0, 1);
        reserve(0, {32'h401, 64'd0}, 1, 0);

        // Reset immediately gates even an otherwise eligible reservation,
        // then zeroizes busy entries and pending requests at its active edge.
        @(negedge clk);
        reserve_iv_valid = 1; reserve_iv_slot = 0;
        #1; ck(reserve_iv_grant, "reservation eligible before asynchronous reset gating");
        reset = 1;
        #1; ck(!reserve_iv_grant && reserved_iv == 0, "reset masks eligible reservation before the clock edge");
        provision_valid = 1; provision_slot = 0;
        invalidate_valid = 1; invalidate_slot = 0;
        for (int i = 0; i < S; i++) slot_busy[i] = 1;
        #1;
        ck(!provision_ready && !provision_error && !invalidate_ready && !reserve_iv_grant &&
           !nonce_exhausted && reserved_iv == 0, "reset overrides pending busy operations");
        for (int p = 0; p < 3; p++) begin
            check_quiet_lookup(p);
            ck(!lookup_duplicate[p], "reset suppresses lookup fault outputs");
        end
        @(posedge clk); #1;
        for (int i = 0; i < S; i++) check_zero_slot(i);
        @(negedge clk);
        provision_valid = 0; invalidate_valid = 0; reserve_iv_valid = 0;
        for (int i = 0; i < S; i++) slot_busy[i] = 0;
        reset = 0;
        reserve(0, '0, 0, 0);
        provision(0, 96'b0, 'h55, 32'h500, 0, 1);
        for (int p = 0; p < 3; p++) lookup_tenant_id[p] = 0;
        #1;
        for (int p = 0; p < 3; p++)
            ck(lookup_found[p] && lookup_key[p] == 'h55 && !lookup_duplicate[p],
               "zero tenant ID is valid after reprovisioning");
        reserve(0, {32'h500, 64'd0}, 1, 0);
        done = 1;
    end
endmodule

module tenant_key_regfile_tb;
    logic clk = 0;
    wire [2:0] done;
    always #5 clk = ~clk;
    tenant_key_regfile_case #(.S(1), .KEY_W(128)) one_slot (.clk(clk), .done(done[0]));
    tenant_key_regfile_case #(.S(3), .KEY_W(256)) three_slots (.clk(clk), .done(done[1]));
    tenant_key_regfile_case #(.S(8), .KEY_W(256)) eight_slots (.clk(clk), .done(done[2]));
    initial begin
        wait (&done);
        $display("PASS: trusted tenant key register file (1/3/8 slots, AES-128/256)");
        $finish;
    end
    initial begin
        #10000;
        $fatal(1, "key register file test timeout");
    end
endmodule
