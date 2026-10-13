`timescale 1ns/1ps
// Oracle records come from Python/OpenSSL EVP, including independent AAD packing.
// The bench contains no AES, GCTR, GHASH, or tag-generation implementation.
module tenant_gcm_cluster_tb #(
    parameter int AES_KEY_W = 256,
    parameter int MEM_DATA_W = 128,
    parameter int MAX_TXN_BYTES = 193,
    parameter int NUM_KEY_SLOTS = 3,
    parameter int SLOT_W = NUM_KEY_SLOTS <= 1 ? 1 : $clog2(NUM_KEY_SLOTS)
);
    localparam int BYTES = MEM_DATA_W / 8;
    localparam int LANES = MEM_DATA_W / 128;
    localparam int ROUNDS = AES_KEY_W == 128 ? 10 : 14;
    localparam int BEATS = (MAX_TXN_BYTES + BYTES - 1) / BYTES;
    localparam int VECTORS = 1024;
    localparam int SECOND_SLOT = NUM_KEY_SLOTS > 1 ? 1 : 0;
    logic clk = 0, reset = 1;
    logic [2:0] clear = 0;
    logic provision_valid = 0, invalidate_valid = 0;
    wire provision_ready, provision_error, invalidate_ready;
    logic [SLOT_W-1:0] provision_slot = 0, invalidate_slot = 0;
    logic [95:0] provision_tenant_id = 0;
    logic [AES_KEY_W-1:0] provision_key = 0;
    logic [31:0] provision_iv_fixed_field = 0;
    logic [63:0] provision_counter_start = 0;
    logic [2:0] cmd_valid = 0;
    wire [2:0] cmd_ready;
    logic [2:0][95:0] cmd_tenant_id = 0, cmd_iv = 0;
    logic [2:0][31:0] cmd_record_type = 0, cmd_payload_bytes = 0;
    logic [2:0][63:0] cmd_destination = 0;
    logic [2:0][127:0] cmd_expected_tag = 0;
    logic [2:0] in_valid = 0, in_last = 0, out_ready = 0, result_ready = 0;
    wire [2:0] in_ready, out_valid, out_last, result_valid;
    logic [2:0][MEM_DATA_W-1:0] in_data = 0;
    logic [2:0][BYTES-1:0] in_keep = 0;
    wire [2:0][MEM_DATA_W-1:0] out_data;
    wire [2:0][BYTES-1:0] out_keep;
    wire [2:0][95:0] out_tenant_id, result_iv;
    wire [2:0][63:0] out_destination;
    wire [2:0][127:0] result_tag;
    wire [2:0][3:0] result_error;
    logic [AES_KEY_W-1:0] vk [0:VECTORS-1];
    logic [95:0] vt [0:VECTORS-1], vi [0:VECTORS-1];
    logic [31:0] vr [0:VECTORS-1];
    logic [63:0] vd [0:VECTORS-1];
    int vl [0:VECTORS-1];
    logic [8*MAX_TXN_BYTES-1:0] vp [0:VECTORS-1];
    logic [8*MAX_TXN_BYTES-1:0] vc [0:VECTORS-1][0:2];
    logic [127:0] vtag [0:VECTORS-1][0:2];
    logic [127:0] bad_length_tag [0:VECTORS-1], bad_magic_tag [0:VECTORS-1];
    int vv [0:2], fault [0:2], faultbit [0:2], framing [0:2], nonce_index [0:2];
    int checked = 0, authenticated = 0, rejected = 0, cancelled = 0, groups = 0;
    int tag_bits = 8, metadata_bits = 4;
    logic [31:0] rng = 32'hcd529e31;
    string fixture_path;
    always #5 clk = ~clk;
    tenant_gcm_cluster #(.AES_KEY_W(AES_KEY_W), .MEM_DATA_W(MEM_DATA_W),
        .MAX_TXN_BYTES(MAX_TXN_BYTES), .NUM_KEY_SLOTS(NUM_KEY_SLOTS), .SLOT_W(SLOT_W)) dut (.*);

    // Observe erase throughout the hierarchy, not only public output masking.
    wire [2:0] engine_erased, metadata_erased, ownership_erased, reported_busy;
    for (genvar p = 0; p < 3; p++) begin : g_erase
        wire [BEATS-1:0] quarantine_erased;
        wire [ROUNDS:0] setup_state_erased, ctr_data_erased;
        wire [ROUNDS-1:0] setup_keys_erased;
        wire [LANES-1:0] lanes_erased;
        for (genvar b = 0; b < BEATS; b++) begin : g_buffer
            assign quarantine_erased[b] =
                dut.g_port[p].port_engine.engine.quarantine_data[b] === {MEM_DATA_W{1'b0}} &&
                dut.g_port[p].port_engine.engine.quarantine_keep[b] === {BYTES{1'b0}} &&
                dut.g_port[p].port_engine.engine.quarantine_last[b] === 1'b0;
        end
        for (genvar s = 0; s <= ROUNDS; s++) begin : g_setup
            assign setup_state_erased[s] = dut.g_port[p].port_engine.engine.setup_aes.state_pipe[s] === 128'b0;
            assign ctr_data_erased[s] =
                dut.g_port[p].port_engine.engine.ctr.data_pipe[s] === {MEM_DATA_W{1'b0}} &&
                dut.g_port[p].port_engine.engine.ctr.keep_pipe[s] === {BYTES{1'b0}};
        end
        for (genvar s = 0; s < ROUNDS; s++) begin : g_setup_key
            assign setup_keys_erased[s] = dut.g_port[p].port_engine.engine.setup_aes.key_pipe[s] === {AES_KEY_W{1'b0}};
        end
        for (genvar lane = 0; lane < LANES; lane++) begin : g_lane
            wire [ROUNDS:0] states;
            wire [ROUNDS-1:0] keys;
            for (genvar s = 0; s <= ROUNDS; s++) begin : g_state
                assign states[s] = dut.g_port[p].port_engine.engine.ctr.g_lane[lane].aes.state_pipe[s] === 128'b0;
            end
            for (genvar s = 0; s < ROUNDS; s++) begin : g_key
                assign keys[s] = dut.g_port[p].port_engine.engine.ctr.g_lane[lane].aes.key_pipe[s] === {AES_KEY_W{1'b0}};
            end
            assign lanes_erased[lane] = (&states) && (&keys);
        end
        assign engine_erased[p] = (&quarantine_erased) && (&setup_state_erased) &&
            (&setup_keys_erased) && (&ctr_data_erased) && (&lanes_erased) &&
            dut.g_port[p].port_engine.engine.key_reg === {AES_KEY_W{1'b0}} &&
            dut.g_port[p].port_engine.engine.iv_reg === 96'b0 &&
            dut.g_port[p].port_engine.engine.h_reg === 128'b0 &&
            dut.g_port[p].port_engine.engine.tag_mask === 128'b0 &&
            dut.g_port[p].port_engine.engine.expected_tag_reg === 128'b0 &&
            dut.g_port[p].port_engine.engine.ctr.key_reg === {AES_KEY_W{1'b0}} &&
            dut.g_port[p].port_engine.engine.ctr.counter_reg === 128'b0 &&
            dut.g_port[p].port_engine.engine.hash.h_reg === 128'b0 &&
            dut.g_port[p].port_engine.engine.hash.accumulator === 128'b0 &&
            dut.g_port[p].port_engine.engine.hash.result_reg === 128'b0;
        assign metadata_erased[p] = dut.g_port[p].port_engine.aad_reg === 256'b0 &&
            dut.g_port[p].port_engine.aad_remaining === 6'b0 &&
            dut.g_port[p].port_engine.tenant_reg === 96'b0 &&
            dut.g_port[p].port_engine.destination_reg === 64'b0 &&
            dut.g_port[p].port_engine.iv_reg === 96'b0;
        assign reported_busy[p] = dut.g_port[p].port_engine.key_busy;
        assign ownership_erased[p] = dut.g_port[p].port_engine.held_key === 1'b0 &&
            dut.g_port[p].port_engine.slot_reg === {SLOT_W{1'b0}};
    end

    task automatic ck(input logic ok, input string message);
        if (ok !== 1'b1)
            $fatal(1, "TENANT_GCM AES%0d bus%0d slots%0d group%0d checked%0d: %s",
                AES_KEY_W, MEM_DATA_W, NUM_KEY_SLOTS, groups, checked, message);
    endtask
    function automatic [31:0] random_word();
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        return rng;
    endfunction
    function automatic [BYTES-1:0] keep_for(input int count);
        logic [BYTES-1:0] value;
        value = 0;
        for (int b = 0; b < BYTES; b++) if (b < count) value[BYTES-1-b] = 1;
        return value;
    endfunction
    task automatic quiet(input int p);
        if (!out_valid[p])
            ck(out_data[p] === {MEM_DATA_W{1'b0}} && out_keep[p] === {BYTES{1'b0}} &&
               out_last[p] === 0 && out_tenant_id[p] === 96'b0 && out_destination[p] === 64'b0,
               $sformatf("port%0d invalid data and metadata pins expose no stale values", p));
        if (!result_valid[p])
            ck(result_tag[p] === 128'b0 && result_iv[p] === 96'b0 && result_error[p] === 4'b0,
               $sformatf("port%0d invalid result pins are zero", p));
    endtask
    task automatic erased(input int p);
        ck(engine_erased[p] && metadata_erased[p], $sformatf("port%0d private engine and metadata erased", p));
    endtask
    task automatic prep(input int vector_number);
        for (int p = 0; p < 3; p++) begin
            vv[p] = vector_number;
            fault[p] = 0;
            faultbit[p] = 0;
            framing[p] = 0;
            nonce_index[p] = 0;
        end
    endtask
    task automatic provision_record(input int vector_number, input int slot_number,
                                    input logic [63:0] counter);
        @(negedge clk);
        provision_slot = SLOT_W'(slot_number);
        provision_tenant_id = vt[vector_number];
        provision_key = vk[vector_number];
        provision_iv_fixed_field = vi[vector_number] >> 64;
        provision_counter_start = counter;
        provision_valid = 1;
        #1;
        ck(provision_ready && !provision_error, "trusted provisioning accepts idle unique key slot");
        @(posedge clk); #1;
        @(negedge clk);
        provision_valid = 0;
    endtask
    task automatic reset_cluster();
        @(negedge clk);
        reset = 1;
        clear = 0;
        cmd_valid = 0;
        in_valid = 0;
        out_ready = 0;
        result_ready = 0;
        provision_valid = 0;
        invalidate_valid = 0;
        #1;
        ck(cmd_ready == 0 && in_ready == 0 && out_valid == 0 && result_valid == 0,
            "reset immediately masks all handshakes");
        repeat (2) begin
            @(posedge clk); #1;
            for (int p = 0; p < 3; p++) begin
                quiet(p); erased(p);
                ck(ownership_erased[p], "reset clears ownership");
            end
            for (int s = 0; s < NUM_KEY_SLOTS; s++)
                ck(dut.keys.valid[s] === 0 && dut.keys.aes_key[s] === {AES_KEY_W{1'b0}} &&
                    dut.keys.tenant_id[s] === 96'b0 && dut.keys.invocation_counter[s] === 64'b0,
                    "reset erases all trusted key slots and counters");
        end
        @(negedge clk); reset = 0;
    endtask

    // faults 1 tag-bit, 2 ciphertext, 3 type-bit, 4 destination-bit, 5 IV-bit,
    // 6 authenticated-length mismatch, 7 alias tenant, 8 magic mismatch,
    // 9 wrong provisioned key, 10 unknown tag, 11 missing, 12 too long,
    // 13 injected duplicate, 14 exhausted. Framing 1 zero,2 hole,3 short keep,
    // 4 early last,5 missing last. Cancellation phases 1 setup,2 payload,
    // 3 output backpressure,4 held result,5 final payload before auth/release.
    task automatic set_command(input int p);
        int v;
        v = vv[p];
        cmd_tenant_id[p] = vt[v];
        cmd_record_type[p] = vr[v];
        cmd_destination[p] = vd[v];
        cmd_payload_bytes[p] = vl[v];
        cmd_iv[p] = p == 2 ? ~vi[v] : vi[v];
        cmd_expected_tag[p] = p == 2 ? ~vtag[v][0] : vtag[v][0];
        case (fault[p])
            1: cmd_expected_tag[p] = vtag[v][0] ^ (128'b1 << faultbit[p]);
            3: cmd_record_type[p] = vr[v] ^ (32'b1 << (faultbit[p] % 32));
            4: cmd_destination[p] = vd[v] ^ (64'b1 << faultbit[p]);
            5: cmd_iv[p] = vi[v] ^ (96'b1 << faultbit[p]);
            6: cmd_expected_tag[p] = bad_length_tag[v];
            7: cmd_tenant_id[p] = vt[v] ^ 96'b1;
            8: cmd_expected_tag[p] = bad_magic_tag[v];
            10: cmd_expected_tag[p] = 128'bx;
            11: cmd_tenant_id[p] = ~vt[v];
            12: cmd_payload_bytes[p] = faultbit[p] == 0 ? MAX_TXN_BYTES + 1 : 32'hffffffff;
        endcase
    endtask

    task automatic run_group(input logic [2:0] mask, input int cancel_port,
                             input int cancel_phase, input bit cancel_reset);
        int ipos [0:2], opos [0:2], steps, take, v, errors [0:2];
        int out_holds [0:2], result_holds [0:2];
        logic [2:0] done, input_fire, stalled_out, stalled_result;
        logic [2:0][MEM_DATA_W-1:0] prev_data;
        logic [2:0][BYTES-1:0] prev_keep;
        logic [2:0] prev_last;
        logic [2:0][127:0] prev_tag;
        logic [2:0][95:0] prev_iv, prev_tenant;
        logic [2:0][63:0] prev_destination;
        logic [2:0][3:0] prev_error;
        logic [MEM_DATA_W-1:0] word_value;
        logic [BYTES-1:0] keep_value;
        logic [7:0] wanted;
        bit did_cancel, cancel_now;
        steps = 0; did_cancel = 0;
        done = ~mask;
        stalled_out = 0; stalled_result = 0;
        for (int p = 0; p < 3; p++) begin
            ipos[p] = 0; opos[p] = 0; out_holds[p] = 0; result_holds[p] = 0;
            errors[p] = framing[p] != 0 ? 2 : fault[p] != 0 ? 1 : 0;
            case (fault[p])
                11: errors[p] = 4;
                12: errors[p] = 3;
                13: errors[p] = 5;
                14: errors[p] = 6;
            endcase
        end
        @(negedge clk);
        for (int p = 0; p < 3; p++) set_command(p);
        cmd_valid = mask;
        in_valid = 0; out_ready = 0; result_ready = 0;
        #1;
        ck((cmd_ready & mask) == mask, "all requested simultaneous commands ready on same idle edge");
        @(posedge clk); #1;
        ck((cmd_ready & mask) == 0, "accepted command reserves port");
        while (done != 3'b111) begin
            @(negedge clk);
            cmd_valid = 0;
            // Poison every command field after acceptance: data/provenance must
            // come from the captured command even if scheduler pins change.
            cmd_tenant_id = '1; cmd_record_type = '1; cmd_destination = '1;
            cmd_payload_bytes = '1; cmd_iv = '1; cmd_expected_tag = '1;
            for (int p = 0; p < 3; p++) begin
                if (out_valid[p]) out_holds[p]++;
                if (result_valid[p]) result_holds[p]++;
                out_ready[p] = !done[p] && out_holds[p] > (p+1)*5 && (random_word() % 4 != 0);
                result_ready[p] = !done[p] && result_holds[p] > (p+1)*4;
                if (!done[p] && !in_valid[p] && ipos[p] < vl[vv[p]] &&
                    errors[p] < 3 && !result_valid[p] && random_word() % 3 != 0) begin
                    v = vv[p];
                    take = vl[v]-ipos[p] < BYTES ? vl[v]-ipos[p] : BYTES;
                    word_value = '1;
                    for (int b = 0; b < take; b++) begin
                        if (p == 2) word_value[MEM_DATA_W-1-8*b -: 8] = vp[v][8*(vl[v]-1-ipos[p]-b) +: 8];
                        else word_value[MEM_DATA_W-1-8*b -: 8] = vc[v][0][8*(vl[v]-1-ipos[p]-b) +: 8];
                        if (fault[p] == 2 && ipos[p]+b == (faultbit[p] == 0 ? 0 : vl[v]-1))
                            word_value[MEM_DATA_W-1-8*b -: 8] ^= 8'h01;
                    end
                    keep_value = keep_for(take);
                    in_last[p] = ipos[p]+take == vl[v];
                    if (ipos[p] == 0) begin
                        if (framing[p] == 1) keep_value = 0;
                        if (framing[p] == 2) keep_value[BYTES-2] = 0;
                        if (framing[p] == 3) keep_value[BYTES-take] = 0;
                        if (framing[p] == 4) in_last[p] = 1;
                    end
                    if (framing[p] == 5 && in_last[p]) in_last[p] = 0;
                    in_data[p] = word_value; in_keep[p] = keep_value; in_valid[p] = 1;
                end
            end
            @(posedge clk);
            input_fire = in_ready & in_valid;
            for (int p = 0; p < 3; p++) begin
                quiet(p);
                if (!done[p]) begin
                    ck(!cmd_ready[p], "active port does not accept another command");
                    v = vv[p];
                    if (errors[p] >= 3) ck(!in_ready[p] && !out_valid[p], "local rejection consumes no stream data");
                    if (p != 2 && errors[p] != 0)
                        ck(!out_valid[p], "failed decrypt releases neither data nor trusted metadata");
                    if (p != 2 && out_valid[p])
                        ck(ipos[p] == vl[v], "plaintext quarantine holds until all input is authenticated");
                    if (stalled_out[p] && framing[p] == 0)
                        ck(out_valid[p] && out_data[p] === prev_data[p] && out_keep[p] === prev_keep[p] &&
                            out_last[p] === prev_last[p] && out_tenant_id[p] === prev_tenant[p] &&
                            out_destination[p] === prev_destination[p], "stalled output includes stable trusted provenance");
                    if (out_valid[p]) begin
                        ck(out_tenant_id[p] === vt[v] && out_destination[p] === vd[v], "output metadata is captured authenticated destination/tenant");
                        if (out_ready[p]) begin
                            ck(opos[p] < vl[v], "no duplicate or excess output bytes");
                            take = vl[v]-opos[p] < BYTES ? vl[v]-opos[p] : BYTES;
                            ck(out_keep[p] === keep_for(take) && out_last[p] === (opos[p]+take == vl[v]), "output keep/last follow exact authenticated length");
                            word_value = out_data[p];
                            for (int b = 0; b < BYTES; b++) begin
                                wanted = 0;
                                if (b < take) begin
                                    if (p == 2) wanted = vc[v][nonce_index[p]][8*(vl[v]-1-opos[p]-b) +: 8];
                                    else wanted = vp[v][8*(vl[v]-1-opos[p]-b) +: 8];
                                end
                                ck(word_value[MEM_DATA_W-1-8*b -: 8] === wanted,
                                    $sformatf("port%0d OpenSSL byte%0d expected%02h got%02h", p, opos[p]+b, wanted, word_value[MEM_DATA_W-1-8*b -: 8]));
                            end
                            opos[p] += take;
                        end
                    end
                    if (stalled_result[p])
                        ck(result_valid[p] && result_tag[p] === prev_tag[p] && result_iv[p] === prev_iv[p] && result_error[p] === prev_error[p], "held terminal result is stable");
                    if (result_valid[p]) begin
                        ck(result_error[p] === 4'(errors[p]), $sformatf("port%0d expected error%0d got%0d fault%0d framing%0d", p, errors[p], result_error[p], fault[p], framing[p]));
                        if (errors[p] == 0) ck(opos[p] == vl[v], "success follows consumption of every output byte");
                        if (p != 2 || errors[p] != 0)
                            ck(result_tag[p] === 128'b0 && result_iv[p] === 96'b0, "decrypt/error result exposes no tag or IV");
                        else
                            ck(result_tag[p] === vtag[v][nonce_index[p]] && result_iv[p] === vi[v]+96'(nonce_index[p]), "encryption uses independently predicted reserved nonce and tag");
                        ck(!out_valid[p], "terminal result follows output drain");
                        if (errors[p] < 3) ck(reported_busy[p], "busy slot protected through held result");
                        else ck(!reported_busy[p], "locally rejected command never takes key ownership");
                        erased(p);
                        if (result_ready[p]) begin
                            done[p] = 1; checked++;
                            if (errors[p] == 0) authenticated++; else rejected++;
                        end
                    end
                    if (input_fire[p]) ipos[p] += vl[v]-ipos[p] < BYTES ? vl[v]-ipos[p] : BYTES;
                end else begin
                    ck(!out_valid[p] && !result_valid[p], "idle/cancelled port cannot leak another port's response");
                end
            end
            stalled_out = out_valid & ~out_ready;
            stalled_result = result_valid & ~result_ready;
            prev_data = out_data; prev_keep = out_keep; prev_last = out_last;
            prev_tenant = out_tenant_id; prev_destination = out_destination;
            prev_tag = result_tag; prev_iv = result_iv; prev_error = result_error;
            steps++;
            ck(steps < 20000, "all independent ports make bounded progress");
            cancel_now = 0;
            if (cancel_port >= 0 && !did_cancel) begin
                cancel_now = (cancel_phase == 1 && steps == 2) ||
                    (cancel_phase == 2 && ipos[cancel_port] > 0 && ipos[cancel_port] < vl[vv[cancel_port]]) ||
                    (cancel_phase == 3 && out_valid[cancel_port] && out_holds[cancel_port] == 2) ||
                    (cancel_phase == 4 && result_valid[cancel_port] && result_holds[cancel_port] == 2) ||
                    (cancel_phase == 5 && ipos[cancel_port] == vl[vv[cancel_port]] && !out_valid[cancel_port]);
            end
            #1;
            in_valid &= ~input_fire;
            if (cancel_now) begin
                @(negedge clk);
                out_ready = 0; result_ready = 0;
                if (cancel_reset) reset = 1;
                else clear[cancel_port] = 1;
                in_valid[cancel_port] = 0;
                cmd_valid[cancel_port] = 0;
                #1;
                ck(!cmd_ready[cancel_port] && !in_ready[cancel_port] && !out_valid[cancel_port] && !result_valid[cancel_port], "clear/reset immediately suppresses cancelled handshakes");
                quiet(cancel_port);
                @(posedge clk);
                // Peers retain their valid/data through this extra clearing
                // edge. Account for their independent input handshakes too.
                input_fire = in_ready & in_valid;
                for (int peer = 0; peer < 3; peer++) begin
                    if (input_fire[peer])
                        ipos[peer] += vl[vv[peer]]-ipos[peer] < BYTES ? vl[vv[peer]]-ipos[peer] : BYTES;
                end
                #1;
                in_valid &= ~input_fire;
                if (cancel_reset) begin
                    for (int peer = 0; peer < 3; peer++) begin
                        erased(peer);
                        ck(ownership_erased[peer], "global reset erases every concurrent owner");
                    end
                end
                erased(cancel_port);
                ck(ownership_erased[cancel_port], "clear edge releases erased private key ownership");
                @(negedge clk);
                reset = 0; clear = 0;
                done[cancel_port] = 1; cancelled++; did_cancel = 1;
                if (cancel_reset) done = 3'b111;
                stalled_out[cancel_port] = 0; stalled_result[cancel_port] = 0;
            end
        end
        if (cancel_port >= 0) ck(did_cancel, "requested cancellation phase reached");
        @(negedge clk);
        cmd_valid = 0; in_valid = 0; out_ready = 0; result_ready = 0;
        @(posedge clk); #1;
        for (int p = 0; p < 3; p++) begin
            quiet(p); erased(p);
            ck(ownership_erased[p], "completed/cancelled command releases slot ownership");
        end
        groups++;
    endtask

    task automatic launch_without_payload(input logic [2:0] mask);
        @(negedge clk);
        for (int p = 0; p < 3; p++) set_command(p);
        cmd_valid = mask;
        #1; ck((cmd_ready & mask) == mask, "launch-only commands accepted together");
        @(posedge clk); #1;
        @(negedge clk); cmd_valid = 0;
    endtask

    task automatic busy_lifecycle();
        prep(0);
        launch_without_payload(3'b011);
        provision_slot = 0; provision_tenant_id = vt[0]; provision_key = ~vk[0];
        provision_iv_fixed_field = 32'h01234567; provision_counter_start = 0;
        provision_valid = 1; invalidate_slot = 0; invalidate_valid = 1;
        repeat (3) begin
            #1; ck(!provision_ready && provision_error && !invalidate_ready,
                "two active readers block trusted key replacement and invalidation");
            @(posedge clk); #1;
            ck(dut.keys.aes_key[0] === vk[0], "busy provisioning cannot change stored key");
            @(negedge clk);
        end
        clear[0] = 1;
        #1; ck(!invalidate_ready, "clear request retains ownership until erase edge");
        @(posedge clk); #1;
        erased(0);
        ck(!invalidate_ready && dut.keys.aes_key[0] === vk[0], "one of two readers clearing retains shared busy reference");
        @(negedge clk); clear = 0;
        clear[1] = 1;
        #1; ck(!invalidate_ready, "last reader protected before final clear edge");
        @(posedge clk); #1;
        erased(1);
        ck(invalidate_ready && dut.keys.valid[0], "last owner erase releases slot for next mutation edge");
        @(negedge clk); clear = 0;
        @(posedge clk); #1;
        ck(!dut.keys.valid[0] && dut.keys.aes_key[0] === {AES_KEY_W{1'b0}}, "invalidation wins same-slot provisioning and erases key");
        @(negedge clk); invalidate_valid = 0; provision_valid = 0;
        groups++;
    endtask

    task automatic writer_priority();
        prep(0);
        launch_without_payload(3'b001);
        set_command(1); set_command(2);
        cmd_valid = 3'b110;
        #1;
        ck(!cmd_ready[2] && !cmd_ready[1], "pending output blocks new same-key readers until existing readers drain");
        ck(dut.keys.invocation_counter[0] === 64'b0, "waiting encryption has not consumed a nonce");
        repeat (4) begin
            @(posedge clk); #1;
            ck(!cmd_ready[1] && !cmd_ready[2], "writer priority persists under stalled existing reader");
            @(negedge clk);
        end
        clear[0] = 1;
        #1; ck(!cmd_ready[2], "waiting output cannot reserve before old owner clear edge");
        @(posedge clk); #1;
        ck(cmd_ready[2] && cmd_ready[1], "once idle simultaneous new reader and writer can share capture edge");
        @(negedge clk); clear = 0;
        @(posedge clk); #1;
        ck(dut.keys.invocation_counter[0] === 64'd1 && !cmd_ready[1] && !cmd_ready[2], "reader and writer capture key with exactly one atomic IV reservation");
        @(negedge clk); cmd_valid = 0; clear = 3'b110;
        @(posedge clk); #1;
        for (int p = 0; p < 3; p++) erased(p);
        @(negedge clk); clear = 0;
        groups++;
    endtask

    task automatic cross_slot_arbitration();
        // Own nonzero slot1. An attempted mutation of that busy slot must
        // neither touch its key nor block a reader on independent slot0.
        provision_record(1, 1, 0);
        prep(0); vv[0] = 1;
        launch_without_payload(3'b001);
        provision_slot = 1; provision_tenant_id = vt[1]; provision_key = ~vk[1];
        provision_iv_fixed_field = vi[1] >> 64; provision_counter_start = 0;
        provision_valid = 1; invalidate_slot = 1; invalidate_valid = 1;
        vv[1] = 0; vv[2] = 1;
        set_command(1); set_command(2); cmd_valid = 3'b110;
        #1;
        ck(!provision_ready && provision_error && !invalidate_ready,
            "nonzero busy slot blocks its own mutation");
        ck(cmd_ready[1] && !cmd_ready[2],
            "rejected busy-slot update and pending writer do not block another-key reader");
        ck(dut.keys.invocation_counter[SECOND_SLOT] === 0 && dut.keys.invocation_counter[0] === 0,
            "waiting nonzero-slot writer consumes no nonce");
        @(posedge clk); #1;
        ck(dut.keys.aes_key[SECOND_SLOT] === vk[1], "rejected nonzero-slot write preserves captured key");
        @(negedge clk);
        cmd_valid[1] = 0; provision_valid = 0; invalidate_valid = 0;
        // Both independently owned slots must now reject invalidation.
        invalidate_slot = 0; invalidate_valid = 1;
        #1; ck(!invalidate_ready, "independent slot0 reader owns its actual slot");
        @(posedge clk); #1;
        @(negedge clk); invalidate_valid = 0;
        clear[0] = 1;
        #1; ck(!cmd_ready[2], "nonzero-slot writer waits through clearing edge");
        @(posedge clk); #1;
        ck(cmd_ready[2], "nonzero-slot writer advances even while other-key reader stays busy");
        @(negedge clk); clear = 0;
        @(posedge clk); #1;
        ck(dut.keys.invocation_counter[SECOND_SLOT] === 1 && dut.keys.invocation_counter[0] === 0,
            "nonzero-slot encryption reserves only the matching key counter");
        @(negedge clk); cmd_valid = 0;
        // An accepted mutation of a third idle slot must leave both captured
        // contexts intact, even while the independent streams are stalled.
        if (NUM_KEY_SLOTS > 2) begin
            provision_record(2, 2, 0);
            ck(dut.g_port[1].port_engine.engine.key_reg === vk[0],
                "accepted unrelated key provisioning preserves active reader key");
            @(negedge clk); invalidate_slot = 2; invalidate_valid = 1;
            #1; ck(invalidate_ready, "unowned third slot invalidates while peers are active");
            @(posedge clk); #1;
            ck(!dut.keys.valid[2] && reported_busy[1] && reported_busy[2],
                "accepted other-slot invalidation preserves both active owners");
            @(negedge clk); invalidate_valid = 0;
        end
        clear = 3'b110;
        @(posedge clk); #1;
        for (int p = 0; p < 3; p++) begin erased(p); ck(ownership_erased[p], "cross-slot ownership clears independently"); end
        @(negedge clk); clear = 0;
        groups++;
    endtask

    task automatic key_update_races();
        prep(0);
        @(negedge clk);
        for (int p = 0; p < 3; p++) set_command(p);
        cmd_valid = 3'b111;
        provision_valid = 1; provision_slot = 0;
        provision_tenant_id = vt[1]; provision_key = vk[1];
        provision_iv_fixed_field = vi[1] >> 64; provision_counter_start = 0;
        #1;
        ck(provision_ready && cmd_ready == 0, "accepted key update globally stalls new commands");
        @(posedge clk); #1;
        ck(dut.keys.aes_key[0] === vk[1] && (&ownership_erased), "mutation edge captures no stale lookup key");
        @(negedge clk); provision_valid = 0; cmd_valid = 0;
        prep(1); run_group(3'b111, -1, 0, 0);
        @(negedge clk);
        for (int p = 0; p < 3; p++) set_command(p);
        cmd_valid = 3'b111; invalidate_valid = 1; invalidate_slot = 0;
        #1;
        ck(invalidate_ready && cmd_ready == 0, "accepted invalidation stalls every new command");
        @(posedge clk); #1;
        ck(!dut.keys.valid[0] && (&ownership_erased), "invalidate edge captures no old key");
        @(negedge clk); invalidate_valid = 0; cmd_valid = 0;
        for (int p = 0; p < 3; p++) fault[p] = 11;
        run_group(3'b111, -1, 0, 0);
        groups++;
    endtask

    initial begin : campaign
        int stream, count, scanned, ignored;
        logic [63:0] saved_counter;
        logic [8*MAX_TXN_BYTES-1:0] cipher0, cipher1, cipher2;
        logic [127:0] tag0, tag1, tag2;
        ignored = $value$plusargs("tag_bits=%d", tag_bits);
        ignored = $value$plusargs("metadata_bits=%d", metadata_bits);
        ck($value$plusargs("vectors=%s", fixture_path), "requires independently generated +vectors fixture");
        stream = $fopen(fixture_path, "r");
        ck(stream != 0, "open oracle record fixture");
        scanned = $fscanf(stream, "%d\n", count);
        ck(scanned == 1 && count >= 3 && count < VECTORS, "fixture contains multibeat, empty, and one-byte records");
        for (int v = 0; v < count; v++) begin
            scanned = $fscanf(stream, "%h %h %h %h %h %d %h %h %h %h %h %h %h %h %h\n",
                vk[v], vt[v], vr[v], vd[v], vi[v], vl[v], vp[v],
                cipher0, tag0, cipher1, tag1, cipher2, tag2,
                bad_length_tag[v], bad_magic_tag[v]);
            ck(scanned == 15 && vl[v] <= MAX_TXN_BYTES, "fixture parses with bounded independent payload");
            vc[v][0] = cipher0; vc[v][1] = cipher1; vc[v][2] = cipher2;
            vtag[v][0] = tag0; vtag[v][1] = tag1; vtag[v][2] = tag2;
        end
        $fclose(stream);
        reset_cluster();
        // Each vector starts all three engines on one idle-slot edge. Only the
        // output port consumes a counter; both input ports use their record IV.
        for (int v = 0; v < count; v++) begin
            provision_record(v, 0, 0);
            prep(v); run_group(3'b111, -1, 0, 0);
            ck(dut.keys.invocation_counter[0] === 64'd1, "three same-key starts consume one nonce");
        end
        provision_record(0, 0, 0);
        prep(0);
        // Every tag bit is rejected on each decryption path in the intensive
        // configurations; representative mutations repeat across all bus widths.
        for (int b = 0; b < tag_bits; b++) begin
            fault[0] = 1; fault[1] = 1; faultbit[0] = b; faultbit[1] = b;
            run_group(3'b011, -1, 0, 0);
        end
        for (int b = 0; b < metadata_bits; b++) begin
            fault[0] = 3; fault[1] = 4; faultbit[0] = b; faultbit[1] = b;
            run_group(3'b011, -1, 0, 0);
        end
        for (int f = 2; f <= 10; f++) begin
            if (f != 7 && f != 9) begin
                prep(0); fault[0] = f; fault[1] = f;
                faultbit[0] = 0; faultbit[1] = f == 5 ? 95 : 63;
                run_group(3'b011, -1, 0, 0);
            end
        end
        // Distinct live tenant IDs may deliberately share the AES key provided
        // the fixed nonce fields differ. AAD must still separate the tenants.
        if (NUM_KEY_SLOTS > 1) begin
            @(negedge clk);
            provision_slot = 1; provision_tenant_id = vt[0] ^ 96'b1;
            provision_key = vk[0]; provision_iv_fixed_field = (vi[0] >> 64) ^ 32'b1;
            provision_counter_start = 0; provision_valid = 1;
            #1; ck(provision_ready, "alias tenant with same key but distinct nonce sequence is legal");
            @(posedge clk); #1;
            @(negedge clk); provision_valid = 0;
            prep(0); fault[0] = 7; fault[1] = 7;
            run_group(3'b011, -1, 0, 0);
            @(negedge clk); invalidate_valid = 1; invalidate_slot = 1;
            #1; ck(invalidate_ready, "alias key can retire after failed authentication");
            @(posedge clk); #1;
            @(negedge clk); invalidate_valid = 0;
        end
        // Replacing the key under the same tenant changes authentication.
        @(negedge clk);
        provision_valid = 1; provision_slot = 0; provision_tenant_id = vt[0];
        provision_key = ~vk[0]; provision_iv_fixed_field = vi[0] >> 64; provision_counter_start = 0;
        #1; ck(provision_ready, "idle tenant key replacement accepted");
        @(posedge clk); #1;
        @(negedge clk); provision_valid = 0;
        prep(0); fault[0] = 9; fault[1] = 9;
        run_group(3'b011, -1, 0, 0);
        provision_record(0, 0, 0);
        for (int f = 1; f <= 5; f++) begin
            prep(0); framing[0] = f; framing[1] = f;
            run_group(3'b011, -1, 0, 0);
            // Independent trials reset key state; encryption failures must still
            // consume the IV reserved by their accepted command.
            reset_cluster(); provision_record(0, 0, 0);
            prep(0); framing[2] = f;
            run_group(3'b100, -1, 0, 0);
            ck(dut.keys.invocation_counter[0] === 64'd1, "framing failure burns reserved encryption nonce");
        end
        for (int f = 11; f <= 12; f++) begin
            prep(0);
            saved_counter = dut.keys.invocation_counter[0];
            for (int p = 0; p < 3; p++) begin fault[p] = f; faultbit[p] = 0; end
            run_group(3'b111, -1, 0, 0);
            ck(dut.keys.invocation_counter[0] === saved_counter, "local command rejection does not reserve a nonce");
            if (f == 12) begin
                for (int p = 0; p < 3; p++) faultbit[p] = 1;
                run_group(3'b111, -1, 0, 0);
            end
        end
        // Cancellation independently aborts each port while its peers continue
        // and preserve their output/provenance and successful final tags.
        for (int p = 0; p < 3; p++) begin
            for (int phase = 1; phase <= 5; phase++) begin
                reset_cluster(); provision_record(0, 0, 0);
                prep(0); run_group(3'b111, p, phase, 0);
                ck(dut.keys.invocation_counter[0] === 64'd1, "clear never rolls back shared output nonce reservation");
                prep(0); nonce_index[2] = 1;
                run_group(3'b100, -1, 0, 0);
            end
        end
        // Reset during a live command cancels all contexts and requires newly
        // provisioned keys. Use a different key for the recovery transaction.
        for (int phase = 1; phase <= 5; phase++) begin
            reset_cluster(); provision_record(0, 0, 0);
            prep(0); run_group(3'b111, 2, phase, 1);
            for (int s = 0; s < NUM_KEY_SLOTS; s++) ck(!dut.keys.valid[s], "active reset invalidates every key");
            prep(0); for (int p = 0; p < 3; p++) fault[p] = 11;
            run_group(3'b111, -1, 0, 0);
            provision_record(1, 0, 0); prep(1); run_group(3'b111, -1, 0, 0);
        end
        reset_cluster(); provision_record(0, 0, 0);
        if (NUM_KEY_SLOTS > 1) begin
            cross_slot_arbitration();
            reset_cluster(); provision_record(0, 0, 0);
        end
        busy_lifecycle();
        provision_record(0, 0, 0);
        writer_priority();
        prep(0); nonce_index[2] = 1; run_group(3'b100, -1, 0, 0);
        key_update_races();
        // Conservatively reject all-ones, reserving the preceding final legal
        // counter once even if that transaction is cancelled immediately.
        provision_record(0, 0, 64'hfffffffffffffffe);
        prep(0); launch_without_payload(3'b100);
        ck(dut.keys.invocation_counter[0] === 64'hffffffffffffffff, "last legal nonce increments to exhausted sentinel");
        @(negedge clk); clear[2] = 1;
        @(posedge clk); #1;
        @(negedge clk); clear = 0;
        prep(0); fault[2] = 14; run_group(3'b100, -1, 0, 0);
        ck(dut.keys.invocation_counter[0] === 64'hffffffffffffffff, "exhaustion never wraps counter");
        prep(0); run_group(3'b011, -1, 0, 0);
        if (NUM_KEY_SLOTS > 1) begin
            // Fault injection bypasses trusted provisioning to emulate a
            // corrupted duplicate CAM entry. Normal writes reject duplicates.
            reset_cluster(); provision_record(0, 0, 0);
            @(negedge clk);
            dut.keys.valid[1] = 1;
            dut.keys.tenant_id[1] = vt[0];
            dut.keys.aes_key[1] = vk[0];
            dut.keys.iv_fixed[1] = 32'hfeedface;
            dut.keys.invocation_counter[1] = 0;
            prep(0); for (int p = 0; p < 3; p++) fault[p] = 13;
            run_group(3'b111, -1, 0, 0);
            ck(dut.keys.invocation_counter[0] === 0 && dut.keys.invocation_counter[1] === 0, "ambiguous lookup consumes no nonce");
            // Oversize rejects before duplicate CAM lookup.
            for (int p = 0; p < 3; p++) fault[p] = 12;
            run_group(3'b111, -1, 0, 0);
            reset_cluster();
        end
        if (NUM_KEY_SLOTS >= 3) begin
            provision_record(0, 0, 0); provision_record(1, 1, 0); provision_record(2, 2, 0);
            prep(0); vv[1] = 1; vv[2] = 2;
            run_group(3'b111, -1, 0, 0);
            ck(dut.keys.invocation_counter[0] === 0 && dut.keys.invocation_counter[1] === 0 && dut.keys.invocation_counter[2] === 1,
                "concurrent different keys isolate output nonce ownership");
        end
        reset_cluster();
        ck(authenticated > count*3 && rejected > 20 && cancelled == 20, "all oracle/error/cancel coverage completed");
        $display("PASS TENANT_GCM AES%0d bus%0d slots%0d: %0d checked transactions, %0d authenticated, %0d rejected, %0d cancellation scenarios, %0d groups, %0d OpenSSL records",
            AES_KEY_W, MEM_DATA_W, NUM_KEY_SLOTS, checked, authenticated, rejected, cancelled, groups, count);
        $finish;
    end
    initial begin
        #200000000;
        $fatal(1, "TENANT_GCM global watchdog expired");
    end
endmodule
