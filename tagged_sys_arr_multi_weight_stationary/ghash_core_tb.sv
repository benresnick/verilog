`timescale 1ns/1ps
// Official GHASH intermediates from NIST AES_GCM.pdf, AES-128 examples
// 1/2/3/5 and AES-256 example 5:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
// Random tests use polynomial convolution/reduction, independently of the
// RTL's reflected shift-right multiplication algorithm.
module ghash_core_tb #(
    parameter int MEM_DATA_W = 128
);
    localparam int LANES = MEM_DATA_W / 128;
    localparam int COUNT_W = (LANES <= 1) ? 1 : $clog2(LANES + 1);
    localparam logic [127:0] NIST_H = 128'hb83b533708bf535d0aa6e52980d53b78;
    logic clk = 0, reset = 1, clear = 0;
    logic start_valid = 0, in_valid = 0, in_last = 0, out_ready = 0;
    logic [127:0] hash_subkey = 0;
    logic [MEM_DATA_W-1:0] in_data = 0;
    logic [COUNT_W-1:0] in_blocks = 0;
    wire start_ready, in_ready, out_valid, protocol_error;
    wire [127:0] hash_out;
    logic [127:0] mul_x, mul_y;
    wire [127:0] mul_product;
    logic [127:0] message [0:16*LANES+15];
    logic [31:0] rng = 32'h67bd109a;
    int cycle = 0, checked = 0, stress_iters = 0;
    int seed = 32'h67bd109a;

    always #5 clk = ~clk;
    always @(posedge clk) cycle <= cycle + 1;
    ghash_core #(.MEM_DATA_W(MEM_DATA_W)) dut (.*);
    gf128_mul multiplier (.x(mul_x), .y(mul_y), .product(mul_product));

    task automatic ck(input logic condition, input string what);
        if (condition !== 1'b1) $fatal(1, "GHASH width=%0d seed=%0d: %s", MEM_DATA_W, seed, what);
    endtask

    function automatic [127:0] random_block();
        logic [127:0] value;
        for (int word_index = 0; word_index < 4; word_index++) begin
            rng = rng ^ (rng << 13);
            rng = rng ^ (rng >> 17);
            rng = rng ^ (rng << 5);
            value[word_index*32 +: 32] = rng;
        end
        return value;
    endfunction

    function automatic [127:0] reference_mul(input logic [127:0] a, b);
        logic [127:0] ar, br, result;
        logic [255:0] polynomial;
        for (int i = 0; i < 128; i++) begin
            ar[i] = a[127-i];
            br[i] = b[127-i];
        end
        polynomial = '0;
        for (int i = 0; i < 128; i++)
            if (ar[i]) polynomial = polynomial ^ ({128'b0, br} << i);
        for (int i = 254; i >= 128; i--)
            if (polynomial[i])
                polynomial = polynomial ^ (256'h100000000000000000000000000000087 << (i-128));
        for (int i = 0; i < 128; i++) result[i] = polynomial[127-i];
        return result;
    endfunction

    function automatic [127:0] reference_hash(input int count, input logic [127:0] h);
        logic [127:0] acc;
        acc = '0;
        for (int i = 0; i < count; i++) acc = reference_mul(acc ^ message[i], h);
        return acc;
    endfunction

    task automatic begin_message(input logic [127:0] h);
        @(negedge clk);
        start_valid = 1;
        hash_subkey = h;
        #1;
        ck(start_ready, "start handshake");
        @(posedge clk); #1;
        ck(in_ready && !out_valid, "active after start");
        @(negedge clk);
        start_valid = 0;
        hash_subkey = ~h; // The engine must use its captured subkey.
    endtask

    task automatic check_erased();
        ck(dut.h_reg === 128'b0 && dut.accumulator === 128'b0,
           "working hash state zeroized");
    endtask

    task automatic run_message(input int count, input logic [127:0] h,
                               input logic [127:0] expected, input bit bubbles);
        int position, take, beats, previous_cycle;
        logic [31:0] packing_random;
        begin_message(h);
        position = 0;
        beats = 0;
        previous_cycle = -1;
        while (position < count) begin
            @(negedge clk);
            if (bubbles && (beats % 2 == 0)) begin
                in_valid = 0;
                @(posedge clk); #1;
                ck(!out_valid && !protocol_error, "input bubble preserves transaction");
                @(negedge clk);
            end
            take = ((count-position) < LANES) ? (count-position) : LANES;
            if (bubbles && stress_iters > 0) begin
                packing_random = random_block();
                take = 1 + (packing_random % take);
            end
            in_data = '1; // Unused trailing lanes must be ignored, not hashed.
            for (int lane = 0; lane < take; lane++)
                in_data[MEM_DATA_W-1-128*lane -: 128] = message[position+lane];
            in_blocks = COUNT_W'(take);
            in_last = (position + take == count);
            in_valid = 1;
            #1;
            ck(in_ready, "one beat per cycle while active");
            @(posedge clk); #1;
            if (!bubbles && previous_cycle >= 0)
                ck(cycle == previous_cycle + 1, "continuous input has no bubbles");
            previous_cycle = cycle;
            position += take;
            beats++;
            ck(!protocol_error, "legal block count accepted");
            ck(out_valid == (position == count), "result only after final beat");
        end
        ck(hash_out === expected, "hash matches independent expected value");
        check_erased();
        @(negedge clk);
        in_valid = 0;
        start_valid = 1;
        for (int stall = 0; stall < 4; stall++) begin
            in_data = ~in_data;
            @(posedge clk); #1;
            ck(out_valid && hash_out === expected, "result stable during output stall");
            ck(!start_ready && !in_ready, "blocked result cannot be overwritten");
            @(negedge clk);
        end
        start_valid = 0;
        out_ready = 1;
        @(posedge clk); #1;
        ck(!out_valid && hash_out === 128'b0 && dut.result_reg === 128'b0,
           "result consumed and zeroized");
        @(negedge clk);
        out_ready = 0;
        checked++;
        if (count == 12*LANES)
            $display("GHASH width=%0d sustained input: %0d beats in %0d cycles", MEM_DATA_W, beats, beats);
    endtask

    task automatic bad_count(input logic [COUNT_W-1:0] count);
        begin_message(NIST_H);
        in_valid = 1;
        in_last = 1;
        in_blocks = count;
        @(posedge clk); #1;
        ck(protocol_error && !out_valid && !in_ready, "invalid count aborts without result");
        check_erased();
        @(negedge clk);
        in_valid = 0;
        @(posedge clk); #1;
        ck(!protocol_error && start_ready, "fault pulse clears and engine recovers");
    endtask

    task automatic check_turnover();
        logic [127:0] expected;
        // Multiplication by field identity makes lane inclusion observable.
        begin_message(128'h80000000000000000000000000000000);
        in_valid = 1;
        in_last = 0;
        in_blocks = 1;
        in_data = '1;
        in_data[MEM_DATA_W-1 -: 128] = 128'h12;
        @(posedge clk); #1;
        ck(dut.accumulator === 128'h12 && !out_valid,
           "partial nonfinal beat ignores unused lanes");
        @(negedge clk);
        in_last = 1;
        in_data[MEM_DATA_W-1 -: 128] = 128'h345;
        expected = 128'h12 ^ 128'h345;
        if (LANES > 1) begin
            in_blocks = 2;
            in_data[MEM_DATA_W-129 -: 128] = 128'h678;
            expected = expected ^ 128'h678;
        end
        @(posedge clk); #1;
        ck(out_valid && hash_out === expected, "partial beats form one ordered message");
        @(negedge clk);
        start_valid = 1;
        hash_subkey = 0;
        in_blocks = 1;
        in_data = '1;
        #1;
        ck(!start_ready && !in_ready, "next start and data wait for stalled result");
        @(posedge clk); #1;
        ck(out_valid && hash_out === expected, "waiting requests preserve old result");
        @(negedge clk); out_ready = 1;
        #1;
        ck(start_ready && !in_ready && out_valid, "old output and new start share an edge");
        @(posedge clk); #1;
        ck(in_ready && !out_valid && dut.result_reg === 128'b0,
           "new transaction starts without accepting premature data");
        check_erased(); // New subkey is zero; old state must be gone.
        @(negedge clk);
        start_valid = 0;
        hash_subkey = '1;
        @(posedge clk); #1;
        ck(out_valid && hash_out === 128'b0 && !protocol_error,
           "held data uses newly captured subkey");
        @(negedge clk); in_valid = 0;
        @(posedge clk); #1;
        ck(!out_valid && dut.result_reg === 128'b0, "turnover result consumed and erased");
        check_erased();
        @(negedge clk); out_ready = 0;
    endtask

    initial begin : test
        logic [127:0] h, expected;
        int count;
        if ($value$plusargs("stress_iters=%d", stress_iters)) begin end
        if ($value$plusargs("seed=%d", seed)) begin end
        rng = seed;
        ck(seed != 0 && stress_iters >= 0, "valid stress controls");
        repeat (2) @(posedge clk);
        @(negedge clk); reset = 0;
        // Field identities and randomized product oracle.
        for (int i = 0; i < 66; i++) begin
            mul_x = random_block();
            mul_y = (i == 0) ? 128'b0 : (i == 1) ? 128'h80000000000000000000000000000000 : random_block();
            #1;
            ck(mul_product === reference_mul(mul_x, mul_y), "field multiplication oracle");
        end

        // Empty AAD/ciphertext still contributes a zero length block.
        message[0] = 0;
        run_message(1, NIST_H, 128'b0, 0);
        message[0] = 128'h42831ec2217774244b7221b784d0d49c;
        message[1] = 128'he3aa212f2c02a4e035c17e2329aca12e;
        message[2] = 128'h21d514b25466931c7d8f6a5aac84aa05;
        message[3] = 128'h1ba30b396a0aac973d58e091473f5985;
        message[4] = {64'd0, 64'd512};
        run_message(5, NIST_H, 128'h7f1b32b81b820d02614f8895ac1d4eac, 0);
        message[0] = 128'h3ad77bb40d7a3660a89ecaf32466ef97;
        message[1] = 128'hf5d3d58503b9699de785895a96fdbaaf;
        message[2] = 128'h43b1cd7f598ece23881b00e3ed030688;
        message[3] = 128'h7b0c785e27e8ad3f8223207104725dd4;
        message[4] = {64'd512, 64'd0};
        run_message(5, NIST_H, 128'h6dd6cf3a1fa0371dd4c5c1ac1c3675f1, 1);

        // Twenty-byte AAD and sixty-byte ciphertext, separately zero padded.
        message[1] = 128'hf5d3d585000000000000000000000000;
        message[2] = 128'h42831ec2217774244b7221b784d0d49c;
        message[3] = 128'he3aa212f2c02a4e035c17e2329aca12e;
        message[4] = 128'h21d514b25466931c7d8f6a5aac84aa05;
        message[5] = 128'h1ba30b396a0aac973d58e09100000000;
        message[6] = {64'd160, 64'd480};
        run_message(7, NIST_H, 128'hc23b3d63d2ed95056ca342769cd13c03, 1);
        message[2] = 128'h522dc1f099567d07f47f37a32a84427d;
        message[3] = 128'h643a8cdcbfe5c0c97598a2bd2555d1aa;
        message[4] = 128'h8cb08e48590dbb3da7b08b1056828838;
        message[5] = 128'hc5f61e6393ba7a0abcc9f66200000000;
        run_message(7, 128'hacbef20579b4b8ebce889bac8732dad7,
                    128'h1dbbb349e0b1f4fff5aa3bb1f6b2b0de, 0);

        for (int iteration = 0; iteration < 12; iteration++) begin
            count = 1 + ((iteration*17 + LANES) % (3*LANES+5));
            h = random_block();
            for (int i = 0; i < count; i++) message[i] = random_block();
            expected = reference_hash(count, h);
            run_message(count, h, expected, iteration % 2);
        end
        for (int i = 0; i < 12*LANES; i++) message[i] = random_block();
        h = random_block();
        run_message(12*LANES, h, reference_hash(12*LANES, h), 0);
        run_message(12*LANES, 128'b0, 128'b0, 0);

        check_turnover();

        if (stress_iters > 0) begin
            // Every legal final-lane count; random segmentation on intermediate
            // beats covers padding boundaries independent of physical width.
            for(int tail_count=1;tail_count<=LANES;tail_count++) begin
                for(int i=0;i<tail_count;i++) message[i]=random_block();
                h=random_block();
                run_message(tail_count,h,reference_hash(tail_count,h),0);
            end
            for(int i=0;i<stress_iters;i++) begin
                h=random_block();
                count=1+(rng % (3*LANES+5));
                for(int b=0;b<count;b++) message[b]=random_block();
                run_message(count,h,reference_hash(count,h),1);
            end
            for(int count_value=LANES+1;count_value<2**COUNT_W;count_value++)
                bad_count(COUNT_W'(count_value));
        end

        bad_count('0);
        if (LANES > 1 && (2**COUNT_W-1) > LANES) bad_count(COUNT_W'(LANES+1));

        // Clear/reset must erase both active and stalled-result state.
        for (int kind = 0; kind < 4; kind++) begin
            begin_message(NIST_H);
            in_valid = 1;
            in_blocks = 1;
            in_data = '1;
            in_last = kind[0];
            @(posedge clk); #1;
            @(negedge clk);
            in_valid = 0;
            if (kind < 2) clear = 1; else reset = 1;
            #1;
            ck(!in_ready && !start_ready && !out_valid && hash_out === 128'b0,
               "reset/clear gates handshakes and result immediately");
            @(posedge clk); #1;
            check_erased();
            ck(dut.result_reg === 128'b0 && !protocol_error, "reset/clear erases pending result");
            @(negedge clk); clear = 0; reset = 0;
        end
        message[0] = 0;
        run_message(1, NIST_H, 0, 0);
        $display("PASS: GHASH width=%0d, %0d messages, NIST vectors, field oracle, stalls, faults, zeroization", MEM_DATA_W, checked);
        $finish;
    end

    initial begin
        #1000000;
        $fatal(1, "GHASH test timeout");
    end
endmodule
