`timescale 1ns/1ps
// Independent keystream oracle generated with OpenSSL AES-ECB. The fixed
// counter sequence crosses inc32 wrap after 16 blocks. To reproduce a block:
// printf 00112233445566778899aabbfffffff0 | xxd -r -p |
// openssl enc -aes-128-ecb -K 2b7e151628aed2a6abf7158809cf4f3c -nopad -nosalt
module gctr_core_tb #(
    parameter int AES_KEY_W = 256,
    parameter int MEM_DATA_W = 128
);
    localparam int BYTES = MEM_DATA_W / 8;
    localparam int LANES = MEM_DATA_W / 128;
    localparam int ROUNDS = AES_KEY_W == 128 ? 10 : 14;
    localparam int LONG_BEATS = (128 / LANES < 24) ? 128 / LANES : 24;
    localparam logic [127:0] COUNTER = 128'h00112233445566778899aabbfffffff0;
    localparam logic [AES_KEY_W-1:0] KEY = AES_KEY_W == 128 ?
        AES_KEY_W'(128'h2b7e151628aed2a6abf7158809cf4f3c) :
        AES_KEY_W'(256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4);
    logic clk = 0, reset = 1, clear = 0;
    logic start_valid = 0, in_valid = 0, in_last = 0, out_ready = 0;
    logic [AES_KEY_W-1:0] key_in = 0;
    logic [127:0] initial_counter = 0;
    logic [MEM_DATA_W-1:0] in_data = 0;
    logic [BYTES-1:0] in_keep = 0;
    wire start_ready, in_ready, out_valid, out_last, protocol_error;
    wire [MEM_DATA_W-1:0] out_data;
    wire [BYTES-1:0] out_keep;
    logic [127:0] stream [0:127];
    logic [MEM_DATA_W-1:0] payload [0:127], expected [0:127];
    logic [BYTES-1:0] keeps [0:127];
    wire [LANES-1:0] lane_erased;
    logic [31:0] rng = 32'h950b812a;
    int checked = 0;

    always #5 clk = ~clk;
    gctr_core #(.AES_KEY_W(AES_KEY_W), .MEM_DATA_W(MEM_DATA_W)) dut (.*);
    generate
        for (genvar lane = 0; lane < LANES; lane++) begin : g_zero
            wire [ROUNDS:0] state_zero;
            wire [ROUNDS-1:0] key_zero;
            for (genvar stage = 0; stage <= ROUNDS; stage++) begin : g_s
                assign state_zero[stage] = dut.g_lane[lane].aes.state_pipe[stage] == 0;
            end
            for (genvar stage = 0; stage < ROUNDS; stage++) begin : g_k
                assign key_zero[stage] = dut.g_lane[lane].aes.key_pipe[stage] == 0;
            end
            assign lane_erased[lane] = (&state_zero) && (&key_zero) &&
                dut.g_lane[lane].aes.valid_pipe == 0;
        end
    endgenerate

    task automatic ck(input logic condition, input string what);
        if (condition !== 1'b1)
            $fatal(1, "GCTR AES=%0d width=%0d: %s", AES_KEY_W, MEM_DATA_W, what);
    endtask

    function automatic [31:0] random_word();
        rng = rng ^ (rng << 13);
        rng = rng ^ (rng >> 17);
        rng = rng ^ (rng << 5);
        return rng;
    endfunction

    task automatic erased();
        ck(dut.key_reg == 0 && dut.counter_reg == 0 && dut.blocks_used == 0,
           "transaction secrets erased");
        ck(dut.valid_pipe == 0 && dut.last_pipe == 0 && (&lane_erased),
           "AES pipeline fully erased");
        for (int i = 0; i <= ROUNDS; i++)
            ck(dut.data_pipe[i] == 0 && dut.keep_pipe[i] == 0, "payload pipeline erased");
        ck(!out_valid && out_data == 0 && out_keep == 0 && !out_last, "inactive outputs zero");
    endtask

    task automatic begin_message();
        @(negedge clk);
        start_valid = 1;
        key_in = KEY;
        initial_counter = COUNTER;
        #1; ck(start_ready, "idle accepts start");
        @(posedge clk); #1;
        ck(in_ready && !start_ready, "start enters active state");
        @(negedge clk);
        start_valid = 0;
        key_in = ~KEY;
        initial_counter = ~COUNTER;
    endtask

    task automatic run_message(input int beats, input int final_bytes,
                               input bit bubbles, input bit stalls);
        int sent, got, elapsed, previous_input, previous_output, bytes_this;
        bit pending, held;
        logic [MEM_DATA_W-1:0] held_data;
        logic [BYTES-1:0] held_keep;
        logic held_last;
        for (int beat = 0; beat < beats; beat++) begin
            for (int word_index = 0; word_index < MEM_DATA_W/32; word_index++)
                payload[beat][32*word_index +: 32] = random_word();
            bytes_this = beat == beats-1 ? final_bytes : BYTES;
            keeps[beat] = '0;
            expected[beat] = '0;
            for (int byte_index = 0; byte_index < bytes_this; byte_index++) begin
                keeps[beat][BYTES-1-byte_index] = 1;
                expected[beat][MEM_DATA_W-1-8*byte_index -: 8] =
                    payload[beat][MEM_DATA_W-1-8*byte_index -: 8] ^
                    stream[beat*LANES+byte_index/16][127-8*(byte_index%16) -: 8];
            end
        end
        begin_message();
        sent = 0; got = 0; elapsed = 0;
        pending = 0; held = 0;
        previous_input = -1; previous_output = -1;
        while (got < beats && elapsed < 3000) begin
            // begin_message exits on a falling edge; all later iterations do too.
            start_valid = 1; // An overlapping start must not replace the key/counter.
            out_ready = !stalls || (elapsed > ROUNDS+6 && random_word()%4 != 0);
            if (!pending && sent < beats && (!bubbles || random_word()%3 != 0)) begin
                in_valid = 1;
                in_data = payload[sent];
                in_keep = keeps[sent];
                in_last = sent == beats-1;
                pending = 1;
            end
            if (!pending) in_valid = 0;
            #1;
            ck(!protocol_error && !start_ready, "active transfer has no protocol error");
            if (held)
                ck(out_valid && out_data === held_data && out_keep === held_keep && out_last === held_last,
                   "blocked output is stable");
            held = out_valid && !out_ready;
            held_data = out_data; held_keep = out_keep; held_last = out_last;
            if (out_valid && !out_ready) ck(!in_ready, "output backpressure freezes input");
            if (in_valid && in_ready) begin
                if (!bubbles && !stalls && previous_input >= 0)
                    ck(elapsed == previous_input+1, "one input beat per cycle");
                previous_input = elapsed;
                sent++; pending = 0;
            end
            if (out_valid && out_ready) begin
                ck(out_data === expected[got], $sformatf("independent ciphertext beat %0d", got));
                ck(out_keep === keeps[got] && out_last == (got == beats-1), "keep/last alignment");
                if (!bubbles && !stalls && got == 0)
                    ck(elapsed == ROUNDS+1, "AES latency includes input and round registers");
                if (!bubbles && !stalls && previous_output >= 0)
                    ck(elapsed == previous_output+1, "one output beat per cycle");
                previous_output = elapsed;
                got++;
            end
            @(posedge clk); #1;
            if (sent == beats) ck(dut.key_reg == 0 && !in_ready, "key erased at final input");
            elapsed++;
            @(negedge clk);
        end
        ck(got == beats, "bounded completion");
        in_valid = 0; out_ready = 0; in_last = 0; start_valid = 0;
        #1; ck(start_ready, "idle after final output");
        erased(); checked++;
    endtask

    task automatic abort_message(input int kind);
        begin_message();
        in_valid = 1; in_data = '1; in_keep = '1; in_last = 0;
        @(posedge clk); #1;
        @(negedge clk);
        if (kind == 0) in_keep = '0;
        if (kind == 1) begin in_last = 1; in_keep = '1; in_keep[BYTES-2] = 0; end
        if (kind == 2) begin in_keep = '1; in_keep[0] = 0; end
        if (kind == 3) begin
            // Deposit a near-exhausted count; no force remains over the abort edge.
            dut.blocks_used = 33'h0fffffffe;
        end
        if (kind == 4) clear = 1;
        if (kind == 5) reset = 1;
        #1;
        ck(!out_valid && out_data == 0, "aborted output masked immediately");
        if (kind >= 4) ck(!in_ready && !start_ready, "clear/reset immediately mask handshakes");
        @(posedge clk); #1;
        ck(protocol_error == (kind < 4), "abort/error pulse classification");
        erased();
        @(negedge clk);
        in_valid = 0; reset = 0; clear = 0;
        @(posedge clk); #1;
        ck(start_ready && !protocol_error, "aborted transaction can restart");
        checked++;
    endtask

    task automatic abort_stalled_output(input int kind);
        begin_message();
        in_valid = 1; in_data = '0; in_keep = '1; in_last = 0;
        @(posedge clk); #1;
        @(negedge clk); in_valid = 0;
        while (!out_valid) begin @(posedge clk); #1; end
        ck(out_data[MEM_DATA_W-1 -: 128] === stream[0], "pending ciphertext before abort");
        repeat (3) begin
            @(posedge clk); #1;
            ck(out_valid && !in_ready, "pending output remains blocked");
        end
        @(negedge clk);
        if (kind == 0) clear = 1;
        if (kind == 1) reset = 1;
        if (kind >= 2) begin
            out_ready = kind == 2;
            in_valid = 1;
            in_last = 1;
            in_keep = '0;
        end
        #1;
        ck(!out_valid && out_data == 0 && out_keep == 0 && !out_last,
           "abort masks already valid output before edge");
        @(posedge clk); #1;
        erased();
        ck(protocol_error == (kind >= 2), "stalled abort error pulse");
        @(negedge clk);
        reset = 0; clear = 0; in_valid = 0; out_ready = 0;
        @(posedge clk); #1;
        ck(start_ready && !protocol_error, "stalled abort returns idle");
        checked++;
    endtask

    task automatic limit_boundary(input bit full_beat);
        begin_message();
        dut.blocks_used = 33'h0fffffffe - (full_beat ? 33'(LANES) : 33'd1);
        in_valid = 1; in_last = 1; in_keep = '0;
        in_keep[BYTES-1 -: 8] = '1;
        if (full_beat) in_keep = '1;
        in_data = '0;
        @(posedge clk); #1;
        ck(!protocol_error && dut.key_reg == 0, "exact maximum partial final block allowed");
        @(negedge clk); in_valid = 0;
        while (!out_valid) begin @(posedge clk); #1; end
        ck(out_data[MEM_DATA_W-1 -: 64] === stream[0][127:64], "limit case ciphertext");
        if (full_beat)
            for (int lane = 0; lane < LANES; lane++)
                ck(out_data[MEM_DATA_W-1-128*lane -: 128] === stream[lane], "limit case full lane");
        @(negedge clk); out_ready = 1;
        @(posedge clk); #1;
        erased();
        @(negedge clk); out_ready = 0;
        checked++;
    endtask

    initial begin
        if (AES_KEY_W == 128) begin
            stream[0] = 128'h74465289db787c2d49848913f27859c9;
            stream[1] = 128'h211fc05ed54335c376b4b02613031df1;
            stream[2] = 128'h56509b25188cde2d28c977e544e21ce0;
            stream[3] = 128'h82fe5da0afe661d7822bfe25d377642e;
            stream[4] = 128'hf71806cfffc7148f9dc20ababbbd302e;
            stream[5] = 128'ha7c84d6ca11f9c7cc43b6d1bf703d25a;
            stream[6] = 128'h92592e4c2b9b37faded9180cc9ee9019;
            stream[7] = 128'h455ea0491ea8a35948241ddeceb6595d;
            stream[8] = 128'h17c9dc60fe291ebf37a336922b8d85bb;
            stream[9] = 128'hd7ac63a9e512180fdd3b7ce81472689e;
            stream[10] = 128'hf00bd5d0d27a7d08ff20f3c81f0b6bac;
            stream[11] = 128'h3615740a1dc9c96267f2383f11aaa549;
            stream[12] = 128'he7aaac5e31b6b701e83c2d00f84bde87;
            stream[13] = 128'he5f95faa8717637770d40a770e8dee0b;
            stream[14] = 128'h57801429e49fd9b7d80971833034d6e3;
            stream[15] = 128'h8a67e52d71e5a8b5639095f4b2c3b877;
            stream[16] = 128'h689604478803963dac182085e573d637;
            stream[17] = 128'h4e562aa1f4860da96fd7a6138303bbdf;
            stream[18] = 128'h4805522c76ed03b74d52e527616c2f33;
            stream[19] = 128'h09c000da0aabb480eaa231d4c5d1b600;
            stream[20] = 128'h690ab0c8a00a4f1d955f2bb9dddade86;
            stream[21] = 128'h4fa2270214b18432fc91f6ece1aeb074;
            stream[22] = 128'he8ba994ac100e433a2b05e3b899aa9cb;
            stream[23] = 128'h4d9bcedab79fd456b5dd88c30a4efa25;
            stream[24] = 128'h7d86ec52c625a52ee8602a2eb5afa250;
            stream[25] = 128'h35389d93c3fb8d0d840034cd0a4469d7;
            stream[26] = 128'h7e57a7246d1f13dd25769fc737568981;
            stream[27] = 128'h76fe519dc081a412c4d53f63980e715b;
            stream[28] = 128'h6b962f51c94e44d0c30570aeff90b1a6;
            stream[29] = 128'he4a2b196a2e02e605a0dee588b4275c7;
            stream[30] = 128'hf02c671c082f493bb60600300ddc5bd8;
            stream[31] = 128'hef3392b7f1ccaffb350fd11048bde66d;
            stream[32] = 128'h681d49c1926b5bb751ecf7b9beb88c6e;
            stream[33] = 128'hb843ccbe498b5308b547ff4b97f14a9e;
            stream[34] = 128'hc4dda44458a9c57d21b10ac84442c402;
            stream[35] = 128'h027f3089e85efc818ea56e882b3d64a5;
            stream[36] = 128'h3a7e159ad1935a74f69ae89a5ce1a0d7;
            stream[37] = 128'hc00264b3fea31ffcb157cd6c032b6dad;
            stream[38] = 128'h8749e5f81a19e60899b65b955213c1f9;
            stream[39] = 128'h9cdeff4fd2d60f1b0215778f0c628296;
            stream[40] = 128'h610c3f20ecc62bdb35456fe169a0c362;
            stream[41] = 128'hbbd226d9230d97fa63976938955967c4;
            stream[42] = 128'h4c60a7aad5083bed23e2f5b60c78709c;
            stream[43] = 128'h30460aa5d9ff2d4bcc22dd8ad52af8db;
            stream[44] = 128'hf1ff345684163069bd7aca9aef7e2074;
            stream[45] = 128'h68f4ac5f293c8d19ea649f077d762ed1;
            stream[46] = 128'h1d83c5235fb1e399603ec3569bd29368;
            stream[47] = 128'h281d5d0e4e5e20a8f69b6e7732d5ab54;
            stream[48] = 128'hcde95c09d71a1f09d313d899d508cf8c;
            stream[49] = 128'h631c742aac034073627993f8d5d5ab92;
            stream[50] = 128'h41b0e561666d9e65f52ffb70aaaf2936;
            stream[51] = 128'hf5c5124e7a1a4e8a8b5cb289249133f3;
            stream[52] = 128'h6aae0fe18ded1fc2678ab9d85c105c2e;
            stream[53] = 128'h42ce8803d87e53ca5d8e87875702ef95;
            stream[54] = 128'hec655db0571a41b1c1270fe5836ad879;
            stream[55] = 128'h6e802acd5d4476d01222b2dd898bca11;
            stream[56] = 128'hd9ce3ff66762f51a9098369854b7d191;
            stream[57] = 128'hd89ccec8190e893adfca3b570f9a9451;
            stream[58] = 128'hc068d859e3883f1526c3796fac0826f2;
            stream[59] = 128'hc2f7fdba889732629658f513374ea98d;
            stream[60] = 128'h1ddc409bd788b8b25393b5cbad96e4ef;
            stream[61] = 128'h2333d540b053f475c387aabc528067c2;
            stream[62] = 128'hf2cff855ba7c3fb7278330b4302b1ec1;
            stream[63] = 128'h4abe7801bac0c82f16517ebf772e8bc4;
            stream[64] = 128'hee33462d1aa5c07a7d5bd5ab640c606b;
            stream[65] = 128'h4382044e17ebffd7d823ae175028c49f;
            stream[66] = 128'he45c1efa889668e5547da3530ee8a069;
            stream[67] = 128'hc54c6265cc7f59357485eb56677c446f;
            stream[68] = 128'ha58c0f07ecac1a445ee1b6d663e73746;
            stream[69] = 128'h1b35b8e4581f268b996f2aa003668687;
            stream[70] = 128'hbc5970ef222171923abef61c7af612e1;
            stream[71] = 128'h8ed46d6cd3bacdd21f8b18021d6e33de;
            stream[72] = 128'h389d06ba0ae9ab9b0a46a1bebae05d3f;
            stream[73] = 128'hc3a315d4526da5bbcdc1214756e34712;
            stream[74] = 128'h8bc0318acacf2dd05b28d575cfcefca6;
            stream[75] = 128'h29f695059024aa5789043ac211905e63;
            stream[76] = 128'hae27bcf5374383233190444ad7ac6b13;
            stream[77] = 128'h27a554e59081637a39623e8c2a4759f3;
            stream[78] = 128'hbc095fd10b89b26f2d382ca69e7e4157;
            stream[79] = 128'h46b28245481cf018c9d3d5d240cd2542;
            stream[80] = 128'hc89ef9f170c24dc7024df3a25224c586;
            stream[81] = 128'h419a88afd6fdef9c0a36426a81711b84;
            stream[82] = 128'h78099a520005fb8d23cf58cdabe4ee61;
            stream[83] = 128'h720d4d52364c54a2e63f5d6b826c2e6e;
            stream[84] = 128'h244d6bdf4b1af5b23767c1f1d1cef472;
            stream[85] = 128'h4597a698e256e6116773a92f78b29bf6;
            stream[86] = 128'hf2f1eee044a5ea6c9a5c988b862fb14c;
            stream[87] = 128'h36862a8e898415915156d8f1f17882ac;
            stream[88] = 128'h568c8bb6472b0e660da64e41070c5b41;
            stream[89] = 128'ha4b5693ead8804eecb146603e11a0b6b;
            stream[90] = 128'h879c072bae81bc867a3415faf1e8c2ab;
            stream[91] = 128'hf67a5b15f662eee2684d95d6c0809b8e;
            stream[92] = 128'h2af3f06c3a195e3fcccba7aba14554ec;
            stream[93] = 128'h01f7381e66a0f3aaff222ac3ac28df63;
            stream[94] = 128'h2b63d81ef4f25a1071417cf0c40cc780;
            stream[95] = 128'h925524ef91f2959dff359fb56f1ba877;
            stream[96] = 128'h2324fd3a024683077408fa2ad2441b97;
            stream[97] = 128'he8328e416af4fdbbef585287ed0aa822;
            stream[98] = 128'h1c804e4a9b4116c8d531144b13316419;
            stream[99] = 128'h6a1dba7957d9b620b8d4238598e54ec8;
            stream[100] = 128'h37687432cd214116ce67e4e1bb704b3b;
            stream[101] = 128'h49b088266b05910f111c2328bf92a7ef;
            stream[102] = 128'h5b9fc174be2e9f16a3b15c9309767917;
            stream[103] = 128'h5f6ce5549296920373a5fb6939dbe6a0;
            stream[104] = 128'hb81b8fa07f3e0096ddd1aaf86028ff19;
            stream[105] = 128'h0bbdddfde30ce0cb6f161c59ed37b8f0;
            stream[106] = 128'h82113f605a5f67a6a8edcb93ce30dbe9;
            stream[107] = 128'hcecbe878908297dd8eb971d62e38c4ef;
            stream[108] = 128'h51e85421a2d889222d4aee456427b54f;
            stream[109] = 128'h5a13058bb843d57274a790e2633bb7c7;
            stream[110] = 128'hfdf3ec3770d26541d52ddbaae5a2018a;
            stream[111] = 128'h9370e106868156a67449110368ceb950;
            stream[112] = 128'h4200239926854cc80e3501ad251ce1c4;
            stream[113] = 128'h196d0f94c8fdef8bd3d73c8d4ef39f75;
            stream[114] = 128'hb2d637acb9ebfee9b54b8f7f73ae1dc4;
            stream[115] = 128'he6e94701bbe67586a53855b2feac17d2;
            stream[116] = 128'hbcbcaa078fcf73d1b9a6351778ef9e72;
            stream[117] = 128'h077db19edc619599062bc8e243cf76b1;
            stream[118] = 128'h6e4550c6bd5f75db7682e43516a3a03a;
            stream[119] = 128'h97de5e2909d0cb59ab95a90317a9c2b7;
            stream[120] = 128'h3ebbb4aa290ffd9b6a22552333105306;
            stream[121] = 128'h314df0eed7f7b88ab41ee44ee3008389;
            stream[122] = 128'h67c3d585f340162a628385898a0dccff;
            stream[123] = 128'h1e453fcf438d425d4efec9af1c03fe0a;
            stream[124] = 128'hb671b85a7302c83e260182317f976fba;
            stream[125] = 128'h07d347c1c8bb67bb417d34ffc3a405f2;
            stream[126] = 128'hce9b93e7d4d56ff744e0d0edd3165236;
            stream[127] = 128'hd81c75c3fa63bdc07a350ab306261c90;
        end else begin
            stream[0] = 128'h890bdb47d0f7906a78360f36c5d15f65;
            stream[1] = 128'h416337c927eceac29b20b60c2ffda47c;
            stream[2] = 128'h3bc884afe8d0a4d01650a1ac489f6a41;
            stream[3] = 128'h830e90fc378d0eb54e505081616bed6f;
            stream[4] = 128'h889f7d98cdd7c878ff2d62940cb60564;
            stream[5] = 128'h5ccd721630a40e0de0bc8a8af76abda5;
            stream[6] = 128'h48bad96e2be2429eaace64e56c77d660;
            stream[7] = 128'h4f569a81ee20c48e4f03a82b23002ce8;
            stream[8] = 128'hd5347f044efcea4df199a655b2615f10;
            stream[9] = 128'h857eb1b70153887a057981dc6783fd18;
            stream[10] = 128'h1e3c95df718961ae898f53b58d9b47c3;
            stream[11] = 128'h800924782819fb92119d8eebf1166282;
            stream[12] = 128'h65568ee97de2056f6cf42629e721aa3a;
            stream[13] = 128'h55a867ea278e1165ef8bec121a38de78;
            stream[14] = 128'hf0f938c55d99827b7092e6622d69dc6c;
            stream[15] = 128'hc06815122006bf3714633832af072196;
            stream[16] = 128'h7d2ecefdee58345b11208406e0ea91da;
            stream[17] = 128'h91f4624d1a1034e3c6d8c58aa28c4e30;
            stream[18] = 128'ha814b5ae390db859157c920b94cf27d1;
            stream[19] = 128'h09fe2ca8a3597dc76cc067c6b0b7a566;
            stream[20] = 128'hd5c4abfda7305fc570bc67e5817771ca;
            stream[21] = 128'h11a51bac6f3badf6765271ee8f08a29b;
            stream[22] = 128'h03607501cf85bdcf19f2cafa94dafe80;
            stream[23] = 128'h04846017c7c16c33589034b79d214002;
            stream[24] = 128'hd224888d5ade395aa2502fe296fee28e;
            stream[25] = 128'h1907680302fe77d50cad857a0af25e26;
            stream[26] = 128'h0b2f8efd6eea1fb8746dcdcf0d97d805;
            stream[27] = 128'h673e707d9b902da81d11b1ec8f028f65;
            stream[28] = 128'h7ecc01e9916bf2f2e73aa7497bb34da0;
            stream[29] = 128'hc193931a4c4249b6c670d3a3f4f49871;
            stream[30] = 128'h65dc796a795c51f133f4cab4d2772fb4;
            stream[31] = 128'h9d5c7dc53d5a8e5f58e97e669e34e656;
            stream[32] = 128'h4417272bb5f81c120de1ed18a0187a5e;
            stream[33] = 128'h35cfbc527f19cc181d67cb5b2aa5cc57;
            stream[34] = 128'h09e006d4242f2c1f1e3963a08915883d;
            stream[35] = 128'h77e979102b691d15eaaeff4c4829e5cd;
            stream[36] = 128'hc6a1ce34a8e3c0e8d7d01be6ec7b2849;
            stream[37] = 128'h2cecdda3b5946711cc5b1af77c4da45a;
            stream[38] = 128'hdd3290c43f1abfd6b83d7538a5e1a33a;
            stream[39] = 128'h43868834da353e38e67188ec5345f241;
            stream[40] = 128'h76ee7831f369478d9242dfb4cb706e34;
            stream[41] = 128'hcdd84a297f1b001ead10648966cbb34a;
            stream[42] = 128'h2ac9e5e626905e1a50eb4b21b52741b1;
            stream[43] = 128'hae4769686ae6b0f48b543106b09e89b5;
            stream[44] = 128'hba9906559f91fdc9773fad9d3d99177c;
            stream[45] = 128'h716dd53dd1a54bec698e0384e0e15703;
            stream[46] = 128'h1907777b38bf4a4a476ffc4a6f08944e;
            stream[47] = 128'ha68c9428482a4440e18a9ebda9d38d2a;
            stream[48] = 128'h9bc7be361983ed138a5d1183e93ceb91;
            stream[49] = 128'hbf1d91b6a039d73997dbdc6234961c54;
            stream[50] = 128'hde178e8970ef62465add42cec8f3561f;
            stream[51] = 128'h42461ffa6d5c9809e36fe92fcd8fc776;
            stream[52] = 128'h75c1ec1413bcee224fa50dac5b866a1e;
            stream[53] = 128'h156fb2b19bafe727a8e2970eda6405af;
            stream[54] = 128'h5b4c9c128e4436a1cf7698999cf73ebc;
            stream[55] = 128'h9209af2a88d8c6fd9c6737f2f4a5ea6c;
            stream[56] = 128'h8faf14695e676ac12c1ad000d1484ace;
            stream[57] = 128'hb7d08e30039ab886a69d04620d419316;
            stream[58] = 128'h939c6838b60cdc3bfc2a7fcca533a56f;
            stream[59] = 128'ha0d1eab8f500709dbcc7867fdefc7df2;
            stream[60] = 128'h90c71347c745cc2cf90e548e6f3bd45f;
            stream[61] = 128'h2ff34c0b8474dd3ee1b00f1bba6535ee;
            stream[62] = 128'h98ba24186d7537608332bcea2b1c437a;
            stream[63] = 128'hb53556dcdaabd12da030c5d3dfc9b17f;
            stream[64] = 128'h0e0f23462b37632edc66da93e438c78d;
            stream[65] = 128'haaa21e25c19c731e2091a1525c23625b;
            stream[66] = 128'h68a5e198b625cfca4e95dde4573e99f7;
            stream[67] = 128'had9dcae55be677d7075071aef9060e33;
            stream[68] = 128'hacc70f10b90c4d95825fa64f48cd68a7;
            stream[69] = 128'hd8d97cc076b7e4f9f988196f40df7768;
            stream[70] = 128'h20ed245faea3db0ce5dd6626256075ae;
            stream[71] = 128'heaf825f811b66bb622e152677da0a210;
            stream[72] = 128'h781467784c509faae2b7cfb638aa8f77;
            stream[73] = 128'h8d5a7d9e114d00cc4cc941e229a25cf0;
            stream[74] = 128'h983c90ea2377ccd689abee8789d5c8a4;
            stream[75] = 128'h055cc0e65a7bf5ce4b2e61b0dfdee8eb;
            stream[76] = 128'hcf0a4469612911c728b389f0ecbd5d3f;
            stream[77] = 128'h83f23502e6df12bfeb1b32e676af4467;
            stream[78] = 128'hb6034381f223bbb50b6205c3211f2071;
            stream[79] = 128'h794efd3b5c05aa5059a1be9901b06d45;
            stream[80] = 128'h639798a8e8f972a0bf3e496ae45f1d82;
            stream[81] = 128'he9ae134dcafe5e3c7d35edc92d8a9de4;
            stream[82] = 128'h05844d37d35c137452b512b79cb6040d;
            stream[83] = 128'hc970c4537de93656d1b3487745aafe9d;
            stream[84] = 128'h301ebab799cde8c7fd40ac9e9182b054;
            stream[85] = 128'hdb661df8f02766ee20685b445796ab89;
            stream[86] = 128'hec4a82258ec30f530cc2fdd7d4a33daa;
            stream[87] = 128'h988c5241fad1436ad6534abf27b82700;
            stream[88] = 128'hc0be79da76580c648da77d103f991f7a;
            stream[89] = 128'h70c2bbb9e5d9754d4f26aad38f2e5115;
            stream[90] = 128'h4b6580756408fb4969300f4d2b51ebf7;
            stream[91] = 128'hd116d010f34b556f4b371e2615088961;
            stream[92] = 128'h8d6635044f660fee697bba3508278089;
            stream[93] = 128'hd975c314aad2f6d5bb6318f863f909d9;
            stream[94] = 128'h35d055b49ca0d17d3824ad177b27ffed;
            stream[95] = 128'h716a3fe1e5330dcb8bb32a3f131024ab;
            stream[96] = 128'h8ac328ed65e94dfcce7295f36a145fca;
            stream[97] = 128'he6f1c6ff343d470ffbb956328ad332a9;
            stream[98] = 128'h1f595e62e49663bfecdb4740601c47ee;
            stream[99] = 128'h3fbc6093d2769d11ceaaed88b6c5b5ab;
            stream[100] = 128'hb509d8c3d77784c6fdb8f0cfae002f76;
            stream[101] = 128'h78606e11362d794f2598506c92c00ae4;
            stream[102] = 128'h40bf0bbedb7aabce3de2ba8b2a6b570c;
            stream[103] = 128'h974f2af892c75416fc7c57a0d9b88228;
            stream[104] = 128'hfcad05d7fb3f1613cd48107b7046bf37;
            stream[105] = 128'hd290b41719bd74e20a217b21b5a597ea;
            stream[106] = 128'hca5f3dbcf3205f5e601a840e89177a18;
            stream[107] = 128'h51450048339f8546b8b9121bd32ef72a;
            stream[108] = 128'h3f5ef47c2a03f5006b39ca4c096a475d;
            stream[109] = 128'h493e1a6e24df20ff6113c729fd7e9403;
            stream[110] = 128'h0444beb51e6d0cb95fc007fd933813af;
            stream[111] = 128'h47fa6c2b899a465dff9d532d899820f6;
            stream[112] = 128'h5ceb95229ef3faacf5092acfae59ce6b;
            stream[113] = 128'h2268259cb02e4be73fbeaf01f90ccde9;
            stream[114] = 128'h8bd34f529546fb119a21e8a77ba930cf;
            stream[115] = 128'h7d4c9cd164e33ad240749eaf7b2604ed;
            stream[116] = 128'h712e2f3051e5209eadd201bfda3865cf;
            stream[117] = 128'hf779e49bb6dd1a34dbf34d82de8acd29;
            stream[118] = 128'hac09c8af20588234c9574c927fc5e242;
            stream[119] = 128'hcd92d591fac52981fa88baa7871e8bfb;
            stream[120] = 128'hbd8216352de00051de8b4e80bbcb210e;
            stream[121] = 128'h0fb1ad948b119677cc0a2fbe285a549e;
            stream[122] = 128'h47b86fbe3da65cad48a6e63407c370ab;
            stream[123] = 128'h54482ad18a283b6dbcc7f88723404335;
            stream[124] = 128'hfe1e5ddc91ad7193e1f03436eb009288;
            stream[125] = 128'hc31ef7e56c576fd2e5e0b4d121f565fc;
            stream[126] = 128'hee07b87d9dbb3510774accc7029e0d71;
            stream[127] = 128'hd6bf634934ccb152bfa9759aceea9497;
        end
        repeat (2) @(posedge clk);
        @(negedge clk); reset = 0;
        #1; erased();
        run_message(LONG_BEATS, BYTES, 0, 0);
        run_message(LONG_BEATS, BYTES-1, 1, 1);
        for (int final_bytes = 1; final_bytes <= BYTES; final_bytes++)
            run_message(1, final_bytes, final_bytes%2 == 0, final_bytes%3 == 0);
        for (int kind = 0; kind < 6; kind++) begin
            abort_message(kind);
            run_message(2, 1, 0, 0);
        end
        for (int kind = 0; kind < 4; kind++) abort_stalled_output(kind);
        for (int trial = 0; trial < 12; trial++)
            run_message(1+int'(random_word()%LONG_BEATS), 1+int'(random_word()%BYTES), 1, 1);
        limit_boundary(0);
        limit_boundary(1);
        $display("PASS GCTR AES=%0d width=%0d: %0d transactions; independent vectors, wrap, masks, stalls, errors, erasure",
                 AES_KEY_W, MEM_DATA_W, checked);
        $finish;
    end
    initial begin #10000000; $fatal(1, "GCTR watchdog expired"); end
endmodule
