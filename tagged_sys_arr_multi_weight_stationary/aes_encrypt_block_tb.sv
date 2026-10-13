`timescale 1ns/1ps

// Expected ciphertexts are independent of the RTL:
//   0: FIPS 197 (2001), Appendix C.1/C.3 (AES unchanged in the 2023 update).
//      https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
//   2..5: NIST SP 800-38A, Appendix F.1.1/F.1.5, ECB-AES128/256.Encrypt.
//      https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
//   1, 6..31: OpenSSL 3.6.1 `enc -aes-{128,256}-ecb -K KEY -nopad -nosalt`
//      with one raw 16-byte plaintext block on stdin. OpenSSL also cross-checked
//      all of the NIST vectors. Vector 1 is all-zero; vector 6 is all-one.
//      For vectors i=7..31, derive key/block bytes using Python hashlib:
//      key = sha256(f"aes-test-key-{bits}-{i}".encode()).digest()[:bits // 8]
//      block = sha256(f"aes-test-block-{bits}-{i}".encode()).digest()[:16]
// Byte strings below follow NIST ordering: the first byte is the MSB.
module aes_encrypt_block_tb #(
    parameter integer AES_KEY_W = 256
);
    localparam integer NR = (AES_KEY_W == 128) ? 10 : 14;
    localparam integer NUM_VECTORS = 32;
    localparam integer QUEUE_SIZE = 2048;

    logic clk = 0;
    logic reset = 1;
    logic in_valid = 0;
    logic in_ready;
    logic [127:0] block_in = '0;
    logic [AES_KEY_W-1:0] key_in = '0;
    logic out_valid;
    logic out_ready = 0;
    logic [127:0] block_out;

    logic [AES_KEY_W-1:0] vector_key [0:NUM_VECTORS-1];
    logic [127:0] vector_block [0:NUM_VECTORS-1];
    logic [127:0] vector_cipher [0:NUM_VECTORS-1];
    logic [127:0] expected [0:QUEUE_SIZE-1];
    integer accepted_cycle [0:QUEUE_SIZE-1];
    integer head = 0, tail = 0;
    integer cycle_count = 0;
    integer checked_blocks = 0;
    integer accepted_blocks = 0;
    integer dropped_blocks = 0;
    integer stalled_cycles = 0;
    integer blocked_inputs = 0;
    integer reset_count = 0;
    integer first_output_cycle = -1, last_output_cycle = -1;
    integer throughput_outputs = 0;
    integer vector_coverage [0:NUM_VECTORS-1];
    bit check_latency = 0;
    bit check_throughput = 0;
    bit accepted_last = 0;
    bit transferred_last = 0;
    bit held_output = 0;
    logic [127:0] held_cipher;
    logic [31:0] random_state = 32'h43f16a8b;

    always #5 clk = ~clk;
    aes_encrypt_block #(.AES_KEY_W(AES_KEY_W)) dut (.*);

    task automatic check(input bit condition, input string message_text);
        if (!condition)
            $fatal(1, "AES-%0d cycle %0d: %s", AES_KEY_W, cycle_count, message_text);
    endtask

    // A single driver owns all stimulus and scoreboard updates. Drive on the
    // falling edge; inspect transfers before the rising-edge NBA updates.
    task automatic step(
        input bit do_reset,
        input bit send_valid,
        input integer vector_index,
        input bit receive_ready
    );
        integer idx;
        integer stage;
        begin
            idx = vector_index % NUM_VECTORS;
            @(negedge clk);
            reset = do_reset;
            in_valid = send_valid;
            key_in = vector_key[idx];
            block_in = vector_block[idx];
            out_ready = receive_ready;
            @(posedge clk);
            cycle_count = cycle_count + 1;
            accepted_last = !reset && in_valid && in_ready;
            transferred_last = !reset && out_valid && out_ready;
            if (reset) begin
                dropped_blocks = dropped_blocks + tail - head;
                head = 0;
                tail = 0;
                held_output = 0;
                reset_count = reset_count + 1;
                check(in_ready === 1'b0, "reset must suppress input acceptance");
            end else begin
                check((in_ready === 1'b0) || (in_ready === 1'b1), "unknown input ready");
                check((out_valid === 1'b0) || (out_valid === 1'b1), "unknown output valid");
                if (held_output)
                    check(out_valid && block_out === held_cipher,
                          "stalled output changed before it was consumed");
                if (out_valid) begin
                    check(head < tail, "unexpected or duplicate output");
                    check(block_out === expected[head],
                          $sformatf("ciphertext mismatch: got %032h expected %032h",
                                    block_out, expected[head]));
                end
                if (transferred_last) begin
                    if (check_latency)
                        check(cycle_count - accepted_cycle[head] == NR + 1,
                              "incorrect transfer latency with no backpressure");
                    if (check_throughput) begin
                        if (last_output_cycle >= 0)
                            check(cycle_count == last_output_cycle + 1,
                                  "output bubble in continuous throughput test");
                        else
                            first_output_cycle = cycle_count;
                        last_output_cycle = cycle_count;
                        throughput_outputs = throughput_outputs + 1;
                    end
                    head = head + 1;
                    checked_blocks = checked_blocks + 1;
                end
                if (accepted_last) begin
                    check(tail < QUEUE_SIZE, "scoreboard capacity exceeded");
                    expected[tail] = vector_cipher[idx];
                    accepted_cycle[tail] = cycle_count;
                    tail = tail + 1;
                    accepted_blocks = accepted_blocks + 1;
                    vector_coverage[idx] = vector_coverage[idx] + 1;
                end
                if (in_valid && !in_ready)
                    blocked_inputs = blocked_inputs + 1;
                held_output = out_valid && !out_ready;
                held_cipher = block_out;
                if (held_output)
                    stalled_cycles = stalled_cycles + 1;
            end
            #1;
            // Security storage invariant: reset and bubbles erase key/state
            // registers, including interior stages hidden from normal outputs.
            for (stage = 0; stage <= NR; stage = stage + 1)
                if (reset || !dut.valid_pipe[stage])
                    check(dut.state_pipe[stage] === 128'b0,
                          $sformatf("inactive state stage %0d retained data", stage));
            for (stage = 0; stage < NR; stage = stage + 1)
                if (reset || !dut.valid_pipe[stage])
                    check(dut.key_pipe[stage] === {AES_KEY_W{1'b0}},
                          $sformatf("inactive key stage %0d retained key material", stage));
            if (reset) begin
                check(out_valid === 1'b0, "reset must cancel outstanding output");
                check(block_out === 128'b0, "reset must clear output data");
            end else begin
                if (held_output)
                    check(out_valid && block_out === held_cipher,
                          "stalled output changed across a rising edge");
                if (check_latency && out_valid) begin
                    check(head < tail, "newly asserted output has no request");
                    check(cycle_count - accepted_cycle[head] == NR,
                          "incorrect output availability latency with no backpressure");
                end
            end
        end
    endtask

    task automatic drain;
        integer watchdog;
        begin
            watchdog = 0;
            while (head < tail) begin
                step(0, 0, watchdog, 1);
                watchdog = watchdog + 1;
                check(watchdog < 256, "pipeline drain timed out");
            end
            // Catch duplicated responses after the final expected block.
            repeat (NR + 2) step(0, 0, 0, 1);
            check(!out_valid, "pipeline should be idle after draining");
        end
    endtask

    task automatic next_random;
        begin
            random_state = random_state ^ (random_state << 13);
            random_state = random_state ^ (random_state >> 17);
            random_state = random_state ^ (random_state << 5);
        end
    endtask

    initial begin : regression
        integer i;
        integer sent;
        integer watchdog;
        integer oracle_fd, oracle_fields, oracle_count;
        string oracle_file;
        bit pending;
        check(AES_KEY_W == 128 || AES_KEY_W == 256, "unsupported test key width");
        for (i = 0; i < NUM_VECTORS; i = i + 1)
            vector_coverage[i] = 0;

        if (AES_KEY_W == 128) begin
            vector_key[0] = 128'h000102030405060708090a0b0c0d0e0f;
            vector_block[0] = 128'h00112233445566778899aabbccddeeff;
            vector_cipher[0] = 128'h69c4e0d86a7b0430d8cdb78070b4c55a;
            vector_key[1] = 128'h00000000000000000000000000000000;
            vector_block[1] = 128'h00000000000000000000000000000000;
            vector_cipher[1] = 128'h66e94bd4ef8a2c3b884cfa59ca342b2e;
            vector_key[2] = 128'h2b7e151628aed2a6abf7158809cf4f3c;
            vector_block[2] = 128'h6bc1bee22e409f96e93d7e117393172a;
            vector_cipher[2] = 128'h3ad77bb40d7a3660a89ecaf32466ef97;
            vector_key[3] = 128'h2b7e151628aed2a6abf7158809cf4f3c;
            vector_block[3] = 128'hae2d8a571e03ac9c9eb76fac45af8e51;
            vector_cipher[3] = 128'hf5d3d58503b9699de785895a96fdbaaf;
            vector_key[4] = 128'h2b7e151628aed2a6abf7158809cf4f3c;
            vector_block[4] = 128'h30c81c46a35ce411e5fbc1191a0a52ef;
            vector_cipher[4] = 128'h43b1cd7f598ece23881b00e3ed030688;
            vector_key[5] = 128'h2b7e151628aed2a6abf7158809cf4f3c;
            vector_block[5] = 128'hf69f2445df4f9b17ad2b417be66c3710;
            vector_cipher[5] = 128'h7b0c785e27e8ad3f8223207104725dd4;
            vector_key[6] = 128'hffffffffffffffffffffffffffffffff;
            vector_block[6] = 128'hffffffffffffffffffffffffffffffff;
            vector_cipher[6] = 128'hbcbf217cb280cf30b2517052193ab979;
            vector_key[7] = 128'ha83fc0f7ceba45e52b1c62961e254f4e;
            vector_block[7] = 128'h868bf45407ed36ff53ab83471e6b05c2;
            vector_cipher[7] = 128'hd38da4b5b01c6d319cbe3207d7489f98;
            vector_key[8] = 128'h1adb5c93d175cdd980b3d93b94f4a618;
            vector_block[8] = 128'hc78947d86c565993cf0e299d263dd850;
            vector_cipher[8] = 128'h493bcd993a469f52844a6307bc62a868;
            vector_key[9] = 128'hbaf686b442490ee9e2a434fdcfb3d9c3;
            vector_block[9] = 128'h4368f3ab76aed22c4b6660bd5755b324;
            vector_cipher[9] = 128'h80df464d1ce67dd82949c2487d451cea;
            vector_key[10] = 128'hb833bec8cbf1c2f73237fb8d4c48711e;
            vector_block[10] = 128'h2e324949e8226b1bc1a2b0e6e86ecf20;
            vector_cipher[10] = 128'hc36b4c9eaed71f6e7401a25cf709d2c1;
            vector_key[11] = 128'h36fea2c665d552c49cfa910edd6f6682;
            vector_block[11] = 128'h803bbf7a11a7e1b3ad1834ff1477aa7b;
            vector_cipher[11] = 128'hbcd96d43afae530a85d139a4a0ea4297;
            vector_key[12] = 128'h89e24d88eb3a9aa80bea604ab396f4e2;
            vector_block[12] = 128'hf84c233201920b149f3b2451a94d5f4d;
            vector_cipher[12] = 128'hdbc9177151caf986a0c7de4dcd1742e4;
            vector_key[13] = 128'had0e8c4e7cb69d5d341eeabac878476e;
            vector_block[13] = 128'h0d0f26eca9c8efcf27138b9d1915afc0;
            vector_cipher[13] = 128'ha1600fbda4d96225d878811e74e3ec0c;
            vector_key[14] = 128'h78112fc6ce981537c8028415f76d68b0;
            vector_block[14] = 128'h8e3698cd7dc90143b3617c4cf66c90ce;
            vector_cipher[14] = 128'heda69f1cc4bb0206bce5739cb8b0f365;
            vector_key[15] = 128'h16a9bf185434e1a18a74036c9349a0d9;
            vector_block[15] = 128'h3d142213f6af54df60db34b3eb89e36b;
            vector_cipher[15] = 128'hc41c04fd5d821f4a36d6a6c9f45d5ef5;
            vector_key[16] = 128'hf93ab3c9b30b29daaceb2aec94adee2b;
            vector_block[16] = 128'hb01676ecbb82889db736124d4912e004;
            vector_cipher[16] = 128'h1a90d9d68f25bb9d4473649ef30999b3;
            vector_key[17] = 128'hfd21d26e55bc6e5f7547ba5cfe893776;
            vector_block[17] = 128'h6df586939516d9847ebc49a577e29b91;
            vector_cipher[17] = 128'h7d4b04d27526b45315c921d4ba4fbe69;
            vector_key[18] = 128'hea46b3dd20e62f7993fb640073a7f754;
            vector_block[18] = 128'hfffb1c476718d8724d4e421511e211e1;
            vector_cipher[18] = 128'hca7c768a98c2351ccd36cc526fd1ff10;
            vector_key[19] = 128'h4771aa0c7065200f9eeece0129ab4f78;
            vector_block[19] = 128'h13649b7ac2a59e68f584a8ae1113cd16;
            vector_cipher[19] = 128'h90f96e646f83d48b368940d736750d48;
            vector_key[20] = 128'hd9917c42881192082579629f84d19526;
            vector_block[20] = 128'ha6cca17ab8ae28b0cd19f17241a11e46;
            vector_cipher[20] = 128'hace30b8f541cc6b15e2b039226eb34ac;
            vector_key[21] = 128'h76955b3f2de59dc73d2f7933de7eaa68;
            vector_block[21] = 128'h79097712983a12423d6cab4e16bad5f2;
            vector_cipher[21] = 128'h44db1918572d64e621dc16e61445cf49;
            vector_key[22] = 128'h267cb147183efd39d86b3aff8b9a80a5;
            vector_block[22] = 128'h44fdfe12dfa2b612000262292e824ae7;
            vector_cipher[22] = 128'he98dfa0b36d0345fbdeef00c66f0513d;
            vector_key[23] = 128'hc6e6cf4b666c8a0472c6f645431ce844;
            vector_block[23] = 128'h2bf49921c92b065c15ad2fc8b6843e03;
            vector_cipher[23] = 128'h87c19191bf6b875e9af972108b3262ee;
            vector_key[24] = 128'he5be82e5736b325909e9d37ab5be3dee;
            vector_block[24] = 128'he7247c2015073c856a7cbf6ef5674f0f;
            vector_cipher[24] = 128'h0e8e44e5593f660febcf6d10bd5d6f99;
            vector_key[25] = 128'h9c4fc316e7570b6e64c6cfb56700f9c4;
            vector_block[25] = 128'hcea611df09d9dfe42be01cec24808aad;
            vector_cipher[25] = 128'hccb3346fc681f41b895f9b04f41a3af6;
            vector_key[26] = 128'hab41a7673bced31dde8930e6570d1f8d;
            vector_block[26] = 128'h4cb75d88272649a973cbb0312fe120ba;
            vector_cipher[26] = 128'hdf1006671dfc172b83fd35639215f1de;
            vector_key[27] = 128'hfe75d7f67ebf43cc2443cf343584c94a;
            vector_block[27] = 128'he6779707c00e630b5da56eb4772758f8;
            vector_cipher[27] = 128'h89143c9b754737cb2492073b28d9cdc6;
            vector_key[28] = 128'hfdd7ec895ff1fabd4c370a1982230190;
            vector_block[28] = 128'hd71c62a59bb8d21c988b080cb554a394;
            vector_cipher[28] = 128'h9bd10a190e8594f81573bbc2a049ee40;
            vector_key[29] = 128'hb188d90983974c6f1a4015e05ba3f426;
            vector_block[29] = 128'h19e321f999bbf74e9a132cc4cb45dd06;
            vector_cipher[29] = 128'h9cc9ba3c7907660124ac5481cee4c659;
            vector_key[30] = 128'hda7385c1c54bf89c22e97b485e64c102;
            vector_block[30] = 128'h08cefa820044c8a3e2559dd21829296d;
            vector_cipher[30] = 128'hca7e258844d1e41ad7af599f2b8cc43e;
            vector_key[31] = 128'hd99d1b72e16d460a411b89700f34579b;
            vector_block[31] = 128'hf06bd72d1e29aa55d36ff267f8033fde;
            vector_cipher[31] = 128'hca13900328ae4b3cd4d9e402eaed977e;
        end else begin
            vector_key[0] = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
            vector_block[0] = 128'h00112233445566778899aabbccddeeff;
            vector_cipher[0] = 128'h8ea2b7ca516745bfeafc49904b496089;
            vector_key[1] = 256'h0000000000000000000000000000000000000000000000000000000000000000;
            vector_block[1] = 128'h00000000000000000000000000000000;
            vector_cipher[1] = 128'hdc95c078a2408989ad48a21492842087;
            vector_key[2] = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;
            vector_block[2] = 128'h6bc1bee22e409f96e93d7e117393172a;
            vector_cipher[2] = 128'hf3eed1bdb5d2a03c064b5a7e3db181f8;
            vector_key[3] = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;
            vector_block[3] = 128'hae2d8a571e03ac9c9eb76fac45af8e51;
            vector_cipher[3] = 128'h591ccb10d410ed26dc5ba74a31362870;
            vector_key[4] = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;
            vector_block[4] = 128'h30c81c46a35ce411e5fbc1191a0a52ef;
            vector_cipher[4] = 128'hb6ed21b99ca6f4f9f153e7b1beafed1d;
            vector_key[5] = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;
            vector_block[5] = 128'hf69f2445df4f9b17ad2b417be66c3710;
            vector_cipher[5] = 128'h23304b7a39f9f3ff067d8d8f9e24ecc7;
            vector_key[6] = 256'hffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
            vector_block[6] = 128'hffffffffffffffffffffffffffffffff;
            vector_cipher[6] = 128'hd5f93d6d3311cb309f23621b02fbd5e2;
            vector_key[7] = 256'h0b9cb792ecc55b9ff1c72a72a1d659843b680ef85580b29c61a5c800efc58f44;
            vector_block[7] = 128'hd32b4b9c372e74dc2b2139819b3171c2;
            vector_cipher[7] = 128'h4dae5065f06c15d21fd4e4bcfef43368;
            vector_key[8] = 256'h1ac1c5136ba25461c305f2c367753374c5ce13c267637f873e1d52aba766cde5;
            vector_block[8] = 128'hed9a102f9e05cb18de617d62a564ce0a;
            vector_cipher[8] = 128'hf03d680f94dd0b9db74a939e9ed63cfe;
            vector_key[9] = 256'hdbae09e25b48b5afa0f21a3fa5d5933050a15c9c03e22e44d9712bd125bc6dee;
            vector_block[9] = 128'h7fc74b80b8800614c985ebd0e5860ce8;
            vector_cipher[9] = 128'hda2d851d42217bb7dbc65b01b53bce02;
            vector_key[10] = 256'hec6eec97ed6774cb3c6662d58eaba6a92d3baf86616798982ce378c0c3d28e7a;
            vector_block[10] = 128'hd4aba607417965918a8488539a76934b;
            vector_cipher[10] = 128'h49469a112cc6313c74aa040f13ede863;
            vector_key[11] = 256'h9e3e6c084ada5aa4d2175a143ea3d260eb5dc6ca210c9d671bc5089fa040f5b2;
            vector_block[11] = 128'hc1c39e5c7baa32aeea8ef90b214c6caa;
            vector_cipher[11] = 128'he1b0bf3d2213b81ccf7d4f7bf93ec0c4;
            vector_key[12] = 256'h94c39d45bd8ffc0b783d4de9b95e39405418bf8463e6ece479e302afec0b5ebf;
            vector_block[12] = 128'hec6697d3673b75660179b5ba8e825e56;
            vector_cipher[12] = 128'hfd2cf0881a81c35f2ee9afa1aab1888c;
            vector_key[13] = 256'hf10997d4ccda8c047f7a49027548678f7151b3c1b9b722ee2ad79731b329bfe1;
            vector_block[13] = 128'h2ce19b745bb354003ee19db3ad0c47e6;
            vector_cipher[13] = 128'h601ed92e3258bfc06435da2b7c5448bd;
            vector_key[14] = 256'h6a4f12e05cd8b30686ebe6da964ef3b4721f309d3c7a65b58e0f1d058f2a5151;
            vector_block[14] = 128'hb0c10766d640f6fcca5c395cbe0cb9fd;
            vector_cipher[14] = 128'hb4e5bd48c87d6882b183bdba5b3f7cba;
            vector_key[15] = 256'h5c6037d44649af8ac1abda65b983eb7b9cceb2b809d6c861697fd0bf7cf5803a;
            vector_block[15] = 128'hdb029c6b3886651ccd2a43162beb4915;
            vector_cipher[15] = 128'h5c4e37180846105a83d917333f11b9ea;
            vector_key[16] = 256'h161fe3dd4134767da65c374bb41ebe727a46112eb6f6a69514136ed0e42e8693;
            vector_block[16] = 128'h7609c1d7b5f23abd559e7463954676e1;
            vector_cipher[16] = 128'h3b80c053c3efa5beb62c41f224883014;
            vector_key[17] = 256'h1918ba231a2817c83661c77d07c4f687f14d5af730170e2c2d373af34cf397d2;
            vector_block[17] = 128'he5f9690ded8021e5ce2f41cd77c845f7;
            vector_cipher[17] = 128'h0560fe1297c6c35381a69d0b0f3b8abf;
            vector_key[18] = 256'h1be482e77a7c392655dc2bd3893f48224d6f2ae8856a70f992f222908c975b99;
            vector_block[18] = 128'had41224e342ced1a6ef7fb3d08a3a4c2;
            vector_cipher[18] = 128'hcfefd1ec556ac2943f0f85189f5b4316;
            vector_key[19] = 256'h3b6b0eb8eddd56378c6ea94cbec9b56a0a4a43c2b7c0ad53e65f46cee6f66dae;
            vector_block[19] = 128'h1b1e1311e8031b3dbdfdf3447f506db7;
            vector_cipher[19] = 128'h11d6c12ebe98fe3d5c6bd36ffb70304b;
            vector_key[20] = 256'hf877ace88fbc2d0ba55d19fd4c09d44ae007f2af0c3adc9fbbe7ed3399799436;
            vector_block[20] = 128'h47d53816da1f638c0c8767e9b159f4fe;
            vector_cipher[20] = 128'hcf106c99310d1753c88bfb90a31c8353;
            vector_key[21] = 256'ha58e8b6fd00cb4cede5945acc0715eda31258613d2e6c51baa8cef9a74e67410;
            vector_block[21] = 128'h0e7de3794ccf451bb35dff000f5add4b;
            vector_cipher[21] = 128'h62e844955d7497df1e884125efccb2b7;
            vector_key[22] = 256'h03114f0842c0fcce852dce6494d4414649b9c60523bc495c221cdb11916ef548;
            vector_block[22] = 128'h533c413f2296277cfd6a15e5020e753a;
            vector_cipher[22] = 128'h1e404f430006d3029099a86308d13abe;
            vector_key[23] = 256'h0a46ebfcd5e0dcb92f9412fd889d00d61f0ce2bc35db3b84e27ef36001335918;
            vector_block[23] = 128'h666e94ea28c26b3d5fc3d588aaf62d8e;
            vector_cipher[23] = 128'he87396b167e047f42dd88ba8851f6ea9;
            vector_key[24] = 256'h961578a5bf6eb5ad7e2b9f3cabb9628314d4dce744dc60e5b5db479770da42ce;
            vector_block[24] = 128'h7df082ae680995b1f6d330ea9f3a8f68;
            vector_cipher[24] = 128'h170e6163981337e5ec901b2826fa484b;
            vector_key[25] = 256'h55479a4db1139dd7cf16e3d57208cc726609d812eb7061d7b55c9e31a4fc9b65;
            vector_block[25] = 128'h652965f1102b086cfd935e52be9c3b34;
            vector_cipher[25] = 128'h5163b3c4e13007e8289643495a8c678a;
            vector_key[26] = 256'h10f9fde444af95213c56912f080af6d2e5b4ffffd6cf706be5cb21695f45f03d;
            vector_block[26] = 128'hcd5268467978d3031e6305b51bef5156;
            vector_cipher[26] = 128'h99bf290aee264721ec1f72f1fdecef3e;
            vector_key[27] = 256'h95875294bcdf8338b7a253590f2bd41f810133dc3271b1caabcec44030ba95ad;
            vector_block[27] = 128'h195ce84f97255a900b25cd9df1dd77a4;
            vector_cipher[27] = 128'hbccae33775e5bfa7d27d0ca450e9ba81;
            vector_key[28] = 256'h32c46d53dedb8b1c6cafb56c782bc41170a447cd5b8dec6ad64860e6db4905e5;
            vector_block[28] = 128'h7b5dbc2d4058203b5b4d33d24633d090;
            vector_cipher[28] = 128'h877f35aea93968cb112d4d52acddb939;
            vector_key[29] = 256'h14859b412fad60efc3ce5633a4a28f6863291c6e4475a2d166b1e5be9e62678c;
            vector_block[29] = 128'h3e3edf5484056f8cad4efebacb3ded31;
            vector_cipher[29] = 128'h45b3b85c349279cbadf8325a6df8d447;
            vector_key[30] = 256'h22ba9bbfefa306438d4787746b014d25dccf769a50b2f3d95a218704975eab4b;
            vector_block[30] = 128'h01a3ecd7b3162457c7b0f326b9c16b6e;
            vector_cipher[30] = 128'h533b33c95fc5e82e1d5d443e852be20d;
            vector_key[31] = 256'hf014c95902b3ec1d9f8b3409e09ac4ed105a3a31e80d019136798037f24a9c83;
            vector_block[31] = 128'h9b099cea58047282d26df046f71785a8;
            vector_cipher[31] = 128'h03010f42635d4e644cfb3bade1bf7a88;
        end

        step(1, 0, 0, 0);
        step(1, 1, 6, 1); // Reset wins even with both interfaces active.

        // Ninety-six consecutive requests exercise all vectors three times,
        // changing key every cycle except the four-block NIST ECB transaction.
        check_latency = 1;
        check_throughput = 1;
        for (i = 0; i < 96; i = i + 1) begin
            step(0, 1, i, 1);
            check(accepted_last, "input bubble in continuous throughput test");
        end
        drain();
        check(throughput_outputs == 96, "continuous burst lost an output");
        check(last_output_cycle - first_output_cycle == 95,
              "must sustain one encrypted block per cycle");
        check_throughput = 0;
        check_latency = 0;

        // Hold the output stopped until the pipeline fills, then keep the
        // rejected next input stable while all occupied stages are frozen.
        for (i = 0; i < NR + 1; i = i + 1) begin
            step(0, 1, i, 0);
            check(accepted_last, "pipeline should accept blocks before output fills");
        end
        check(out_valid, "filled pipeline must present an output");
        repeat (9) begin
            step(0, 1, NR + 1, 0);
            check(!accepted_last, "full stalled pipeline accepted an extra block");
        end
        step(0, 1, NR + 1, 1);
        check(accepted_last && transferred_last,
              "pipeline must resume input and output on the same edge");
        drain();

        // Deterministic pseudo-random bubbles and output stalls. A pending
        // request retains valid/key/block until the ready/valid transfer.
        sent = 0;
        pending = 0;
        watchdog = 0;
        while (sent < 160) begin
            next_random();
            if (!pending)
                pending = random_state[0] || random_state[7];
            step(0, pending, sent, random_state[2] || random_state[11]);
            if (accepted_last) begin
                sent = sent + 1;
                pending = 0;
            end
            watchdog = watchdog + 1;
            check(watchdog < 1000, "mixed traffic made insufficient progress");
        end
        drain();

        // Reset while blocks occupy only intermediate rounds.
        for (i = 0; i < 4; i = i + 1)
            step(0, 1, i + 7, 1);
        check(!out_valid && tail - head == 4, "reset setup must have four inflight blocks");
        step(1, 1, 0, 1);
        repeat (NR + 3) step(0, 0, 6, 1);
        check(head == tail, "reset leaked an inflight result");

        // Reset while a valid output is held by backpressure, with later
        // blocks and their independent keys still resident in the pipeline.
        for (i = 0; i < NR + 1; i = i + 1)
            step(0, 1, i + 16, 0);
        check(out_valid, "stalled reset setup must have a valid output");
        repeat (3) step(0, 0, 6, 0);
        step(1, 1, 6, 0);
        repeat (NR + 3) step(0, 0, 0, 1);

        // Fresh requests after cancellation must use fresh keys and maintain
        // the original latency. Mutating invalid inputs must have no effect.
        check_latency = 1;
        for (i = 0; i < NUM_VECTORS; i = i + 1) begin
            step(0, 1, NUM_VECTORS - 1 - i, 1);
            step(0, 0, i, 1);
        end
        drain();
        for (i = 0; i < NUM_VECTORS; i = i + 1)
            check(vector_coverage[i] >= 4, "a reference vector was insufficiently exercised");
        check(stalled_cycles >= 12 && blocked_inputs >= 9,
              "backpressure scenarios were not exercised");
        check(accepted_blocks == checked_blocks + dropped_blocks,
              "accepted requests do not match completed plus canceled requests");
        check(dropped_blocks == NR + 5, "reset cancellation count mismatch");
        // Optional independently generated OpenSSL campaign. Holding vector
        // slot 31 until acceptance obeys the producer's ready/valid contract.
        oracle_count = 0;
        if ($value$plusargs("oracle_file=%s", oracle_file)) begin
            oracle_fd = $fopen(oracle_file, "r");
            check(oracle_fd != 0, "cannot open independent oracle vectors");
            check_latency = 0;
            while (!$feof(oracle_fd)) begin
                oracle_fields = $fscanf(oracle_fd, "%h %h %h\n", vector_key[31], vector_block[31], vector_cipher[31]);
                if (oracle_fields == 3) begin
                    watchdog = 0;
                    do begin
                        next_random();
                        step(0, 1, 31, random_state[0] || random_state[4]);
                        watchdog++;
                        check(watchdog < 100, "oracle request stalled indefinitely");
                    end while (!accepted_last);
                    if (random_state[5:4] == 0) step(0, 0, 6, random_state[6]);
                    oracle_count++;
                end else check($feof(oracle_fd), "malformed independent oracle fixture");
            end
            $fclose(oracle_fd);
            check(oracle_count >= 512, "oracle campaign must contain at least 512 fresh cases");
            drain();
        end
        // Cancel a request resident at every pipeline position, including
        // initial key capture and the blocked output stage.
        check_latency = 0;
        for (i = 0; i <= NR; i++) begin
            step(0, 1, i, 0);
            repeat(i) step(0, 0, 6, 0);
            check(dut.valid_pipe[i] === 1'b1, "reset stage was not occupied");
            step(1, 1, 0, 0);
            repeat(NR + 2) step(0, 0, 6, 1);
        end
        check(accepted_blocks == checked_blocks + dropped_blocks, "final transaction conservation");
        $display("AES-%0d additional oracle vectors=%0d; reset at all %0d pipeline stages", AES_KEY_W, oracle_count, NR+1);
        $display("PASS: AES-%0d %0d checked blocks, %0d vectors, latency=%0d cycles, throughput=1 block/cycle, stalled=%0d cycles, reset-canceled=%0d blocks",
                 AES_KEY_W, checked_blocks, NUM_VECTORS, NR, stalled_cycles, dropped_blocks);
        $finish;
    end

    initial begin
        #100000;
        $fatal(1, "AES-%0d test timeout", AES_KEY_W);
    end
endmodule
