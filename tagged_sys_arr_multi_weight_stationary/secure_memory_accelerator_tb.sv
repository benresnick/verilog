`timescale 1ns/1ps
// End-to-end oracle: independently encoded OpenSSL records and signed Python
// matrix multiplication. No crypto or arithmetic model shares DUT RTL code.
module secure_memory_accelerator_tb #(
    parameter int ROWS=2, COLS=2, WEIGHTS_PER_PE=2,
    parameter int DATA_WIDTH=8, ACC_WIDTH=32,
    parameter int AES_KEY_W=256, MEM_DATA_W=128,
    parameter int MAX_M=8, MAX_K=24, MAX_N=8,
    parameter int NUM_KEY_SLOTS=3,
    parameter int SLOT_W=$clog2(NUM_KEY_SLOTS),
    parameter int M_WIDTH=$clog2(MAX_M+1), K_WIDTH=$clog2(MAX_K+1), N_WIDTH=$clog2(MAX_N+1),
    parameter int COOKIE_W=64
);
    localparam int BYTES=MEM_DATA_W/8, DATA_BYTES=DATA_WIDTH/8, ACC_BYTES=ACC_WIDTH/8;
    localparam int COUNTERS=32;
    logic clk=0, reset=1, abort=0;
    logic [2:0] clear=0;
    logic provision_valid=0, invalidate_valid=0;
    wire provision_ready, provision_error, invalidate_ready;
    logic [SLOT_W-1:0] provision_slot=0, invalidate_slot=0;
    logic [95:0] provision_tenant_id=0;
    logic [AES_KEY_W-1:0] provision_key=0;
    logic [31:0] provision_iv_fixed_field=0;
    logic [63:0] provision_counter_start=0;
    logic config_valid=0, start_valid=0;
    wire config_ready, config_error, start_ready, busy, done, job_error, security_fault;
    logic [M_WIDTH-1:0] config_m=0;
    logic [K_WIDTH-1:0] config_k=0;
    logic [N_WIDTH-1:0] config_n=0;
    logic [1:0] load_valid=0, load_data_valid=0, load_last=0, load_result_ready=0;
    wire [1:0] load_ready, load_data_ready, load_result_valid;
    logic [1:0][95:0] load_tenant=0;
    logic [1:0][31:0] load_row=0;
    logic [1:0][255:0] load_header=0;
    logic [1:0][MEM_DATA_W-1:0] load_data=0;
    logic [1:0][BYTES-1:0] load_keep=0;
    wire [1:0][3:0] load_result_error;
    wire store_valid, store_last, store_header_valid, store_ack_ready, store_result_valid;
    logic store_ready=0, store_header_ready=0, store_ack_valid=0, store_ack_success=0, store_result_ready=0;
    wire [MEM_DATA_W-1:0] store_data;
    wire [BYTES-1:0] store_keep;
    wire [255:0] store_header;
    wire [M_WIDTH-1:0] store_row;
    wire [31:0] store_bytes;
    wire [COOKIE_W-1:0] store_cookie;
    logic [COOKIE_W-1:0] store_ack_cookie=0;
    wire [3:0] store_result_error;
    logic [95:0] tenant[0:2];
    logic [AES_KEY_W-1:0] key_value[0:2];
    logic [31:0] iv_fixed[0:2];
    logic [MAX_K*DATA_WIDTH-1:0] a_plain[0:MAX_M-1], a_cipher[0:MAX_M-1];
    logic [MAX_K*DATA_WIDTH-1:0] a_alt_plain[0:MAX_M-1], a_alt_cipher[0:MAX_M-1];
    logic [255:0] a_header[0:MAX_M-1], a_alt_header[0:MAX_M-1];
    logic [MAX_N*DATA_WIDTH-1:0] b_plain[0:MAX_K-1], b_cipher[0:MAX_K-1];
    logic [MAX_N*DATA_WIDTH-1:0] b_alt_plain[0:MAX_K-1], b_alt_cipher[0:MAX_K-1];
    logic [255:0] b_header[0:MAX_K-1], b_alt_header[0:MAX_K-1];
    logic [MAX_N*ACC_WIDTH-1:0] c_plain[0:MAX_M-1], c_cipher[0:MAX_M-1][0:COUNTERS-1];
    logic [255:0] c_header[0:MAX_M-1][0:COUNTERS-1];
    logic [DATA_WIDTH-1:0] a_model[0:MAX_M-1][0:MAX_K-1], b_model[0:MAX_K-1][0:MAX_N-1];
    bit a_loaded[0:MAX_M-1], b_loaded[0:MAX_K-1], retired[0:MAX_M-1];
    int m,k,n,job=-1,loads=0,stored_rows=0,rejected_loads=0,checks=0,done_count=0;
    int output_attempts=0,nonce_next[0:2];
    int active_nonce=-1,active_row=-1;
    logic [COOKIE_W-1:0] cookie_next=0,active_cookie=0;
    logic [31:0] rng=32'h928fd013;
    string fixture_path;
    always #5 clk=~clk;
    secure_memory_accelerator #(.ROWS(ROWS),.COLS(COLS),.WEIGHTS_PER_PE(WEIGHTS_PER_PE),
        .DATA_WIDTH(DATA_WIDTH),.ACC_WIDTH(ACC_WIDTH),.AES_KEY_W(AES_KEY_W),.MEM_DATA_W(MEM_DATA_W),
        .MAX_M(MAX_M),.MAX_K(MAX_K),.MAX_N(MAX_N),.NUM_KEY_SLOTS(NUM_KEY_SLOTS),.SLOT_W(SLOT_W),
        .M_WIDTH(M_WIDTH),.K_WIDTH(K_WIDTH),.N_WIDTH(N_WIDTH),.COOKIE_W(COOKIE_W)) dut(.*);

    wire [1:0] stage_erased;
    wire [2:0] crypto_private_erased;
    for(genvar p=0;p<2;p++) begin:g_stage_check
        localparam int CAP=(p==0?MAX_K:MAX_N)*DATA_WIDTH;
        assign stage_erased[p]=dut.g_load[p].stage.stage_reg==={CAP{1'b0}} &&
            dut.g_load[p].stage.bytes_reg===0 && dut.g_load[p].stage.received_reg===0 &&
            dut.g_load[p].stage.tenant_reg===96'b0 && dut.g_load[p].stage.destination_reg===64'b0;
    end
    for(genvar p=0;p<3;p++) begin:g_crypto_check
        assign crypto_private_erased[p]=
            dut.crypto.g_port[p].port_engine.engine.key_reg==={AES_KEY_W{1'b0}} &&
            dut.crypto.g_port[p].port_engine.engine.iv_reg===96'b0 &&
            dut.crypto.g_port[p].port_engine.engine.h_reg===128'b0 &&
            dut.crypto.g_port[p].port_engine.engine.tag_mask===128'b0 &&
            dut.crypto.g_port[p].port_engine.engine.expected_tag_reg===128'b0 &&
            dut.crypto.g_port[p].port_engine.aad_reg===256'b0 &&
            dut.crypto.g_port[p].port_engine.tenant_reg===96'b0;
    end
    task automatic ck(input logic condition,input string message);
        checks++;
        if(condition!==1'b1)
            $fatal(1,"SECURE_MEMORY AES%0d bus%0d shape%0dx%0d banks%0d job%0d: %s",AES_KEY_W,MEM_DATA_W,ROWS,COLS,WEIGHTS_PER_PE,job,message);
    endtask
    function automatic [31:0] random_word();
        rng^=rng<<13; rng^=rng>>17; rng^=rng<<5;
        return rng;
    endfunction
    function automatic [BYTES-1:0] keep_for(input int bytes_left);
        logic [BYTES-1:0] mask;
        mask=0;
        for(int b=0;b<BYTES;b++) if(b<bytes_left) mask[BYTES-1-b]=1;
        return mask;
    endfunction
    task automatic quiet_pins();
        if(!store_valid)
            ck(store_data==={MEM_DATA_W{1'b0}} && store_keep==={BYTES{1'b0}} && !store_last,
                "invalid ciphertext pins expose no plaintext or stale ciphertext");
        if(!store_header_valid) ck(store_header===256'b0,"invalid header pins expose no stale IV/tag");
        if(!store_valid && !store_header_valid && !store_ack_ready)
            ck(store_row===0 && store_bytes===0 && store_cookie===0,"invalid storage context pins are zero");
        if(!store_result_valid) ck(store_result_error===0,"invalid storage result is zero");
        for(int p=0;p<2;p++)
            if(!load_result_valid[p]) ck(load_result_error[p]===0,"invalid load result is zero");
    endtask

    // Track the actual protected reservation event, not an expected software
    // schedule. Retries/clear/abort must never roll these model counters back.
    always @(posedge clk) begin : reservation_monitor
        int slot;
        if(reset) begin
            for(int s=0;s<3;s++) nonce_next[s]=0;
            cookie_next=0;active_nonce=-1;active_row=-1;active_cookie=0;
        end else if(dut.crypto_cmd_valid[2] && dut.crypto_cmd_ready[2]) begin
            slot=(dut.output_tenant===tenant[1])?1:(dut.output_tenant===tenant[2])?2:0;
            ck(slot!=0,"output ownership selects a private tenant key");
            ck(dut.crypto.keys.reserve_iv_grant,"legal output command reserves a unique IV on its capture edge");
            ck(dut.crypto.keys.invocation_counter[slot]===64'(nonce_next[slot]),"live nonce counter matches independent reservation model");
            active_nonce=nonce_next[slot];nonce_next[slot]++;
            active_cookie=cookie_next;cookie_next++;
            active_row=dut.output_row;output_attempts++;
        end
        #1;
        if(done) done_count++;
        if(!reset) quiet_pins();
    end
    task automatic clear_models();
        for(int r=0;r<MAX_M;r++) begin
            a_loaded[r]=0;retired[r]=0;
            for(int c=0;c<MAX_K;c++) a_model[r][c]=0;
        end
        for(int r=0;r<MAX_K;r++) begin
            b_loaded[r]=0;
            for(int c=0;c<MAX_N;c++) b_model[r][c]=0;
        end
    endtask
    task automatic check_input_row(input int p,input int row_number);
        if(p==0) begin
            for(int c=0;c<MAX_K;c++) begin
                ck(dut.core.u_ibuff.data[row_number][c]===a_model[row_number][c],"A row is replaced atomically only after authenticated complete staging");
                ck(dut.core.ibuf_v[row_number][c]===1'(a_loaded[row_number] && c<k),"A data-valid bitmap matches whole-row commit");
            end
            ck(dut.core.trusted_row_tag_valid[row_number]===1'(a_loaded[row_number]),"A tenant validity commits atomically with its data");
            ck(dut.core.trusted_row_tag[row_number]===(a_loaded[row_number]?tenant[1+row_number%2]:96'b0),"A trusted tenant tag survives rejected or cancelled replacement");
        end else begin
            for(int c=0;c<MAX_N;c++) begin
                ck(dut.core.u_wbuff.data[row_number][c]===b_model[row_number][c],"public B row is replaced atomically only after authentication");
                ck(dut.core.wbuf_v[row_number][c]===1'(b_loaded[row_number] && c<n),"B data-valid bitmap matches whole-row commit");
            end
        end
    endtask
    task automatic check_inputs();
        for(int r=0;r<MAX_M;r++) check_input_row(0,r);
        for(int r=0;r<MAX_K;r++) check_input_row(1,r);
    endtask
    task automatic check_c_row(input int r,input bit erased);
        logic [ACC_WIDTH-1:0] expected_word;
        for(int c=0;c<MAX_N;c++) begin
            expected_word=0;
            if(!erased && c<n) expected_word=c_plain[r][ACC_WIDTH*(n-1-c)+:ACC_WIDTH];
            ck(dut.core.u_obuff.data[r][c]===expected_word,
                erased?"successful storage acknowledgement zeroizes whole output row":"complete plaintext row and tenant tags survive until matching successful storage acknowledgement");
            ck(dut.core.u_obuff.valid[r][c]===1'(!erased && c<n) && dut.core.u_obuff.final_valid[r][c]===1'(!erased && c<n),
                "output data-valid bits retire atomically as a complete row");
            ck(dut.core.u_secure_obuff_tags.valid[r][c]===1'(!erased && c<n) &&
                dut.core.u_secure_obuff_tags.tag[r][c]===(!erased && c<n?tenant[1+r%2]:96'b0),
                "output data and protected tenant tags have identical retirement lifetime");
        end
    endtask
    task automatic provision_all(input int counter1,input int counter2);
        for(int s=0;s<3;s++) begin
            @(negedge clk);
            provision_valid=1;provision_slot=SLOT_W'(s);provision_tenant_id=tenant[s];
            provision_key=key_value[s];provision_iv_fixed_field=iv_fixed[s];
            provision_counter_start=s==1?64'(counter1):s==2?64'(counter2):64'b0;
            #1;ck(provision_ready&&!provision_error,"trusted public/private key provisioning succeeds");
            @(posedge clk);#1;
            nonce_next[s]=s==1?counter1:s==2?counter2:0;
            @(negedge clk);provision_valid=0;
        end
    endtask
    task automatic cancel_all(input bit use_reset);
        int saved1,saved2;
        logic [COOKIE_W-1:0] saved_cookie;
        saved1=nonce_next[1];saved2=nonce_next[2];saved_cookie=cookie_next;
        @(negedge clk);
        load_valid=0;load_data_valid=0;load_result_ready=0;config_valid=0;start_valid=0;
        store_ready=0;store_header_ready=0;store_ack_valid=0;store_result_ready=0;
        if(use_reset) reset=1;else abort=1;
        #1;ck(!store_valid&&!store_header_valid&&!store_ack_ready&&!store_result_valid && load_ready==0 && load_data_ready==0,"abort/reset masks every record handshake immediately");
        repeat(2) begin
            @(posedge clk);#2;
            ck((&stage_erased)&&(&crypto_private_erased),"abort/reset erases all input stages and private crypto contexts");
            ck(dut.plain_reg==={MEM_DATA_W{1'b0}} && dut.header_reg===256'b0,"abort/reset erases output serializer and pending header");
        end
        clear_models();check_inputs();
        for(int r=0;r<MAX_M;r++) check_c_row(r,1);
        if(use_reset) begin
            for(int s=0;s<3;s++) ck(!dut.crypto.keys.valid[s]&&dut.crypto.keys.aes_key[s]==={AES_KEY_W{1'b0}},"reset invalidates and wipes trusted key slots");
        end else begin
            ck(dut.crypto.keys.invocation_counter[1]===64'(saved1) && dut.crypto.keys.invocation_counter[2]===64'(saved2),"abort preserves consumed nonces");
            ck(cookie_next===saved_cookie && dut.cookie_counter===saved_cookie,"abort preserves storage-cookie history");
            for(int s=0;s<3;s++) ck(dut.crypto.keys.valid[s]&&dut.crypto.keys.aes_key[s]===key_value[s],"abort preserves provisioned trusted keys");
        end
        @(negedge clk);reset=0;abort=0;clear=0;
    endtask
    task automatic configure_job();
        @(negedge clk);
        config_valid=1;config_m=M_WIDTH'(m);config_k=K_WIDTH'(k);config_n=N_WIDTH'(n);
        #1;ck(config_ready,"idle adapter accepts next trusted shape epoch");
        @(posedge clk);#2;
        ck(!config_error,"valid configured dimensions accepted");
        clear_models();check_inputs();
        for(int r=0;r<MAX_M;r++) begin
            for(int c=0;c<MAX_K;c++) ck(!dut.core.ibuf_v[r][c],"fresh configuration erases every data-valid entry");
            check_c_row(r,1);
        end
        @(negedge clk);config_valid=0;
    endtask
    task automatic start_job(input bit expect_success);
        @(negedge clk);start_valid=1;
        #1;ck(start_ready,"idle protocol accepts start decision");
        @(posedge clk);#2;
        if(expect_success) ck(busy&&!job_error,"complete authenticated input epoch starts matrix multiply");
        else ck(job_error&&!busy&&!store_valid,"missing authenticated input rows reject start without computation");
        @(negedge clk);start_valid=0;
    endtask

    task automatic load_records(input logic [1:0] mask,input int row_a,input int row_b,
        input int fault_a,input int fault_b,input bit alternate,input int cancel_port,input int cancel_phase);
        int rr[0:1],fault[0:1],expected_error[0:1],pos[0:1],held[0:1],lengths[0:1];
        int steps,take;
        logic [1:0] finished,input_fire,commit_fire,seen_commit;
        logic [MEM_DATA_W-1:0] beat;
        logic [BYTES-1:0] byte_mask;
        logic [255:0] header_value;
        bit cancelled_now,did_cancel;
        rr[0]=row_a;rr[1]=row_b;fault[0]=fault_a;fault[1]=fault_b;
        lengths[0]=k*DATA_BYTES;lengths[1]=n*DATA_BYTES;
        finished=~mask;seen_commit=0;steps=0;did_cancel=0;
        for(int p=0;p<2;p++) begin
            pos[p]=0;held[p]=0;
            expected_error[p]=fault[p]==0?0:1;
            if(fault[p]==4||fault[p]==5||(fault[p]==6&&p==1)) expected_error[p]=7;
            if(fault[p]==8||fault[p]==9) expected_error[p]=2;
            if(fault[p]==10) expected_error[p]=4;
        end
        @(negedge clk);
        load_valid=mask;load_data_valid=0;load_result_ready=0;
        for(int p=0;p<2;p++) begin
            load_row[p]=rr[p];load_tenant[p]=p==0?tenant[1+rr[p]%2]:tenant[0];
            if(p==0) header_value=alternate?a_alt_header[rr[p]]:a_header[rr[p]];
            else header_value=alternate?b_alt_header[rr[p]]:b_header[rr[p]];
            case(fault[p])
                1:header_value^=256'b1;
                3:header_value^=256'b1<<128;
                4:header_value^=256'b1<<255;
                5:load_row[p]=p==0?m:k;
                6:load_tenant[p]=p==0?tenant[2-rr[p]%2]:tenant[1];
                7:load_row[p]=rr[p]+1;
                10:load_tenant[p]=96'hdeaddeaddeaddeaddeaddead;
                11:header_value^=256'b1<<127;
            endcase
            load_header[p]=header_value;
        end
        #1;ck((load_ready&mask)==mask,"input paths accept requested independent records together");
        @(posedge clk);#2;
        while(finished!=2'b11) begin
            @(negedge clk);
            load_valid=0;load_tenant='1;load_row='1;load_header='1;
            for(int p=0;p<2;p++) begin
                if(load_result_valid[p]) held[p]++;
                load_result_ready[p]=!finished[p]&&held[p]>5;
                if(!finished[p]&&!load_data_valid[p]&&pos[p]<lengths[p]&&expected_error[p]<3&&random_word()%3!=0) begin
                    take=lengths[p]-pos[p]<BYTES?lengths[p]-pos[p]:BYTES;
                    beat='1;
                    for(int b=0;b<take;b++) begin
                        if(p==0) beat[MEM_DATA_W-1-b*8-:8]=alternate?
                            a_alt_cipher[rr[p]][8*(lengths[p]-1-pos[p]-b)+:8]:a_cipher[rr[p]][8*(lengths[p]-1-pos[p]-b)+:8];
                        else beat[MEM_DATA_W-1-b*8-:8]=alternate?
                            b_alt_cipher[rr[p]][8*(lengths[p]-1-pos[p]-b)+:8]:b_cipher[rr[p]][8*(lengths[p]-1-pos[p]-b)+:8];
                        if(fault[p]==2&&pos[p]+b==lengths[p]-1) beat[MEM_DATA_W-1-b*8-:8]^=8'h80;
                    end
                    byte_mask=keep_for(take);
                    if(fault[p]==8&&pos[p]==0) byte_mask=0;
                    load_data[p]=beat;load_keep[p]=byte_mask;
                    load_last[p]=pos[p]+take==lengths[p]&&fault[p]!=9;
                    load_data_valid[p]=1;
                end
            end
            @(posedge clk);
            input_fire=load_data_valid&load_data_ready;
            commit_fire=dut.commit_valid&dut.commit_ready;
            for(int p=0;p<2;p++) begin
                if(!finished[p]) begin
                    check_input_row(p,rr[p]);
                    ck(!config_ready,"active input record blocks reconfiguration");
                    if(expected_error[p]!=0) ck(!commit_fire[p],"rejected ciphertext never commits data or tenant metadata");
                    if(commit_fire[p]) begin
                        ck(!seen_commit[p]&&expected_error[p]==0,"exactly one atomic commit per authenticated row");
                        ck(dut.commit_destination[p]===64'(rr[p]),"committed destination comes from captured trusted command");
                        ck(dut.commit_tenant[p]===(p==0?tenant[1+rr[p]%2]:96'b0),"committed ownership comes from authenticated record");
                        seen_commit[p]=1;
                    end
                    if(load_result_valid[p]) begin
                        ck(load_result_error[p]===4'(expected_error[p]),$sformatf("load port%0d fault%0d expected error%0d got%0d",p,fault[p],expected_error[p],load_result_error[p]));
                        if(expected_error[p]==0) ck(seen_commit[p],"successful load status follows complete row commit");
                        ck(stage_erased[p]&&crypto_private_erased[p],"terminal load status retains no staged plaintext or captured key");
                        if(load_result_ready[p]) begin
                            finished[p]=1;
                            if(expected_error[p]==0) loads++;else rejected_loads++;
                        end
                    end
                    if(input_fire[p]) pos[p]+=lengths[p]-pos[p]<BYTES?lengths[p]-pos[p]:BYTES;
                end
            end
            #2;
            for(int p=0;p<2;p++) begin
                if(commit_fire[p]) begin
                    if(p==0) begin
                        a_loaded[rr[p]]=1;
                        for(int c=0;c<MAX_K;c++) begin
                            a_model[rr[p]][c]=0;
                            if(c<k) a_model[rr[p]][c]=alternate?a_alt_plain[rr[p]][DATA_WIDTH*(k-1-c)+:DATA_WIDTH]:a_plain[rr[p]][DATA_WIDTH*(k-1-c)+:DATA_WIDTH];
                        end
                    end else begin
                        b_loaded[rr[p]]=1;
                        for(int c=0;c<MAX_N;c++) begin
                            b_model[rr[p]][c]=0;
                            if(c<n) b_model[rr[p]][c]=alternate?b_alt_plain[rr[p]][DATA_WIDTH*(n-1-c)+:DATA_WIDTH]:b_plain[rr[p]][DATA_WIDTH*(n-1-c)+:DATA_WIDTH];
                        end
                    end
                    check_input_row(p,rr[p]);
                end
            end
            load_data_valid&=~input_fire;
            cancelled_now=0;
            if(cancel_port>=0&&!did_cancel) begin
                cancelled_now=(cancel_phase==1&&steps==2)||
                    (cancel_phase==2&&pos[cancel_port]>0)||
                    (cancel_phase==3&&((cancel_port==0&&dut.g_load[0].stage.received_reg>0)||
                                                       (cancel_port==1&&dut.g_load[1].stage.received_reg>0)));
            end
            if(cancelled_now) begin
                ck(mask==(2'b01<<cancel_port),"directed stage cancellation has one active input stream");
                ck(!seen_commit[cancel_port],"staging cancellation occurs before atomic row commit");
                @(negedge clk);clear[cancel_port]=1;load_data_valid=0;load_result_ready=0;
                #1;ck(!load_ready[cancel_port]&&!load_data_ready[cancel_port]&&!load_result_valid[cancel_port],"input clear immediately cancels all record handshakes");
                @(posedge clk);#2;
                ck(stage_erased[cancel_port]&&crypto_private_erased[cancel_port],"input cancellation zeroizes authenticated staging and private key");
                check_input_row(cancel_port,rr[cancel_port]);
                @(negedge clk);clear=0;
                finished[cancel_port]=1;did_cancel=1;
            end
            steps++;ck(steps<10000,"input record makes bounded progress");
        end
        if(cancel_port>=0) ck(did_cancel,"requested authenticated staging cancellation phase reached");
        @(negedge clk);load_valid=0;load_data_valid=0;load_result_ready=0;
        @(posedge clk);#2;check_inputs();
    endtask

    task automatic load_whole_job();
        for(int r=0;r<k||r<m;r++)
            load_records({1'(r<k),1'(r<m)},r<m?r:0,r<k?r:0,0,0,0,-1,0);
    endtask

    // outcome: 0 matching successful acknowledgement, 1 storage failure,
    // 2 clear while waiting for ACK. All attempts validate complete independent
    // EVP ciphertext/header, including retries at their newly consumed nonce.
    task automatic store_attempt(input int row_number,input int outcome,input logic [COOKIE_W-1:0] stale_cookie,
        input bit use_stale_cookie,output logic [COOKIE_W-1:0] seen_cookie);
        int pos,take,steps,data_holds,header_holds,result_holds;
        int nonce_for_attempt;
        logic [MEM_DATA_W-1:0] prior_data;
        logic [BYTES-1:0] prior_keep;
        logic prior_last,stalled_data,stalled_header;
        logic [255:0] prior_header;
        logic [COOKIE_W-1:0] prior_cookie;
        logic [7:0] expected_byte;
        bit header_done,attempt_seen,finished;
        pos=0;steps=0;data_holds=0;header_holds=0;result_holds=0;
        stalled_data=0;stalled_header=0;header_done=0;attempt_seen=0;finished=0;
        seen_cookie=0;nonce_for_attempt=-1;
        while(!header_done) begin
            @(negedge clk);
            if(store_valid) data_holds++;
            if(store_header_valid) header_holds++;
            store_ready=data_holds>8&&(random_word()%4!=0);
            store_header_ready=header_holds>7;
            store_ack_valid=0;store_result_ready=0;
            @(posedge clk);
            ck(!security_fault&&!job_error,"trusted numerical compute and output provenance remain valid");
            ck(!done,"job completion cannot precede successful storage acknowledgement");
            if(store_valid||store_header_valid||store_ack_ready) begin
                if(!attempt_seen) begin
                    ck(active_row==row_number&&active_nonce>=0&&active_nonce<COUNTERS,"output attempt maps to expected protected row and bounded oracle nonce");
                    nonce_for_attempt=active_nonce;seen_cookie=active_cookie;attempt_seen=1;
                end
                ck(store_row===M_WIDTH'(row_number)&&store_bytes===32'(n*ACC_BYTES)&&store_cookie===seen_cookie,"output record context is captured row/length/cookie");
                check_c_row(row_number,0);
            end
            if(stalled_data)
                ck(store_valid&&store_data===prior_data&&store_keep===prior_keep&&store_last===prior_last&&store_cookie===prior_cookie,
                    "stalled ciphertext and record context remain stable");
            if(stalled_header)
                ck(store_header_valid&&store_header===prior_header&&store_cookie===prior_cookie,"stalled header and cookie remain stable");
            if(store_valid&&store_ready) begin
                ck(pos<n*ACC_BYTES,"ciphertext contains no duplicate or excess output beat");
                take=n*ACC_BYTES-pos<BYTES?n*ACC_BYTES-pos:BYTES;
                ck(store_keep===keep_for(take)&&store_last===(pos+take==n*ACC_BYTES),"ciphertext keep and last match configured row byte length");
                for(int b=0;b<BYTES;b++) begin
                    expected_byte=0;
                    if(b<take) expected_byte=c_cipher[row_number][nonce_for_attempt][8*(n*ACC_BYTES-1-pos-b)+:8];
                    ck(store_data[MEM_DATA_W-1-b*8-:8]===expected_byte,$sformatf("OpenSSL encrypted matrix byte%0d row%0d expected%02h got%02h",pos+b,row_number,expected_byte,store_data[MEM_DATA_W-1-b*8-:8]));
                end
                pos+=take;
            end
            if(store_header_valid) begin
                ck(pos==n*ACC_BYTES,"record header is offered only after every tentative ciphertext byte was consumed");
                ck(store_header===c_header[row_number][nonce_for_attempt],"OpenSSL output header authenticates signed matrix result and row metadata");
                ck(dut.plain_reg==={MEM_DATA_W{1'b0}}&&crypto_private_erased[2],"plaintext serializer and private encryption context erased before publishing header");
                if(store_header_ready) header_done=1;
            end
            stalled_data=store_valid&&!store_ready;stalled_header=store_header_valid&&!store_header_ready;
            prior_data=store_data;prior_keep=store_keep;prior_last=store_last;prior_header=store_header;prior_cookie=store_cookie;
            #2;steps++;ck(steps<20000,"matrix compute and encryption make bounded progress");
        end
        @(negedge clk);store_ready=0;store_header_ready=0;
        // A wrong completion is consumed/ignored and cannot act on this row.
        repeat(5) begin
            store_ack_valid=1;store_ack_success=1;
            store_ack_cookie=use_stale_cookie?stale_cookie:~seen_cookie;
            #1;ck(store_ack_ready,"record waits for a trusted durable-storage acknowledgement");
            @(posedge clk);#2;
            check_c_row(row_number,0);
            ck(store_ack_ready&&!store_result_valid&&!done,"mismatched storage cookie cannot retire row");
            @(negedge clk);
        end
        store_ack_valid=0;
        // Merely waiting after header publication cannot acknowledge storage.
        repeat(6) begin
            @(posedge clk);#2;check_c_row(row_number,0);
            ck(store_ack_ready&&!done,"delayed storage acknowledgement retains whole plaintext row");
            @(negedge clk);
        end
        if(outcome==2) begin
            clear[2]=1;
            #1;ck(!store_ack_ready&&!store_result_valid&&!store_header_valid&&!store_valid,"output clear immediately suppresses cancelled record and ACK");
            @(posedge clk);#2;
            check_c_row(row_number,0);
            ck(dut.plain_reg==={MEM_DATA_W{1'b0}}&&dut.header_reg===0&&crypto_private_erased[2],"output clear wipes tentative record but retains protected output row");
            @(negedge clk);clear=0;
        end else begin
            store_ack_valid=1;store_ack_success=outcome==0;store_ack_cookie=seen_cookie;
            #1;ck(store_ack_ready,"matching storage acknowledgement accepted");
            @(posedge clk);#2;
            if(outcome==0) begin
                retired[row_number]=1;stored_rows++;check_c_row(row_number,1);
            end else check_c_row(row_number,0);
            @(negedge clk);store_ack_valid=0;
            while(!finished) begin
                store_result_ready=result_holds>5;
                @(posedge clk);
                ck(store_result_valid&&store_result_error===4'(outcome==0?0:8),"storage outcome is held with exact success/failure status");
                if(store_result_ready) finished=1;
                result_holds++;
                #2;
                if(!finished) begin
                    check_c_row(row_number,outcome==0);
                    @(negedge clk);
                end
            end
            @(negedge clk);store_result_ready=0;
        end
    endtask
