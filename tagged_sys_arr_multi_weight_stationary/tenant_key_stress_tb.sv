`timescale 1ns/1ps
module tenant_key_stress_tb #(
    parameter int S=5,K=256,L=3,SW=(S<=1)?1:$clog2(S)
);
    logic clk=0,reset=1,provision_valid,invalidate_valid,reserve_iv_valid;
    logic [SW-1:0] provision_slot,invalidate_slot,reserve_iv_slot;
    logic [95:0] provision_tenant_id,lookup_tenant_id[0:L-1];
    logic [K-1:0] provision_key;
    logic [31:0] provision_iv_fixed_field;
    logic [63:0] provision_counter_start;
    logic slot_busy[0:S-1];
    wire provision_ready,provision_error,invalidate_ready,reserve_iv_grant,nonce_exhausted;
    wire [95:0] reserved_iv;
    wire lookup_found[0:L-1],lookup_duplicate[0:L-1];
    wire [K-1:0] lookup_key[0:L-1];
    wire [SW-1:0] lookup_slot[0:L-1];
    bit valid[0:S-1];
    logic [95:0] tenant[0:S-1];
    logic [K-1:0] key[0:S-1];
    logic [31:0] fixed_field[0:S-1];
    logic [63:0] counter[0:S-1];
    logic [31:0] rng=32'h1273aacd;
    int checks=0,grants=0,writes=0,invalidates=0,rejections=0;
    always #5 clk=~clk;
    tenant_key_regfile #(.AES_KEY_W(K),.NUM_KEY_SLOTS(S),.LOOKUP_PORTS(L)) dut(.*);
    function automatic [31:0] rand32();rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;endfunction
    task automatic ck(input logic ok,input string label_text);
        if(ok!==1'b1)$fatal(1,"key stress S=%0d K=%0d L=%0d check=%0d: %s",S,K,L,checks,label_text);checks++;
    endtask
    initial begin
        bit pr,ir,grant,exhausted,pa,ia;
        int chosen,match_slot,match_count;
        logic [95:0] expected_iv;
        for(int n=0;n<1200;n++)begin
            @(negedge clk);
            reset=(n==0 || n%173==0);
            provision_valid=(rand32()%3==0);invalidate_valid=(rand32()%7==0);reserve_iv_valid=rand32()%4!=0;
            provision_slot=rand32();invalidate_slot=rand32();reserve_iv_slot=rand32();
            provision_tenant_id=96'(n+1);provision_key=K'(n+1);provision_iv_fixed_field=n+1;provision_counter_start=0;
            chosen=rand32()%S;
            case(n%9)
                0:provision_tenant_id=tenant[chosen]; // duplicate tenant attempt
                1:begin provision_key=key[chosen];provision_iv_fixed_field=fixed_field[chosen];end
                2:begin // legal forward movement or rejected rollback of live sequence
                    provision_slot=chosen;provision_key=key[chosen];provision_iv_fixed_field=fixed_field[chosen];
                    provision_tenant_id=tenant[chosen];
                    provision_counter_start=counter[chosen]+((n%2)?1:-1);
                end
                3:provision_counter_start=64'hffff_ffff_ffff_fffe;
            endcase
            if(n%13==0)begin provision_slot=chosen;invalidate_slot=chosen;reserve_iv_slot=chosen;provision_valid=1;invalidate_valid=1;reserve_iv_valid=1;end
            for(int s=0;s<S;s++)slot_busy[s]=rand32()%5==0;
            for(int p=0;p<L;p++)begin
                chosen=rand32()%S;
                lookup_tenant_id[p]=(n%5==0)?96'(20000+p):tenant[chosen];
            end
            // Reference protocol decision uses only the abstract entry model,
            // never DUT grants/readbacks as input to the expected result.
            ir=!reset && invalidate_slot<S;
            if(ir)ir=!slot_busy[invalidate_slot];
            ia=ir&&invalidate_valid;
            pr=!reset && provision_slot<S;
            if(pr)begin
                pr=!slot_busy[provision_slot] && !(ia&&invalidate_slot==provision_slot);
                for(int s=0;s<S;s++)if(valid[s])begin
                    if(s!=provision_slot && (tenant[s]==provision_tenant_id ||
                        (key[s]==provision_key && fixed_field[s]==provision_iv_fixed_field)))pr=0;
                    if(s==provision_slot && key[s]==provision_key && fixed_field[s]==provision_iv_fixed_field && provision_counter_start<counter[s])pr=0;
                end
            end
            pa=pr&&provision_valid;
            grant=!reset && reserve_iv_valid && reserve_iv_slot<S;
            exhausted=0;expected_iv=0;
            if(grant)begin
                grant=valid[reserve_iv_slot]&&!slot_busy[reserve_iv_slot]&&
                    !(ia&&invalidate_slot==reserve_iv_slot)&&!(pa&&provision_slot==reserve_iv_slot);
                if(grant)begin
                    exhausted=counter[reserve_iv_slot]==64'hffff_ffff_ffff_ffff;
                    grant=!exhausted;
                    if(grant)expected_iv={fixed_field[reserve_iv_slot],counter[reserve_iv_slot]};
                end
            end
            #1;
            ck(provision_ready===pr && provision_error===(!reset&&provision_valid&&!pr),"provision result match_count independent model");
            ck(invalidate_ready===ir,"invalidation eligibility");
            ck(reserve_iv_grant===grant&&nonce_exhausted===exhausted&&reserved_iv===expected_iv,"IV atomic reservation/exhaustion");
            for(int p=0;p<L;p++)begin
                match_count=0;match_slot=0;
                if(!reset)for(int s=0;s<S;s++)if(valid[s]&&tenant[s]==lookup_tenant_id[p])begin match_count++;match_slot=s;end
                if((ia&&invalidate_slot==match_slot)||(pa&&provision_slot==match_slot))match_count=0;
                ck(lookup_found[p]===(match_count==1)&&!lookup_duplicate[p],"concurrent lookup match count");
                ck(lookup_key[p]===((match_count==1)?key[match_slot]:K'(0)),"lookup key capture versus mutation");
                ck(lookup_slot[p]===((match_count==1)?SW'(match_slot):SW'(0)),"lookup slot qualification");
            end
            @(posedge clk);
            if(reset)for(int s=0;s<S;s++)begin valid[s]=0;tenant[s]=0;key[s]=0;fixed_field[s]=0;counter[s]=0;end
            else begin
                if(pa)begin valid[provision_slot]=1;tenant[provision_slot]=provision_tenant_id;key[provision_slot]=provision_key;fixed_field[provision_slot]=provision_iv_fixed_field;counter[provision_slot]=provision_counter_start;writes++;end
                if(ia)begin valid[invalidate_slot]=0;tenant[invalidate_slot]=0;key[invalidate_slot]=0;fixed_field[invalidate_slot]=0;counter[invalidate_slot]=0;invalidates++;end
                if(grant)begin counter[reserve_iv_slot]++;grants++;end
                if(provision_valid&&!pr)rejections++;
            end
            #1;
            for(int s=0;s<S;s++)ck(dut.valid[s]===valid[s]&&dut.tenant_id[s]===tenant[s]&&dut.aes_key[s]===key[s]&&dut.iv_fixed[s]===fixed_field[s]&&dut.invocation_counter[s]===counter[s],"complete state conservation/zeroization");
        end
        ck(grants>20 && writes>20 && invalidates>20 && rejections>20,"stress exercises all operation classes");
        $display("PASS: key stress S=%0d K=%0d L=%0d %0d checks, writes=%0d invalidate=%0d reserve=%0d rejected=%0d",S,K,L,checks,writes,invalidates,grants,rejections);$finish;
    end
    initial begin #100000; $fatal(1,"key stress timeout");end
endmodule
