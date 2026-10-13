`timescale 1ns/1ps
module secure_tags_stress_tb #(
    parameter int R=3,C=5,TW=96,P=3,
    parameter int RW=(R<=1)?1:$clog2(R),CW=(C<=1)?1:$clog2(C)
);
    logic clk=0,reset=1,flush=0,advance=0,in_valid=0;
    logic [TW-1:0] in_tag,incoming_tag,stored_tag;
    logic incoming_valid,has_prior,stored_valid;
    wire resolved_valid,fault,empty;
    wire [TW-1:0] resolved_tag,tap_tag[0:C-1];
    wire tap_valid[0:C-1];
    logic clear_valids,write_enable[0:P-1];
    logic [RW-1:0] write_row[0:P-1],read_row[0:P];
    logic [CW-1:0] write_col[0:P-1],read_col[0:P];
    logic [TW-1:0] write_tag[0:P-1];
    wire [TW-1:0] read_tag[0:P];
    wire read_valid[0:P];
    logic [TW-1:0] memory[0:R-1][0:C-1],history[0:599];
    bit valid[0:R-1][0:C-1],history_valid[0:599];
    logic [31:0] rng=32'h895abc12;
    int checks=0,issued=0;
    always #5 clk=~clk;
    shared_tag_queue #(.ROWS(R),.COLS(C),.TAG_WIDTH(TW)) q(.*);
    tag_policy_resolver #(.TAG_WIDTH(TW)) policy
        (incoming_valid,incoming_tag,has_prior,stored_valid,stored_tag,resolved_valid,resolved_tag,fault);
    secure_obuff_tag_store #(.ROWS(R),.COLS(C),.TAG_WIDTH(TW),.WRITE_PORTS(P)) store(.*);
    function automatic [95:0] random_tag();
        for(int w=0;w<3;w++)begin rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;random_tag[32*w+:32]=rng;end
    endfunction
    task automatic ck(input logic ok,input string label_text);
        if(ok!==1'b1)$fatal(1,"tag primitives R=%0d C=%0d TW=%0d check=%0d: %s",R,C,TW,checks,label_text);checks++;
    endtask
    initial begin
        int index;
        bit expected_empty,expected_valid;
        // Every validity combination, matching tags, high-bit-only mismatch,
        // low-bit mismatch, and zero/public tags.
        for(int bits=0;bits<8;bits++)for(int relation=0;relation<4;relation++)begin
            incoming_valid=bits[0];stored_valid=bits[1];has_prior=bits[2];
            incoming_tag=(relation==3)?'0:'1;
            stored_tag=incoming_tag;
            if(relation==1)stored_tag^=TW'(1);
            if(relation==2)stored_tag^=(TW'(1)<<(TW-1));
            #1;
            ck(fault===(has_prior && !(incoming_valid&&stored_valid&&incoming_tag==stored_tag)),"complete policy truth table");
            ck(resolved_valid===incoming_valid&&resolved_tag===incoming_tag,"resolver ownership output");
        end
        for(int p=0;p<P;p++)begin write_enable[p]=0;write_row[p]=0;write_col[p]=0;write_tag[p]=0;end
        for(int p=0;p<=P;p++)begin read_row[p]=0;read_col[p]=0;end
        for(int n=0;n<500;n++)begin
            @(negedge clk);
            reset=(n==0||n%107==0);flush=(n%37==0);clear_valids=(n%41==0);
            in_tag=random_tag();advance=(rng%4!=0);in_valid=rng[3];
            for(int p=0;p<P;p++)begin
                write_tag[p]=random_tag();write_row[p]=rng%R;write_col[p]=(rng>>8)%C;write_enable[p]=rng[4];
                if(n%13==0)begin write_enable[p]=1;write_row[p]=0;write_col[p]=0;end
            end
            @(posedge clk);
            if(reset||flush)issued=0;
            else if(advance)begin history[issued]=in_tag;history_valid[issued]=in_valid;issued++;end
            if(reset||clear_valids)for(int r=0;r<R;r++)for(int c=0;c<C;c++)begin valid[r][c]=0;memory[r][c]=0;end
            else for(int p=0;p<P;p++)if(write_enable[p])begin
                memory[write_row[p]][write_col[p]]=write_tag[p];valid[write_row[p]][write_col[p]]=1;
            end
            #1;
            expected_empty=1;
            for(int age=1;age<=R+C-1;age++)if(issued>=age && history_valid[issued-age])expected_empty=0;
            ck(empty===expected_empty,"queue occupancy from accepted-token history");
            for(int c=0;c<C;c++)begin
                index=issued-R-c;expected_valid=(index>=0)?history_valid[index]:0;
                ck(tap_valid[c]===expected_valid,"queue tap token age");
                if(expected_valid)ck(tap_tag[c]===history[index],"queue tag preserved through holds/bubbles");
                if(reset||flush)ck(tap_tag[c]===TW'(0),"flush zeroizes metadata");
            end
            for(int r=0;r<R;r++)for(int c=0;c<C;c++)begin
                for(int p=0;p<=P;p++)begin read_row[p]=(r+p)%R;read_col[p]=(c+p)%C;end
                #0.01;
                for(int p=0;p<=P;p++)begin
                    ck(read_valid[p]===valid[read_row[p]][read_col[p]],"store validity/clear priority");
                    ck(read_tag[p]===memory[read_row[p]][read_col[p]],"store concurrent data and zeroization");
                end
            end
        end
        $display("PASS: tag primitives R=%0d C=%0d TW=%0d %0d checks",R,C,TW,checks);$finish;
    end
    initial begin #100000; $fatal(1,"tag primitive timeout");end
endmodule
