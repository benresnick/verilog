`timescale 1ns/1ps
// Scoreboards model stored words/validity independently of DUT arrays.
module buffers_stress_tb #(
    parameter int R=3,C=5,P=3,DW=8,AW=16,
    parameter int RW=(R<=1)?1:$clog2(R), CW=(C<=1)?1:$clog2(C)
);
    logic clk=0,reset=1,clear_valids=0,we=0,final_in=0;
    logic [RW-1:0] wr,rr;
    logic [CW-1:0] wc,rc;
    logic signed [DW-1:0] d;
    logic signed [AW-1:0] od;
    wire signed [DW-1:0] idata;
    wire signed [AW-1:0] odata;
    wire iv,ov,ofinal;
    logic mwe[0:P-1],mf[0:P-1];
    logic [RW-1:0] mwr[0:P-1],mrr[0:P];
    logic [CW-1:0] mwc[0:P-1],mrc[0:P];
    logic signed [AW-1:0] mwd[0:P-1];
    wire signed [AW-1:0] mrd[0:P];
    wire mv[0:P],mfinal[0:P];
    wire signed [DW-1:0] multi_data[0:P];
    logic signed [DW-1:0] im[0:R-1][0:C-1],mrmodel[0:R-1][0:C-1];
    logic signed [AW-1:0] om[0:R-1][0:C-1],mm[0:R-1][0:C-1];
    bit vi[0:R-1][0:C-1],vo[0:R-1][0:C-1],fo[0:R-1][0:C-1];
    bit vm[0:R-1][0:C-1],fm[0:R-1][0:C-1],mrknown[0:R-1][0:C-1];
    logic [31:0] rng=32'h22cad301;
    int checks=0,collisions=0;
    always #5 clk=~clk;
    matrix_input_buffer #(.ROWS(R),.COLS(C),.DATA_WIDTH(DW)) ib
        (clk,reset,we,wr,wc,d,rr,rc,idata,iv);
    matrix_output_buffer #(.ROWS(R),.COLS(C),.ACC_WIDTH(AW)) ob
        (clk,reset,clear_valids,we,wr,wc,od,final_in,rr,rc,odata,ov,ofinal);
    multi_read_matrix_buffer #(.ROWS(R),.COLS(C),.DATA_WIDTH(DW),.READ_PORTS(P+1)) mr
        (clk,we,wr,wc,d,mrr,mrc,multi_data);
    multi_write_output_buffer #(.ROWS(R),.COLS(C),.ACC_WIDTH(AW),.WRITE_PORTS(P),.READ_PORTS(P+1)) mo
        (clk,reset,clear_valids,mwe,mwr,mwc,mwd,mf,mrr,mrc,mrd,mv,mfinal);
    function automatic [31:0] random_word();rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;endfunction
    task automatic ck(input logic ok,input string what);
        if(ok!==1'b1)$fatal(1,"buffers R=%0d C=%0d P=%0d check=%0d: %s",R,C,P,checks,what);checks++;
    endtask
    initial begin
        wr=0;wc=0;rr=0;rc=0;d=0;od=0;
        for(int p=0;p<P;p++)begin mwe[p]=0;mwr[p]=0;mwc[p]=0;mwd[p]=0;mf[p]=0;end
        for(int p=0;p<=P;p++)begin mrr[p]=0;mrc[p]=0;end
        for(int n=0;n<600;n++)begin
            @(negedge clk);
            reset=(n==0||n%97==0);clear_valids=(n%31==0);
            we=(random_word()%4!=0);wr=random_word()%R;wc=random_word()%C;
            d=random_word();od=random_word();final_in=random_word();
            for(int p=0;p<P;p++)begin
                mwe[p]=random_word()%4!=0;mwr[p]=random_word()%R;mwc[p]=random_word()%C;
                mwd[p]=random_word();mf[p]=random_word();
                if(n%11==0)begin mwe[p]=1;mwr[p]=0;mwc[p]=0;end
            end
            if(n%11==0)collisions++;
            @(posedge clk);
            if(we)begin mrmodel[wr][wc]=d;mrknown[wr][wc]=1;end
            if(reset)for(int r=0;r<R;r++)for(int c=0;c<C;c++)vi[r][c]=0;
            else if(we)begin im[wr][wc]=d;vi[wr][wc]=1;end
            if(reset||clear_valids)begin
                for(int r=0;r<R;r++)for(int c=0;c<C;c++)begin vo[r][c]=0;fo[r][c]=0;vm[r][c]=0;fm[r][c]=0;end
            end else begin
                if(we)begin om[wr][wc]=od;vo[wr][wc]=1;fo[wr][wc]=final_in;end
                // Documented loop ordering: highest port wins a collision.
                for(int p=0;p<P;p++)if(mwe[p])begin
                    mm[mwr[p]][mwc[p]]=mwd[p];vm[mwr[p]][mwc[p]]=1;fm[mwr[p]][mwc[p]]=mf[p];
                end
            end
            #1;
            // Visit every cell; all read ports also exercise aliasing and
            // distinct asynchronous addresses in the same cycle.
            for(int r=0;r<R;r++)for(int c=0;c<C;c++)begin
                rr=r;rc=c;
                for(int p=0;p<=P;p++)begin mrr[p]=(r+p)%R;mrc[p]=(c+p)%C;end
                #0.01;
                ck(iv===vi[r][c],"IBuff validity");if(vi[r][c])ck(idata===im[r][c],"IBuff signed data");
                ck(ov===vo[r][c]&&ofinal===fo[r][c],"OBuff validity/finality");
                if(vo[r][c])ck(odata===om[r][c],"OBuff partial/final replacement");
                for(int p=0;p<=P;p++)begin
                    if(mrknown[mrr[p]][mrc[p]])ck(multi_data[p]===mrmodel[mrr[p]][mrc[p]],"multi-read coherence");
                    ck(mv[p]===vm[mrr[p]][mrc[p]]&&mfinal[p]===fm[mrr[p]][mrc[p]],"multi-write validity/finality");
                    if(mv[p])ck(mrd[p]===mm[mrr[p]][mrc[p]],"multi-write arbitration/data");
                end
            end
        end
        ck(collisions>0,"collision coverage");
        $display("PASS: all four buffers R=%0d C=%0d P=%0d %0d checks, %0d collision cycles",R,C,P,checks,collisions);$finish;
    end
    initial begin #100000; $fatal(1,"buffer stress timeout");end
endmodule
