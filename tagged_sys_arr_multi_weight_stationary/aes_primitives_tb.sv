`timescale 1ns/1ps
// Independent arithmetic oracle: polynomial GF(2^8) multiplication and
// exponentiation/affine S-box, rather than the RTL's lookup table/xtime path.
module aes_primitives_tb;
    import aes_primitives::*;
    logic [255:0] key256;
    logic [127:0] key128;
    wire [127:0] window128[0:10], round128[1:10];
    wire [255:0] window256[0:14];
    wire [127:0] round256[1:14];
    logic [31:0] words[0:59];
    logic [31:0] rng=32'hf021947d;
    int checks=0;
    assign window128[0]=key128;
    assign window256[0]=key256;
    for(genvar r=1;r<=10;r++) begin
        aes_key_expand #(.AES_KEY_W(128),.ROUND(r)) k
            (window128[r-1],window128[r],round128[r]);
    end
    for(genvar r=1;r<=14;r++) begin
        aes_key_expand #(.AES_KEY_W(256),.ROUND(r)) k
            (window256[r-1],window256[r],round256[r]);
    end
    function automatic [7:0] mul8(input logic [7:0] a,b);
        logic [15:0] p;
        p=0;
        for(int i=0;i<8;i++) if(b[i]) p^=({8'b0,a}<<i);
        for(int i=14;i>=8;i--) if(p[i]) p^=(16'h11b<<(i-8));
        return p[7:0];
    endfunction
    function automatic [7:0] sub8(input logic [7:0] a);
        logic [7:0] inverse,result;
        inverse=1;
        for(int n=0;n<254;n++) inverse=mul8(inverse,a);
        for(int i=0;i<8;i++) result[i]=inverse[i]^inverse[(i+4)%8]^
            inverse[(i+5)%8]^inverse[(i+6)%8]^inverse[(i+7)%8]^((8'h63>>i)&1);
        return result;
    endfunction
    function automatic [31:0] subword(input logic [31:0] w);
        return {sub8(w[31:24]),sub8(w[23:16]),sub8(w[15:8]),sub8(w[7:0])};
    endfunction
    function automatic [31:0] random_word();
        rng^=rng<<13; rng^=rng>>17; rng^=rng<<5;
        return rng;
    endfunction
    task automatic ck(input logic ok,input string label_text);
        if(ok!==1'b1) $fatal(1,"AES primitives: %s",label_text);
        checks++;
    endtask
    initial begin
        logic [127:0] value,expected,shifted;
        logic [7:0] rc,a,b,c,d;
        logic [31:0] t;
        for(int byte_value=0;byte_value<256;byte_value++) begin
            ck(aes_sbox(8'(byte_value))===sub8(8'(byte_value)),"exhaustive S-box");
            ck(aes_xtime(8'(byte_value))===mul8(8'(byte_value),2),"exhaustive xtime");
        end
        for(int bit_index=0;bit_index<128;bit_index++) begin
            value=128'b1<<bit_index;
            for(int col=0;col<4;col++) for(int row=0;row<4;row++)
                shifted[127-8*(col*4+row)-:8]=value[127-8*(((col+row)%4)*4+row)-:8];
            ck(aes_shift_rows(value)===shifted,"ShiftRows basis bit mapping");
            for(int col=0;col<4;col++) begin
                {a,b,c,d}=value[127-32*col-:32];
                expected[127-32*col-:32]={mul8(a,2)^mul8(b,3)^c^d,
                    a^mul8(b,2)^mul8(c,3)^d,a^b^mul8(c,2)^mul8(d,3),
                    mul8(a,3)^b^c^mul8(d,2)};
            end
            ck(aes_mix_columns(value)===expected,"MixColumns independent polynomial basis");
        end
        for(int iteration=0;iteration<24;iteration++) begin
            for(int w=0;w<8;w++) key256[255-32*w-:32]=random_word();
            key128=key256[127:0];
            #1;
            for(int nk=4;nk<=8;nk+=4) begin
                for(int w=0;w<nk;w++) words[w]=(nk==4)?key128[127-32*w-:32]:key256[255-32*w-:32];
                rc=1;
                for(int w=nk;w<4*(nk+7);w++) begin
                    t=words[w-1];
                    if(w%nk==0) begin t=subword({t[23:0],t[31:24]})^{rc,24'b0}; rc=mul8(rc,2); end
                    else if(nk==8 && w%8==4) t=subword(t);
                    words[w]=words[w-nk]^t;
                end
                for(int r=1;r<=nk+6;r++) begin
                    expected={words[4*r],words[4*r+1],words[4*r+2],words[4*r+3]};
                    ck(((nk==4)?round128[r]:round256[r])===expected,"all expanded round keys");
                    if(nk==4) ck(window128[r]===expected,"AES128 rolling window");
                    else ck(window256[r]==={words[4*r-4],words[4*r-3],words[4*r-2],words[4*r-1],expected},"AES256 rolling window");
                end
            end
        end
        $display("PASS: AES primitives %0d checks, exhaustive S-box/xtime, 128 basis states, 48 complete schedules",checks);
        $finish;
    end
    initial begin #100000; $fatal(1,"AES primitive timeout"); end
endmodule
