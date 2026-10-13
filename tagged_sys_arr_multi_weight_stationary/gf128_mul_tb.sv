`timescale 1ns/1ps
module gf128_mul_tb;
    logic [127:0] x,y;
    wire [127:0] product;
    logic [31:0] rng=32'h80d189bf;
    int checked=0;
    gf128_mul dut(.*);
    function automatic [127:0] reference_mul(input logic [127:0] a,b);
        logic [255:0] p;
        logic [127:0] ar,br,result;
        for(int i=0;i<128;i++) begin ar[i]=a[127-i];br[i]=b[127-i];end
        p=0;
        for(int i=0;i<128;i++) if(ar[i]) p^=({128'b0,br}<<i);
        for(int i=254;i>=128;i--) if(p[i]) p^=(256'h100000000000000000000000000000087<<(i-128));
        for(int i=0;i<128;i++) result[i]=p[127-i];
        return result;
    endfunction
    function automatic [127:0] random_block();
        for(int w=0;w<4;w++) begin
            rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;
            random_block[32*w+:32]=rng;
        end
    endfunction
    task automatic check_product(input logic [127:0] a,b);
        x=a;y=b;#1;
        if(product!==reference_mul(a,b)) $fatal(1,"GF128 independent product mismatch at case %0d",checked);
        checked++;
    endtask
    initial begin
        logic [127:0] a,b,c,ab,ac;
        // Every pair of polynomial basis vectors exercises every reduction
        // degree and both input positions, not just a random sample.
        for(int i=0;i<128;i++) for(int j=0;j<128;j++)
            check_product(128'b1<<i,128'b1<<j);
        for(int i=0;i<256;i++) begin
            a=random_block();b=random_block();c=random_block();
            check_product(a,b);ab=product;
            check_product(b,a);
            if(product!==ab) $fatal(1,"GF128 commutativity");
            check_product(a,c);ac=product;
            check_product(a,b^c);
            if(product!==(ab^ac)) $fatal(1,"GF128 distributivity");
            check_product(a,0);
            check_product(a,128'h80000000000000000000000000000000);
            if(product!==a) $fatal(1,"GF128 identity");
        end
        $display("PASS: GF128 %0d independent products (all 16384 basis pairs and 256 random algebra cases)",checked);
        $finish;
    end
    initial begin #100000; $fatal(1,"GF128 timeout"); end
endmodule
