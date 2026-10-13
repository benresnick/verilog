`timescale 1ns/1ps
// Direct array test uses a mathematical column dot-product oracle. Controller
// tests separately check transient skew, tiling, and output transaction order.
module sysarr_stress_tb #(
    parameter int R=3,C=5,W=3,DW=8,AW=16,
    parameter int SW=(W<=1)?1:$clog2(W),RW=(R<=1)?1:$clog2(R)
);
    logic clk=0,reset=1,weight_load=0;
    logic signed [DW-1:0] activation_in[0:R-1],weight_in[0:C-1];
    logic activation_valid_in[0:R-1],weight_valid_in[0:C-1],psum_valid_in[0:C-1];
    logic [SW-1:0] weight_slot_in[0:C-1],selected_slot;
    logic [RW-1:0] weight_target_row_in[0:C-1];
    logic signed [AW-1:0] psum_in[0:C-1];
    wire signed [AW-1:0] psum_out[0:C-1];
    wire psum_valid_out[0:C-1];
    logic signed [DW-1:0] weights[0:W-1][0:R-1][0:C-1];
    logic [31:0] rng=32'hcb48913a;
    int checks=0;
    always #5 clk=~clk;
    sysarr #(.ROWS(R),.COLS(C),.WEIGHTS_PER_PE(W),.DATA_WIDTH(DW),.ACC_WIDTH(AW)) dut(.*);
    function automatic [31:0] rand32();rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;endfunction
    task automatic tick();@(posedge clk);#1;@(negedge clk);endtask
    initial begin
        longint signed sum;
        logic signed [AW-1:0] expected;
        selected_slot=0;
        for(int r=0;r<R;r++)begin activation_in[r]=0;activation_valid_in[r]=0;end
        for(int c=0;c<C;c++)begin weight_in[c]=0;weight_valid_in[c]=0;weight_slot_in[c]=0;weight_target_row_in[c]=0;psum_in[c]=0;psum_valid_in[c]=0;end
        tick();reset=0;
        for(int trial=0;trial<8;trial++)begin
            weight_load=1;
            for(int bank=0;bank<W;bank++)for(int r=R-1;r>=0;r--)begin
                for(int c=0;c<C;c++)begin
                    weights[bank][r][c]=rand32();weight_in[c]=weights[bank][r][c];
                    weight_slot_in[c]=bank;weight_target_row_in[c]=r;weight_valid_in[c]=1;
                end
                tick();
            end
            // Bottom-first tokens all reach their target rows on the final
            // load edge of each bank; every local bank now has known weights.
            weight_load=0;
            for(int bank=0;bank<W;bank++)begin
                selected_slot=bank;
                for(int r=0;r<R;r++)begin activation_in[r]=rand32();activation_valid_in[r]=1;end
                for(int c=0;c<C;c++)begin psum_in[c]=rand32();psum_valid_in[c]=1;end
                repeat(R+C+2)tick();
                for(int c=0;c<C;c++)begin
                    sum=$signed(psum_in[c]);
                    for(int r=0;r<R;r++)sum+=$signed(activation_in[r])*$signed(weights[bank][r][c]);
                    expected=sum;
                    if(psum_valid_out[c]!==1'b1 || psum_out[c]!==expected)
                        $fatal(1,"array mathematical dot product R=%0d C=%0d W=%0d trial=%0d bank=%0d col=%0d",R,C,W,trial,bank,c);
                    checks++;
                end
            end
            reset=1;weight_load=1;tick();
            for(int c=0;c<C;c++)if(psum_valid_out[c] || psum_out[c]!==0)$fatal(1,"array reset priority");
            reset=0;weight_load=0;
        end
        $display("PASS: array R=%0d C=%0d W=%0d AW=%0d %0d independent column dot products",R,C,W,AW,checks);$finish;
    end
    initial begin #100000; $fatal(1,"array stress timeout");end
endmodule
