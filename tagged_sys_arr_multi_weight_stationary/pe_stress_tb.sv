`timescale 1ns/1ps
module pe_stress_tb #(
    parameter int W=3, DW=8, AW=16,
    parameter int SW=(W<=1)?1:$clog2(W)
);
    logic clk=0,reset=1,weight_load,activation_valid_in,weight_valid_in,psum_valid_in;
    logic signed [DW-1:0] activation_in,weight_in;
    logic signed [AW-1:0] psum_in;
    logic [SW-1:0] selected_slot,weight_slot_in;
    logic [1:0] weight_target_row_in;
    wire signed [DW-1:0] activation_out,weight_out;
    wire signed [AW-1:0] psum_out;
    wire activation_valid_out,weight_valid_out,psum_valid_out;
    wire [SW-1:0] weight_slot_out;
    wire [1:0] weight_target_row_out;
    logic signed [DW-1:0] weights[0:W-1];
    bit valid[0:W-1];
    logic [31:0] rng=32'h579dde32;
    int checks=0;
    pe #(.DATA_WIDTH(DW),.ACC_WIDTH(AW),.WEIGHTS_PER_PE(W),.ROW_ID(1),.ROW_WIDTH(2)) dut(.*);
    always #5 clk=~clk;
    function automatic [31:0] random_word();
        rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;
    endfunction
    task automatic tick();
        logic signed [AW-1:0] expected;
        bit expect_valid;
        longint signed mathematical;
        expect_valid=!reset && !weight_load && psum_valid_in;
        mathematical=$signed(psum_in);
        if(selected_slot<W && valid[selected_slot] && activation_valid_in)
            mathematical += $signed(activation_in)*$signed(weights[selected_slot]);
        expected=mathematical; // Defined modular accumulator truncation.
        @(posedge clk);#1;
        if(psum_valid_out!==expect_valid) $fatal(1,"PE sum validity W=%0d case=%0d",W,checks);
        if(expect_valid && psum_out!==expected) $fatal(1,"PE signed modular MAC W=%0d case=%0d",W,checks);
        if(reset) begin
            for(int s=0;s<W;s++) begin valid[s]=0;weights[s]=0;end
            if(activation_valid_out || weight_valid_out || activation_out!==0 || weight_out!==0 || psum_out!==0)
                $fatal(1,"PE reset priority and zeroization");
        end else begin
            if(activation_out!==activation_in || activation_valid_out!==activation_valid_in ||
               weight_out!==weight_in || weight_valid_out!==weight_valid_in ||
               weight_slot_out!==weight_slot_in || weight_target_row_out!==weight_target_row_in)
                $fatal(1,"PE registered forwarding");
            if(weight_load && weight_target_row_in==1 && weight_slot_in<W) begin
                weights[weight_slot_in]=weight_in;valid[weight_slot_in]=weight_valid_in;
            end
        end
        checks++;
        @(negedge clk);
    endtask
    initial begin
        activation_in=0;weight_in=0;psum_in=0;weight_load=0;
        activation_valid_in=0;weight_valid_in=0;psum_valid_in=0;
        selected_slot=0;weight_slot_in=0;weight_target_row_in=1;
        tick();reset=0;
        // Exhaust every signed operand pair with a deliberately overflowing
        // nonzero psum and independently calculated modular sum.
        for(int w=0;w<2**DW;w++) begin
            weight_load=1;weight_valid_in=1;weight_in=DW'(w);tick();weight_load=0;
            for(int a=0;a<2**DW;a++) begin
                activation_in=DW'(a);activation_valid_in=1;psum_valid_in=1;
                psum_in={1'b0,{(AW-1){1'b1}}};tick();
            end
        end
        // Invalid banks/targets, invalid loads, reset with load+MAC asserted,
        // forwarding bubbles, and all per-bank overwrite transitions.
        for(int n=0;n<2000;n++) begin
            reset=(n%113==0);weight_load=(random_word()%3==0);
            weight_in=random_word();activation_in=random_word();psum_in=random_word();
            weight_slot_in=random_word();selected_slot=random_word();weight_target_row_in=random_word();
            weight_valid_in=random_word();activation_valid_in=random_word();psum_valid_in=random_word();tick();
        end
        $display("PASS: PE W=%0d DW=%0d AW=%0d %0d cycles; exhaustive %0d signed operand pairs",W,DW,AW,checks,2**(2*DW));
        $finish;
    end
    initial begin #2000000; $fatal(1,"PE stress timeout");end
endmodule
