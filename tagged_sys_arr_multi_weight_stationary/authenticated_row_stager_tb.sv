`timescale 1ns/1ps
module authenticated_row_stager_tb #(
    parameter int MEM_DATA_W = 128, MAX_RECORD_BYTES = 53
);
    localparam int BYTES = MEM_DATA_W/8;
    logic clk=0, reset=1, clear=0;
    logic start_valid=0, in_valid=0, in_last=0, finish_valid=0, commit_ready=0, result_ready=0;
    wire start_ready, in_ready, finish_ready, commit_valid, result_valid;
    logic [31:0] start_bytes=0;
    logic [95:0] start_tenant=0, in_tenant=0;
    logic [63:0] start_destination=0, in_destination=0;
    logic [MEM_DATA_W-1:0] in_data=0;
    logic [BYTES-1:0] in_keep=0;
    logic [3:0] finish_error=0;
    wire [MAX_RECORD_BYTES*8-1:0] commit_data;
    wire [31:0] commit_bytes;
    wire [95:0] commit_tenant;
    wire [63:0] commit_destination;
    wire [3:0] result_error;
    int checks=0, records=0;
    authenticated_row_stager #(.MEM_DATA_W(MEM_DATA_W), .MAX_RECORD_BYTES(MAX_RECORD_BYTES)) dut(.*);
    always #5 clk=~clk;
    task automatic ck(input logic condition, input string message);
        checks++;
        if (condition !== 1'b1) $fatal(1,"STAGER w%0d record%0d: %s",MEM_DATA_W,records,message);
    endtask
    function automatic [7:0] pattern(input int index);
        return 8'((index*79 + records*23) ^ 8'ha6);
    endfunction
    task automatic erased();
        ck(dut.stage_reg === {MAX_RECORD_BYTES*8{1'b0}} && dut.bytes_reg===0 &&
           dut.received_reg===0 && dut.tenant_reg===0 && dut.destination_reg===0,
           "private bytes and captured context erased");
    endtask
    task automatic quiet();
        if (!commit_valid) ck(commit_data===0 && commit_bytes===0 && commit_tenant===0 && commit_destination===0,
            "no public plaintext or metadata before commit");
        if (!result_valid) ck(result_error===0,"inactive status zero");
    endtask
    task automatic launch(input int length);
        @(negedge clk); start_bytes=length; start_tenant=96'hc23456789abcdef001234567;
        start_destination=64'h13579bdf2468ace0; start_valid=1;
        #1; ck(start_ready,"idle accepts record");
        @(posedge clk); #1;
        @(negedge clk); start_valid=0; start_bytes='1; start_tenant='1; start_destination='1;
    endtask
    task automatic send_bytes(input int length, input int fault);
        int position, take;
        position=0;
        while (position<length) begin
            @(negedge clk); in_valid=0;
            repeat (position%3) begin @(posedge clk); #1; quiet(); @(negedge clk); end
            take=length-position<BYTES ? length-position : BYTES;
            in_data='1; in_keep=0;
            for (int b=0;b<take;b++) begin
                in_data[MEM_DATA_W-1-8*b -:8]=pattern(position+b);
                in_keep[BYTES-1-b]=1;
            end
            in_last=position+take==length;
            in_tenant=96'hc23456789abcdef001234567;
            in_destination=64'h13579bdf2468ace0;
            if(position==0) case(fault)
                1:in_keep=0;
                2:in_keep[BYTES>1 ? BYTES-2 : 0]=0;
                3:in_last=~in_last;
                4:in_tenant^=96'h800000000000000000000000;
                5:in_destination^=64'h8000000000000000;
                6:in_tenant='x;
            endcase
            in_valid=1;
            #1; ck(in_ready,"trusted stream makes progress"); quiet();
            @(posedge clk); #1; ck(!commit_valid,"data alone never authorizes commit");
            position+=take;
            @(negedge clk); in_valid=0;
        end
    endtask
    task automatic finish_record(input int length, input logic[3:0] code, input int expected);
        @(negedge clk); finish_error=code; finish_valid=1; commit_ready=0;
        repeat(5) begin
            #1;
            if(expected==0) begin
                ck(commit_valid && !finish_ready && !result_valid,"success holds whole record and key ownership until commit");
                ck(commit_bytes===32'(length) && commit_tenant===96'hc23456789abcdef001234567 &&
                   commit_destination===64'h13579bdf2468ace0,"captured command is immutable");
                for(int b=0;b<MAX_RECORD_BYTES;b++)
                    ck(commit_data[MAX_RECORD_BYTES*8-1-8*b -:8] === (b<length?pattern(b):8'b0),"independent byte oracle and erased tail");
            end else begin
                ck(!commit_valid,"failed record cannot publish bytes");
                if(result_valid) ck(result_error===4'(expected),"error persists under result stall");
            end
            @(posedge clk); #1; quiet(); @(negedge clk);
        end
        if(expected==0) begin
            commit_ready=1; #1; ck(finish_ready,"commit and finish handshake together");
            @(posedge clk); #1;
            @(negedge clk);
        end
        finish_valid=0; commit_ready=0;
        #1; ck(result_valid && result_error===4'(expected),"terminal status matches completed transaction"); erased();
        result_ready=1;
        @(posedge clk); #1;
        @(negedge clk); result_ready=0;
        ck(start_ready && !result_valid,"result ack releases record slot"); quiet(); records++;
    endtask
    task automatic cancel_record(input bit reset_instead);
        @(negedge clk); if(reset_instead) reset=1; else clear=1;
        #1; ck(!commit_valid && !result_valid && !in_ready && !finish_ready && !start_ready,"cancel masks handshakes immediately"); quiet();
        @(posedge clk); #1; erased();
        @(negedge clk); reset=0; clear=0; finish_valid=0; in_valid=0; commit_ready=0;
        #1; ck(start_ready,"cancel recovers idle"); records++;
    endtask
    initial begin
        repeat(2) @(posedge clk);
        @(negedge clk); reset=0;
        for(int length=0;length<=MAX_RECORD_BYTES;length++) begin
            launch(length); send_bytes(length,0); finish_record(length,0,0);
        end
        for(int fault=1;fault<=6;fault++) begin
            launch(MAX_RECORD_BYTES); send_bytes(MAX_RECORD_BYTES,fault); finish_record(MAX_RECORD_BYTES,0,7);
        end
        for(int code=1;code<=6;code++) begin
            launch(MAX_RECORD_BYTES); send_bytes(MAX_RECORD_BYTES,0); finish_record(MAX_RECORD_BYTES,4'(code),code);
        end
        launch(MAX_RECORD_BYTES); send_bytes(MAX_RECORD_BYTES,0); finish_record(MAX_RECORD_BYTES,4'bx,7);
        launch(MAX_RECORD_BYTES); finish_record(MAX_RECORD_BYTES,0,7);
        launch(1); send_bytes(1,0); send_bytes(1,0); finish_record(1,0,7);
        launch(MAX_RECORD_BYTES+1);
        #1; ck(result_valid && result_error===3 && !in_ready && !commit_valid,"oversize rejected without capture"); erased();
        @(negedge clk); result_ready=1;
        @(posedge clk); #1;
        @(negedge clk); result_ready=0;
        for(int kind=0;kind<2;kind++) begin
            launch(MAX_RECORD_BYTES); cancel_record(kind);
            launch(MAX_RECORD_BYTES); send_bytes(MAX_RECORD_BYTES,0); cancel_record(kind);
            launch(1); send_bytes(1,0);
            @(negedge clk); finish_valid=1; finish_error=0;
            #1; ck(commit_valid,"held commit reached"); cancel_record(kind);
            launch(1); send_bytes(1,0);
            @(negedge clk); finish_valid=1; finish_error=1;
            @(posedge clk); #1; ck(result_valid,"held failure reached"); cancel_record(kind);
        end
        launch(1); send_bytes(1,0); finish_record(1,0,0);
        $display("PASS STAGER w%0d: %0d records, %0d checks",MEM_DATA_W,records,checks); $finish;
    end
    initial begin #10000000; $fatal(1,"stager watchdog"); end
endmodule
