`timescale 1ns/1ps
// Unit-level tests for the protected metadata primitives.  Unlike the
// accelerator regression, this directly proves queue/tap and store contracts.
module secure_tags_tb;
    logic clk=0, reset=1, flush=0, advance=0, in_valid=0;
    logic [95:0] in_tag;
    logic tap_valid[0:1]; logic [95:0] tap_tag[0:1]; logic empty;
    logic incoming_valid, has_prior, stored_valid, policy_fault, resolved_valid;
    logic [95:0] incoming_tag, stored_tag, resolved_tag;
    logic clear_valids; logic write_enable[0:1]; logic [1:0] write_row[0:1], read_row[0:2];
    logic [1:0] write_col[0:1], read_col[0:2]; logic [95:0] write_tag[0:1], read_tag[0:2];
    logic read_valid[0:2];
    always #5 clk=~clk;
    shared_tag_queue #(.ROWS(2),.COLS(2),.TAG_WIDTH(96)) q (.*);
    tag_policy_resolver #(.TAG_WIDTH(96)) policy (
        .incoming_valid(incoming_valid),.incoming_tag(incoming_tag),.has_prior_partial(has_prior),
        .stored_tag_valid(stored_valid),.stored_tag(stored_tag),.resolved_valid(resolved_valid),
        .resolved_tag(resolved_tag),.fault(policy_fault)
    );
    secure_obuff_tag_store #(.ROWS(3),.COLS(3),.TAG_WIDTH(96),.WRITE_PORTS(2),.ROW_WIDTH(2),.COL_WIDTH(2)) store (.*);

    task automatic tick; @(posedge clk); #1; endtask
    task automatic check(input logic condition,input string text); begin
        if (!condition) $fatal(1,"secure tag primitive: %s",text);
    end endtask
    initial begin
        clear_valids=0; incoming_valid=0; has_prior=0; stored_valid=0; incoming_tag=96'hA; stored_tag=96'hA;
        for(int p=0;p<2;p++) begin write_enable[p]=0;write_row[p]=0;write_col[p]=0;write_tag[p]=0;end
        for(int p=0;p<3;p++) begin read_row[p]=0;read_col[p]=0;end
        tick; reset=0; tick;
        // Resolver: public/no-prior, matching partial, missing tag, mismatch.
        incoming_valid=1; has_prior=0; #1; check(resolved_valid&&!policy_fault&&resolved_tag==96'hA,"first contribution");
        has_prior=1; stored_valid=1; stored_tag=96'hA; #1; check(!policy_fault,"matching protected partial");
        stored_valid=0; #1; check(policy_fault,"missing protected partial tag");
        stored_valid=1; stored_tag=96'hB; #1; check(policy_fault,"mismatched protected partial tag");
        has_prior=0;
        // q0 -> q1 (tap 0) -> q2 (tap 1), then hold and flush.
        advance=1; in_valid=1; in_tag=96'h11; tick; check(!tap_valid[0]&&!tap_valid[1],"queue injection");
        in_tag=96'h22; tick; check(tap_valid[0]&&tap_tag[0]==96'h11&&!tap_valid[1],"first non-destructive tap");
        in_valid=0; tick; check(tap_valid[0]&&tap_tag[0]==96'h22&&tap_valid[1]&&tap_tag[1]==96'h11,"simultaneous taps");
        advance=0; tick; check(tap_valid[0]&&tap_tag[0]==96'h22&&tap_valid[1]&&tap_tag[1]==96'h11,"queue holds on stall");
        flush=1; tick; flush=0; check(empty&&!tap_valid[0]&&!tap_valid[1],"queue flush");
        // Two independent lanes write their exact addressed protected slots.
        write_enable[0]=1;write_row[0]=0;write_col[0]=1;write_tag[0]=96'hCA;
        write_enable[1]=1;write_row[1]=2;write_col[1]=0;write_tag[1]=96'hDB;tick;
        write_enable[0]=0;write_enable[1]=0;read_row[0]=0;read_col[0]=1;read_row[1]=2;read_col[1]=0;#1;
        check(read_valid[0]&&read_tag[0]==96'hCA&&read_valid[1]&&read_tag[1]==96'hDB,"concurrent store writes");
        clear_valids=1;tick;clear_valids=0;#1;check(!read_valid[0]&&!read_valid[1],"store invalidation");
        $display("PASS: secure tag resolver, shared queue, and OBuff tag store");
        $finish;
    end
endmodule
