`timescale 1ns/1ps
// Broad trusted-integration regression. Hierarchical corruption below is
// verification-only; production hardware has no such tag access path.
module secure_tagging_tb;
 parameter int ROWS=2,COLS=2,W=1,MAX_M=6,MAX_K=10,MAX_N=6;
 localparam int MW=(MAX_M<=1)?1:$clog2(MAX_M+1),KW=(MAX_K<=1)?1:$clog2(MAX_K+1),NW=(MAX_N<=1)?1:$clog2(MAX_N+1);
 logic clk=0,reset=1,config_we=0,a_we=0,b_we=0,start=0,result_ready=1;
 logic [MW-1:0] config_m,a_row,result_row; logic [KW-1:0] config_k,a_col,b_row; logic [NW-1:0] config_n,b_col,result_col;
 logic signed [7:0] a_data,b_data; logic busy,done,job_error,config_ready,a_ready,b_ready,result_valid; logic signed [31:0] result_data;
 logic [3:0] phase; logic [31:0] debug_weight_set_loads,debug_mac_count;
 logic trusted_tag_we,trusted_abort; logic [MW-1:0] trusted_tag_row; logic [95:0] trusted_tag_data;
 logic security_fault,trusted_result_tag_valid; logic [95:0] trusted_result_tag;
 logic signed [7:0] am[0:MAX_M-1][0:MAX_K-1],bm[0:MAX_K-1][0:MAX_N-1]; logic signed [31:0] gold[0:MAX_M-1][0:MAX_N-1];
 logic [95:0] expect_tag[0:MAX_M-1]; logic got[0:MAX_M-1][0:MAX_N-1]; integer passed;
 logic [31:0] rng=32'h318f726b;
 integer stress_iters=0,seed=32'h318f726b;
 function automatic [31:0] rand32();rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;endfunction
 always #5 clk=~clk;
 weight_stationary_accelerator #(.ROWS(ROWS),.COLS(COLS),.WEIGHTS_PER_PE(W),.MAX_M(MAX_M),.MAX_K(MAX_K),.MAX_N(MAX_N)) dut (.*);
 task automatic step; @(negedge clk); endtask
 task automatic clean_reset; begin
  @(negedge clk); reset=1; config_we=0;a_we=0;b_we=0;start=0;trusted_tag_we=0;trusted_abort=0;result_ready=1; dut.tb_invalidate_feedback_tag=0; dut.tb_invalidate_commit_tap=0; repeat(2) @(posedge clk); @(negedge clk); reset=0; @(posedge clk);#1;
  if(security_fault||busy||result_valid) $fatal(1,"reset did not clear protected state");
 end endtask
 function automatic [95:0] tag(input integer r,p); begin
  case(p) 0:tag=96'h100; 1:tag=96'h1000+(r%2); 2:tag=96'h2000+(r%3); 3:tag=96'h3000+r; default:tag={32'hcafe_f00d,32'h8000_0000,32'(r)}; endcase
 end endfunction
 task automatic load(input integer m,k,n,p,seed); integer r,c,x; integer signed s; begin
  step; config_we=1;config_m=m;config_k=k;config_n=n;step;config_we=0;
  for(r=0;r<m;r++) begin expect_tag[r]=tag(r,p); for(c=0;c<k;c++) begin
   am[r][c]=(seed>=1000)?8'(rand32()):((seed+r*3+c*5)%9)-4; step;a_we=1;a_row=r;a_col=c;a_data=am[r][c];trusted_tag_we=1;trusted_tag_row=r;trusted_tag_data=expect_tag[r];step;a_we=0;trusted_tag_we=0;
  end end
  for(r=0;r<k;r++) for(c=0;c<n;c++) begin bm[r][c]=(seed>=1000)?8'(rand32()):((seed+r*7-c*2)%9)-4;step;b_we=1;b_row=r;b_col=c;b_data=bm[r][c];step;b_we=0;end
  for(r=0;r<m;r++) for(c=0;c<n;c++) begin s=0;for(x=0;x<k;x++)s+=am[r][x]*bm[x][c];gold[r][c]=s;got[r][c]=0;end
 end endtask
 task automatic run_ok(input integer m,k,n,p,stall,seed,input string name); integer lim,count; begin
  $display("[SECURE] %s R=%0d C=%0d W=%0d MKN=%0dx%0dx%0d",name,ROWS,COLS,W,m,k,n); load(m,k,n,p,seed);step;start=1;step;start=0;lim=0;count=0;
  while(!done&&lim<10000) begin @(negedge clk);result_ready=!stall||((lim%43)>=19);@(posedge clk);if(result_valid&&result_ready)begin
   if(!trusted_result_tag_valid||trusted_result_tag!==expect_tag[result_row])$fatal(1,"%s tag mismatch",name);
   if(result_data!==gold[result_row][result_col]||got[result_row][result_col])$fatal(1,"%s data/duplicate",name);got[result_row][result_col]=1;count++;
  end if(security_fault)$fatal(1,"%s unexpected fault",name);lim++;#1;end
  if(!done||count!=m*n)$fatal(1,"%s timeout",name);for(int r=0;r<m;r++)for(int c=0;c<n;c++)if(!got[r][c])$fatal(1,"%s missing result",name);
  passed++;$display("[PASS] %s",name);
 end endtask
 task automatic cancel_stalled_output(input bit use_reset); begin
  load(2,2,2,4,1300);step;result_ready=0;start=1;step;start=0;
  wait(result_valid);repeat(5)step;
  if(use_reset)reset=1;else trusted_abort=1;
  @(posedge clk);#1;
  if(result_valid||trusted_result_tag_valid||busy)$fatal(1,"stalled result escaped cancellation");
  step;reset=0;trusted_abort=0;
  if(!use_reset)begin
   repeat(5)begin step;start=1;config_we=1;config_m=1;config_k=1;config_n=1;end
   if(!security_fault||result_valid||busy)$fatal(1,"fault did not remain sticky under host commands");
  end
  clean_reset();run_ok(1,1,1,4,1,1400,"fresh tenant after cancellation");
  passed++;
 end endtask
 task automatic no_tag; begin
  step;config_we=1;config_m=1;config_k=1;config_n=1;step;config_we=0;step;a_we=1;a_row=0;a_col=0;a_data=3;step;a_we=0;step;b_we=1;b_row=0;b_col=0;b_data=2;step;b_we=0;step;start=1;step;start=0;@(posedge clk);
  if(!job_error||busy||security_fault)$fatal(1,"untagged A accepted");passed++;$display("[PASS] missing trusted tag rejected");
 end endtask
 task automatic ingress_fault; begin
  step;config_we=1;config_m=1;config_k=2;config_n=1;step;config_we=0;
  step;a_we=1;a_row=0;a_col=0;a_data=1;trusted_tag_we=1;trusted_tag_row=0;trusted_tag_data=96'hA;step;a_col=1;trusted_tag_data=96'hB;@(posedge clk);step;a_we=0;trusted_tag_we=0;
  if(!security_fault||a_ready||result_valid)$fatal(1,"conflicting ingress did not fault");passed++;$display("[PASS] conflicting ingress faults closed");
 end endtask
 task automatic midflight_reset; begin
  load(1,(MAX_K>ROWS)?ROWS+1:1,1,2,55);step;start=1;step;start=0;wait(phase==2);step;reset=1;@(posedge clk);step;reset=0;@(posedge clk);
 if(busy||result_valid||security_fault||!config_ready)$fatal(1,"reset leaked protected state");passed++;$display("[PASS] midflight reset flushes tags");
 end endtask
 task automatic partial_fault; integer k; begin
  k=(ROWS*W<MAX_K)?ROWS*W+1:MAX_K;load(1,k,1,1,77);step;start=1;step;start=0;wait(phase==2&&(dut.bank!=0||dut.kset_base!=0));dut.tb_invalidate_feedback_tag=1;@(posedge clk);@(negedge clk);dut.tb_invalidate_feedback_tag=0;repeat(2)@(posedge clk);
  if(!security_fault||result_valid)$fatal(1,"missing partial tag did not fault");passed++;$display("[PASS] corrupted partial tag faults closed");
 end endtask
 task automatic tap_fault; integer m; begin
  m=(MAX_M>1)?2:1;load(m,1,1,1,91);step;start=1;step;start=0;wait(phase==2&&dut.pass_cycle>=ROWS);dut.tb_invalidate_commit_tap=1;@(posedge clk);@(negedge clk);dut.tb_invalidate_commit_tap=0;repeat(2)@(posedge clk);
  if(!security_fault||result_valid)$fatal(1,"invalid tap did not fault");passed++;$display("[PASS] invalid commit tap faults closed");
 end endtask
 task automatic abort_midflight; begin
  load(1,1,1,1,63);step;start=1;step;start=0;wait(phase==2);step;trusted_abort=1;@(posedge clk);step;trusted_abort=0;
  if(!security_fault||result_valid)$fatal(1,"trusted abort did not suppress output");passed++;$display("[PASS] trusted abort flushes work");
 end endtask
 // A new configuration epoch must not let a new owner bind a row with one
 // write and inherit the previous owner's remaining A elements.
 task automatic epoch_isolation; begin
  if(MAX_K>=2) begin
   load(1,2,1,0,201);
   step;config_we=1;config_m=1;config_k=2;config_n=1;step;config_we=0;
   step;a_we=1;a_row=0;a_col=0;a_data=1;trusted_tag_we=1;trusted_tag_row=0;trusted_tag_data=96'h9999;step;a_we=0;trusted_tag_we=0;
   step;start=1;step;start=0;@(posedge clk);
   if(!job_error||busy||security_fault)$fatal(1,"new epoch inherited the previous owner's A elements");
   passed++;$display("[PASS] new configuration epoch cannot inherit a previous owner's A elements");
  end else $display("[SKIP] epoch isolation needs MAX_K >= 2");
 end endtask
 // Configure and rebind row 0 to a new owner on the same clock edge: the old
 // epoch's tag must not raise a false conflict, and the result is the new owner's.
 task automatic same_edge_epoch_binding; integer lim,count; begin
  load(1,1,1,0,202);
  step;config_we=1;config_m=1;config_k=1;config_n=1;
  a_we=1;a_row=0;a_col=0;a_data=5;trusted_tag_we=1;trusted_tag_row=0;trusted_tag_data=96'h7777;
  step;config_we=0;a_we=0;trusted_tag_we=0;
  if(security_fault)$fatal(1,"same-edge configure and binding faulted on the old epoch's tag");
  step;start=1;step;start=0;lim=0;count=0;
  while(!done&&lim<1000) begin @(negedge clk);@(posedge clk);
   if(result_valid&&result_ready) begin
    if(trusted_result_tag!==96'h7777||result_data!==32'(5*bm[0][0]))$fatal(1,"same-edge epoch result has wrong owner or data");
    count++;
   end
   lim++;#1;
  end
  if(!done||count!=1||security_fault)$fatal(1,"same-edge epoch job did not complete");
  passed++;$display("[PASS] configure and A binding on the same edge start a clean epoch");
 end endtask
 // Configure and start on the same clock edge.  The configure opens a new
 // epoch and clears every A binding, so the start must be refused rather than
 // run the old dimensions over the cleared buffer (which exported zeros under
 // tag 0 before the fix; found by the formal flow).
 task automatic same_edge_configure_start; integer lim; begin
  load(1,1,1,0,203);
  step;config_we=1;config_m=1;config_k=1;config_n=1;start=1;
  step;config_we=0;start=0;@(posedge clk);#1;
  if(!job_error||busy||security_fault)$fatal(1,"start on a configure edge was accepted");
  for(lim=0;lim<4*(ROWS+COLS+MAX_K+4);lim++) begin @(posedge clk);#1;
   if(result_valid||busy||done)$fatal(1,"refused same-edge start produced output");
  end
  passed++;$display("[PASS] start on a configure edge is refused and exports nothing");
  run_ok(1,1,1,0,0,204,"normal job after refused same-edge start");
 end endtask
 // A result stalled on the port, then flushed by abort or reset, must not stay
 // visible: the port reads zero whenever result_valid is low.
 task automatic result_port_blank_after_flush(input bit use_reset); begin
  load(1,1,1,4,205);step;result_ready=0;start=1;step;start=0;
  wait(result_valid);repeat(3)step;
  if(use_reset)reset=1;else trusted_abort=1;
  step;reset=0;trusted_abort=0;
  repeat(20) begin @(posedge clk);#1;
   if(result_valid||result_data!==0||result_row!==0||result_col!==0||trusted_result_tag!==0)
    $fatal(1,"flushed result is still visible on the result port");
  end
  result_ready=1;passed++;
  $display("[PASS] result port is blank after %s flushes a stalled result",use_reset?"reset":"abort");
 end endtask
 // Coordinates are wide enough to encode MAX and beyond.  Such writes must
 // never reach a buffer write port (synthesis would alias them onto real rows)
 // and must not bind a tag or fault.
 logic oob_port_write=0;
 always @(posedge clk) if(!reset) begin
  if(dut.u_ibuff.write_enable&&(dut.u_ibuff.write_row>=MAX_M||dut.u_ibuff.write_col>=MAX_K)) oob_port_write<=1;
  if(dut.u_wbuff.write_enable&&(dut.u_wbuff.write_row>=MAX_K||dut.u_wbuff.write_col>=MAX_N)) oob_port_write<=1;
 end
 task automatic out_of_range_writes; begin
  step;config_we=1;config_m=1;config_k=1;config_n=1;step;config_we=0;
  if((1<<MW)>MAX_M) begin step;a_we=1;a_row=MAX_M;a_col=0;a_data=7;trusted_tag_we=1;trusted_tag_row=MAX_M;trusted_tag_data=96'h5;step;a_we=0;trusted_tag_we=0; end
  if((1<<KW)>MAX_K) begin step;a_we=1;a_row=0;a_col=MAX_K;a_data=7;trusted_tag_we=1;trusted_tag_row=0;trusted_tag_data=96'h5;step;a_we=0;trusted_tag_we=0;
                          step;b_we=1;b_row=MAX_K;b_col=0;b_data=7;step;b_we=0; end
  if((1<<NW)>MAX_N) begin step;b_we=1;b_row=0;b_col=MAX_N;b_data=7;step;b_we=0; end
  @(posedge clk);#1;
  // The port monitor is the real check: simulation drops an out-of-range array
  // index, so only a write that reaches a buffer port could alias in silicon.
  if(oob_port_write)$fatal(1,"out-of-range host write reached a buffer write port");
  // The a_col=MAX_K write named a legal row: it must not bind that row's tag.
  if(dut.trusted_row_tag_valid[0]||security_fault)$fatal(1,"out-of-range host write bound a tag or faulted");
  passed++;$display("[PASS] out-of-range host writes are dropped before the buffers");
 end endtask
 // Tagged invariants: these inspect only internal trusted state and never
 // print payloads.  Fault-injection cycles are excluded deliberately.
 always @(posedge clk) if(!reset) begin
  for(int pc=0;pc<COLS;pc++) begin
   if(dut.obuf_write_enable[pc] && !security_fault && !dut.tb_invalidate_commit_tap) begin
    assert(dut.tap_valid[pc]) else $fatal(1,"commit without queue tap pc=%0d",pc);
    assert(dut.secure_tag_write_enable[pc]) else $fatal(1,"data/tag write split pc=%0d",pc);
    // The secure store is connected directly to obuf_write_row/col in DUT.
   end
   if(pc>=dut.active_cols) assert(!dut.secure_tag_write_enable[pc]) else $fatal(1,"inactive tile tag write pc=%0d",pc);
  end
  if(result_valid) assert(trusted_result_tag_valid && !security_fault) else $fatal(1,"untrusted final export");
  if(!result_valid) assert(result_data===0 && result_row===0 && result_col===0 && trusted_result_tag===0)
   else $fatal(1,"result port shows a value while result_valid is low");
  if(security_fault) assert(!result_valid) else $fatal(1,"faulted result exported");
 end
 logic was_stalled=0;
 logic [MW+NW+32+96-1:0] held_packet;
 always @(posedge clk) begin
  if(reset||trusted_abort||security_fault)was_stalled<=0;
  else begin
   if(was_stalled)assert(result_valid&&trusted_result_tag_valid&&
     {result_row,result_col,result_data,trusted_result_tag}===held_packet)
      else $fatal(1,"stalled data/tag packet changed before acceptance");
   was_stalled<=result_valid&&!result_ready;
   held_packet<={result_row,result_col,result_data,trusted_result_tag};
  end
 end
 initial begin
  passed=0;clean_reset();no_tag();clean_reset();ingress_fault();clean_reset();
  out_of_range_writes();clean_reset();epoch_isolation();clean_reset();same_edge_epoch_binding();clean_reset();
  same_edge_configure_start();clean_reset();
  result_port_blank_after_flush(0);clean_reset();result_port_blank_after_flush(1);clean_reset();
  if($value$plusargs("stress_iters=%d",stress_iters))begin end
  if($value$plusargs("seed=%d",seed))begin end
  rng=seed;
  run_ok(1,1,1,0,0,1,"scalar same user");
  run_ok((MAX_M>=3)?3:MAX_M,1,(COLS>1)?COLS-1:1,1,0,2,"alternating users underfill");
  run_ok((MAX_M>=4)?4:MAX_M,(MAX_K>=ROWS*W+1)?ROWS*W+1:MAX_K,(MAX_N>=COLS+1)?COLS+1:MAX_N,2,1,3,"three users K/N tiles and stalls");
  run_ok(MAX_M,MAX_K,MAX_N,3,1,4,"all distinct users full capacity");
  run_ok((MAX_M>=2)?2:1,2,(MAX_N>=2)?2:1,1,0,5,"first back-to-back job");
  run_ok((MAX_M>=2)?2:1,2,(MAX_N>=2)?2:1,2,0,6,"second back-to-back job");
  run_ok(2,8,4,1,0,17,"canonical 2x8 by 8x4 alternating users");
  for(int ri=0;ri<6;ri++) run_ok(1+(ri%MAX_M),1+((ri*3)%MAX_K),1+((ri*5)%MAX_N),ri%4,ri%2,100+ri,"seeded tagged random");
  for(int ri=0;ri<stress_iters;ri++)run_ok(1+(rand32()%MAX_M),1+(rand32()%MAX_K),1+(rand32()%MAX_N),4,1,1000+ri,$sformatf("full-range random %0d seed %0d",ri,seed));
  cancel_stalled_output(0);cancel_stalled_output(1);
  midflight_reset();clean_reset();partial_fault();clean_reset();tap_fault();clean_reset();abort_midflight();
  $display("SECURE SUITE: %0d passed",passed);$finish;
 end
 initial begin #2000000;$fatal(1,"tagged suite timeout");end
endmodule
