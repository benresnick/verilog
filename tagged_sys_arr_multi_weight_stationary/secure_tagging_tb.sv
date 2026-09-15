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
 always #5 clk=~clk;
 weight_stationary_accelerator #(.ROWS(ROWS),.COLS(COLS),.WEIGHTS_PER_PE(W),.MAX_M(MAX_M),.MAX_K(MAX_K),.MAX_N(MAX_N)) dut (.*);
 task automatic step; @(negedge clk); endtask
 task automatic clean_reset; begin
  reset=1; config_we=0;a_we=0;b_we=0;start=0;trusted_tag_we=0;trusted_abort=0;result_ready=1; dut.tb_invalidate_feedback_tag=0; dut.tb_invalidate_commit_tap=0; repeat(2) @(posedge clk); reset=0; @(posedge clk);
  if(security_fault||busy||result_valid) $fatal(1,"reset did not clear protected state");
 end endtask
 function automatic [95:0] tag(input integer r,p); begin
  case(p) 0:tag=96'h100; 1:tag=96'h1000+(r%2); 2:tag=96'h2000+(r%3); default:tag=96'h3000+r; endcase
 end endfunction
 task automatic load(input integer m,k,n,p,seed); integer r,c,x; integer signed s; begin
  step; config_we=1;config_m=m;config_k=k;config_n=n;step;config_we=0;
  for(r=0;r<m;r++) begin expect_tag[r]=tag(r,p); for(c=0;c<k;c++) begin
   am[r][c]=((seed+r*3+c*5)%9)-4; step;a_we=1;a_row=r;a_col=c;a_data=am[r][c];trusted_tag_we=1;trusted_tag_row=r;trusted_tag_data=expect_tag[r];step;a_we=0;trusted_tag_we=0;
  end end
  for(r=0;r<k;r++) for(c=0;c<n;c++) begin bm[r][c]=((seed+r*7-c*2)%9)-4;step;b_we=1;b_row=r;b_col=c;b_data=bm[r][c];step;b_we=0;end
  for(r=0;r<m;r++) for(c=0;c<n;c++) begin s=0;for(x=0;x<k;x++)s+=am[r][x]*bm[x][c];gold[r][c]=s;got[r][c]=0;end
 end endtask
 task automatic run_ok(input integer m,k,n,p,stall,seed,input string name); integer lim,count; begin
  $display("[SECURE] %s R=%0d C=%0d W=%0d MKN=%0dx%0dx%0d",name,ROWS,COLS,W,m,k,n); load(m,k,n,p,seed);step;start=1;step;start=0;lim=0;count=0;
  while(!done&&lim<10000) begin result_ready=!stall||((lim%4)!=1);@(posedge clk);if(result_valid&&result_ready)begin
   if(!trusted_result_tag_valid||trusted_result_tag!==expect_tag[result_row])$fatal(1,"%s tag mismatch",name);
   if(result_data!==gold[result_row][result_col]||got[result_row][result_col])$fatal(1,"%s data/duplicate",name);got[result_row][result_col]=1;count++;
  end if(security_fault)$fatal(1,"%s unexpected fault",name);lim++;end
  if(!done||count!=m*n)$fatal(1,"%s timeout",name);for(int r=0;r<m;r++)for(int c=0;c<n;c++)if(!got[r][c])$fatal(1,"%s missing result",name);
  passed++;$display("[PASS] %s",name);
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
  k=(ROWS*W<MAX_K)?ROWS*W+1:MAX_K;load(1,k,1,1,77);step;start=1;step;start=0;wait(phase==2&&(dut.bank!=0||dut.kset_base!=0));dut.tb_invalidate_feedback_tag=1;@(posedge clk);dut.tb_invalidate_feedback_tag=0;repeat(2)@(posedge clk);
  if(!security_fault||result_valid)$fatal(1,"missing partial tag did not fault");passed++;$display("[PASS] corrupted partial tag faults closed");
 end endtask
 task automatic tap_fault; integer m; begin
  m=(MAX_M>1)?2:1;load(m,1,1,1,91);step;start=1;step;start=0;wait(phase==2&&dut.pass_cycle>=ROWS);dut.tb_invalidate_commit_tap=1;@(posedge clk);dut.tb_invalidate_commit_tap=0;repeat(2)@(posedge clk);
  if(!security_fault||result_valid)$fatal(1,"invalid tap did not fault");passed++;$display("[PASS] invalid commit tap faults closed");
 end endtask
 task automatic abort_midflight; begin
  load(1,1,1,1,63);step;start=1;step;start=0;wait(phase==2);step;trusted_abort=1;@(posedge clk);step;trusted_abort=0;
  if(!security_fault||result_valid)$fatal(1,"trusted abort did not suppress output");passed++;$display("[PASS] trusted abort flushes work");
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
  if(security_fault) assert(!result_valid) else $fatal(1,"faulted result exported");
 end
 initial begin
  passed=0;clean_reset();no_tag();clean_reset();ingress_fault();clean_reset();
  run_ok(1,1,1,0,0,1,"scalar same user");
  run_ok((MAX_M>=3)?3:MAX_M,1,(COLS>1)?COLS-1:1,1,0,2,"alternating users underfill");
  run_ok((MAX_M>=4)?4:MAX_M,(MAX_K>=ROWS*W+1)?ROWS*W+1:MAX_K,(MAX_N>=COLS+1)?COLS+1:MAX_N,2,1,3,"three users K/N tiles and stalls");
  run_ok(MAX_M,MAX_K,MAX_N,3,1,4,"all distinct users full capacity");
  run_ok((MAX_M>=2)?2:1,2,(MAX_N>=2)?2:1,1,0,5,"first back-to-back job");
  run_ok((MAX_M>=2)?2:1,2,(MAX_N>=2)?2:1,2,0,6,"second back-to-back job");
  run_ok(2,8,4,1,0,17,"canonical 2x8 by 8x4 alternating users");
  for(int ri=0;ri<6;ri++) run_ok(1+(ri%MAX_M),1+((ri*3)%MAX_K),1+((ri*5)%MAX_N),ri%4,ri%2,100+ri,"seeded tagged random");
  midflight_reset();clean_reset();partial_fault();clean_reset();tap_fault();clean_reset();abort_midflight();
  $display("SECURE SUITE: %0d passed",passed);$finish;
 end
endmodule
