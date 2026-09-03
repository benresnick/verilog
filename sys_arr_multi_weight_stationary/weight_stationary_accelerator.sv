// Blocking weight-stationary matrix multiplier.  A/B are written while idle;
// OBuff returns each partial sum as the seed for the next local-bank pass.
//
// Host transaction sequence:
//   1. Wait for config_ready/a_ready/b_ready (all are high only while idle).
//   2. Pulse config_we with positive M, K, and N within MAX_* capacities.
//   3. Pulse a_we once per A[m,k] and b_we once per B[k,n].  A write is
//      accepted on that rising edge when its matching *_ready is high.
//   4. Pulse start.  The DUT rejects missing, zero-sized, or out-of-range
//      jobs by asserting job_error and remains idle.
//   5. While busy, accept final C values using result_valid/result_ready.
//      result_row/result_col identify each result; done pulses only after the
//      final result handshake.
module weight_stationary_accelerator #(
    parameter int ROWS = 2,
    parameter int COLS = 2,
    parameter int DATA_WIDTH = 8,
    parameter int ACC_WIDTH = 32,
    parameter int WEIGHTS_PER_PE = 1,
    parameter int MAX_M = 8,
    parameter int MAX_K = 16,
    parameter int MAX_N = 8,
    parameter int M_WIDTH = (MAX_M <= 1) ? 1 : $clog2(MAX_M + 1),
    parameter int K_WIDTH = (MAX_K <= 1) ? 1 : $clog2(MAX_K + 1),
    parameter int N_WIDTH = (MAX_N <= 1) ? 1 : $clog2(MAX_N + 1),
    parameter int SLOT_WIDTH = (WEIGHTS_PER_PE <= 1) ? 1 : $clog2(WEIGHTS_PER_PE),
    parameter int ROW_WIDTH = (ROWS <= 1) ? 1 : $clog2(ROWS)
) (
    input logic clk, reset,
    input logic config_we,
    input logic [M_WIDTH-1:0] config_m,
    input logic [K_WIDTH-1:0] config_k,
    input logic [N_WIDTH-1:0] config_n,
    input logic a_we,
    input logic [M_WIDTH-1:0] a_row,
    input logic [K_WIDTH-1:0] a_col,
    input logic signed [DATA_WIDTH-1:0] a_data,
    input logic b_we,
    input logic [K_WIDTH-1:0] b_row,
    input logic [N_WIDTH-1:0] b_col,
    input logic signed [DATA_WIDTH-1:0] b_data,
    input logic start,
    output logic busy, done, job_error,
    // A write is accepted on an asserted write-enable only while its ready
    // signal is high.  All three are low for the duration of a job.
    output logic config_ready, a_ready, b_ready,
    output logic result_valid,
    input logic result_ready,
    output logic [M_WIDTH-1:0] result_row,
    output logic [N_WIDTH-1:0] result_col,
    output logic signed [ACC_WIDTH-1:0] result_data,
    output logic [3:0] phase,
    output logic [31:0] debug_weight_set_loads, debug_mac_count
);
    // A resident set holds W local banks, each spanning all physical rows.
    // K values beyond KR are handled by reloading a later resident K set.
    localparam int KR = ROWS * WEIGHTS_PER_PE;
    typedef enum logic [3:0] {IDLE, LOAD, COMPUTE, DRAIN, RESULTS} state_t;
    state_t state;
    // *_cfg is written by the host while idle.  *_dim is latched only when a
    // valid job starts, so later host activity cannot perturb an active job.
    logic [M_WIDTH-1:0] m_cfg, m_dim, out_m;
    logic [K_WIDTH-1:0] k_cfg, k_dim;
    logic [N_WIDTH-1:0] n_cfg, n_dim, out_n;
    integer n_base, kset_base, bank, load_issue, pass_cycle, commits;
    integer active_cols, active_rows;
    // Data lives inside u_ibuff/u_wbuff.  These local bitmaps are intentionally
    // separate: they prove every required host write occurred before start.
    logic ibuf_v [0:MAX_M-1][0:MAX_K-1];
    logic wbuf_v [0:MAX_K-1][0:MAX_N-1];
    // Array-edge signals: aa enters from the left, aw enters from the top,
    // ap enters at the top as a saved partial sum, and ao exits at the bottom.
    logic signed [DATA_WIDTH-1:0] aa [0:ROWS-1], aw [0:COLS-1];
    logic aav [0:ROWS-1], awv [0:COLS-1];
    logic [SLOT_WIDTH-1:0] aslot [0:COLS-1];
    logic [ROW_WIDTH-1:0] atarget [0:COLS-1];
    logic signed [ACC_WIDTH-1:0] ap [0:COLS-1], ao [0:COLS-1];
    logic apv [0:COLS-1], aov [0:COLS-1];
    logic [M_WIDTH-1:0] ibuf_read_row [0:ROWS-1];
    logic [K_WIDTH-1:0] ibuf_read_col [0:ROWS-1];
    logic signed [DATA_WIDTH-1:0] ibuf_read_data [0:ROWS-1];
    logic [K_WIDTH-1:0] wbuf_read_row [0:COLS-1];
    logic [N_WIDTH-1:0] wbuf_read_col [0:COLS-1];
    logic signed [DATA_WIDTH-1:0] wbuf_read_data [0:COLS-1];
    // OBuff has one write port per physical column, permitting diagonal
    // bottom-edge completions to commit on the same clock.
    logic obuf_write_enable [0:COLS-1];
    logic [M_WIDTH-1:0] obuf_write_row [0:COLS-1];
    logic [N_WIDTH-1:0] obuf_write_col [0:COLS-1];
    logic signed [ACC_WIDTH-1:0] obuf_write_data [0:COLS-1];
    logic obuf_write_final [0:COLS-1];
    logic [M_WIDTH-1:0] obuf_read_row [0:COLS];
    logic [N_WIDTH-1:0] obuf_read_col [0:COLS];
    logic signed [ACC_WIDTH-1:0] obuf_read_data [0:COLS];
    logic obuf_read_valid [0:COLS];
    logic obuf_read_final [0:COLS];
    logic inputs_ready, last_k_pass, last_bank_in_set;
    logic job_accept;
    state_t state_next;
    integer n_base_next, kset_base_next, bank_next, load_issue_next;
    integer pass_cycle_next, commits_next, active_cols_next, active_rows_next;
    logic [M_WIDTH-1:0] out_m_next;
    logic [N_WIDTH-1:0] out_n_next;
    logic done_next;
    logic [31:0] debug_weight_set_loads_next, debug_mac_count_next;
    integer r, c;

    // Host writes are only accepted while idle.  Result transfers are the
    // exception: they occur in RESULTS with their own ready/valid handshake.
    assign busy = (state != IDLE);
    assign config_ready = (state == IDLE);
    assign a_ready = (state == IDLE);
    assign b_ready = (state == IDLE);
    assign phase = state;
    always_comb begin
  // Start is legal only after every element in the requested A and B ranges
  // has been written.  Payload zero and payload invalid remain distinct.
  inputs_ready = 1'b1;
  for (int mi = 0; mi < MAX_M; mi++) for (int ki = 0; ki < MAX_K; ki++)
      if (mi < m_cfg && ki < k_cfg) inputs_ready &= ibuf_v[mi][ki];
  for (int ki = 0; ki < MAX_K; ki++) for (int ni = 0; ni < MAX_N; ni++)
      if (ki < k_cfg && ni < n_cfg) inputs_ready &= wbuf_v[ki][ni];
  // A partial final bank may end a resident set before all W slots are used.
  last_bank_in_set = (bank + 1 >= WEIGHTS_PER_PE) ||
                     (kset_base + (bank + 1) * ROWS >= k_dim);
  last_k_pass = last_bank_in_set && (kset_base + KR >= k_dim);
  // The final extra OBuff read port is reserved for result streaming; ports
  // 0..COLS-1 below are reserved for compute feedback.
  obuf_read_row[COLS] = out_m;
  obuf_read_col[COLS] = out_n;
  result_valid = (state == RESULTS) && obuf_read_final[COLS];
  result_row = out_m;
  result_col = out_n;
  result_data = obuf_read_data[COLS];
  // Activation row pr is issued at local cycle m+pr.  This horizontal skew
  // makes it meet the matching vertical psum at PE[pr,pc].
  for (int pr = 0; pr < ROWS; pr++) begin
   aa[pr] = '0;
   aav[pr] = 1'b0;
   ibuf_read_row[pr] = '0;
   ibuf_read_col[pr] = '0;
   if (state == COMPUTE && pass_cycle >= pr && pass_cycle - pr < m_dim &&
       kset_base + bank * ROWS + pr < k_dim) begin
    ibuf_read_row[pr] = pass_cycle - pr;
    ibuf_read_col[pr] = kset_base + bank * ROWS + pr;
    aa[pr] = ibuf_read_data[pr];
    aav[pr] = ibuf_v[pass_cycle - pr][kset_base + bank * ROWS + pr];
   end
  end
  for (int pc = 0; pc < COLS; pc++) begin
   aw[pc] = '0; awv[pc] = 1'b0;
   aslot[pc] = '0; atarget[pc] = '0;
   ap[pc] = '0; apv[pc] = 1'b0;
   obuf_read_row[pc] = '0;
   obuf_read_col[pc] = '0;
   obuf_write_enable[pc] = 1'b0;
   obuf_write_row[pc] = '0;
   obuf_write_col[pc] = '0;
   obuf_write_data[pc] = '0;
   obuf_write_final[pc] = 1'b0;
   wbuf_read_row[pc] = '0;
   wbuf_read_col[pc] = '0;
   // Every issued token is bottom-row-first; target metadata selects exactly
   // one PE even while prior tokens continue moving through the column.
   if (state == LOAD) begin
    aslot[pc] = load_issue / ROWS;
    atarget[pc] = ROWS - 1 - (load_issue % ROWS);
    if (kset_base + (load_issue / ROWS) * ROWS +
        (ROWS - 1 - (load_issue % ROWS)) < k_dim && n_base + pc < n_dim) begin
     wbuf_read_row[pc] = kset_base + (load_issue / ROWS) * ROWS +
                         (ROWS - 1 - (load_issue % ROWS));
     wbuf_read_col[pc] = n_base + pc;
     aw[pc] = wbuf_read_data[pc];
     awv[pc] = wbuf_v[kset_base + (load_issue / ROWS) * ROWS +
                     (ROWS - 1 - (load_issue % ROWS))][n_base + pc];
    end
   end
   // Psum for C[m,n_base+pc] enters at m+pc.  The matching activation above
   // enters row pr at m+pr, so both arrive at PE[pr,pc] together.
   if (state == COMPUTE && pc < active_cols && pass_cycle >= pc &&
       pass_cycle - pc < m_dim) begin
    obuf_read_row[pc] = pass_cycle - pc;
    obuf_read_col[pc] = n_base + pc;
    // The first global K pass sees an invalid OBuff entry and therefore uses
    // zero; every later bank/set reuses the previously committed partial.
    ap[pc] = obuf_read_valid[pc] ? obuf_read_data[pc] : '0;
    apv[pc] = 1'b1;
   end
   // A bottom-edge output is written back using the coordinate implied by the
   // pipeline schedule.  Finality is set only on the final bank/set of a tile.
   if (state == COMPUTE && aov[pc] && pc < active_cols &&
       pass_cycle >= ROWS + pc && pass_cycle - ROWS - pc < m_dim) begin
    obuf_write_enable[pc] = 1'b1;
    obuf_write_row[pc] = pass_cycle - ROWS - pc;
    obuf_write_col[pc] = n_base + pc;
    obuf_write_data[pc] = ao[pc];
    obuf_write_final[pc] = last_k_pass;
   end
  end
    end

    // IBuff supplies one A element per physical row during a replayed bank.
    multi_read_matrix_buffer #(
        .ROWS(MAX_M), .COLS(MAX_K), .DATA_WIDTH(DATA_WIDTH), .READ_PORTS(ROWS),
        .ROW_WIDTH(M_WIDTH), .COL_WIDTH(K_WIDTH)
    ) u_ibuff (
        .clk(clk), .write_enable(a_we && a_ready),
        .write_row(a_row), .write_col(a_col), .write_data(a_data),
        .read_row(ibuf_read_row), .read_col(ibuf_read_col), .read_data(ibuf_read_data)
    );

    // WBuff provides one bottom-row-first load token per physical column.
    multi_read_matrix_buffer #(
        .ROWS(MAX_K), .COLS(MAX_N), .DATA_WIDTH(DATA_WIDTH), .READ_PORTS(COLS),
        .ROW_WIDTH(K_WIDTH), .COL_WIDTH(N_WIDTH)
    ) u_wbuff (
        .clk(clk), .write_enable(b_we && b_ready),
        .write_row(b_row), .write_col(b_col), .write_data(b_data),
        .read_row(wbuf_read_row), .read_col(wbuf_read_col), .read_data(wbuf_read_data)
    );

    multi_write_output_buffer #(
        .ROWS(MAX_M), .COLS(MAX_N), .ACC_WIDTH(ACC_WIDTH),
        .WRITE_PORTS(COLS), .READ_PORTS(COLS + 1),
        .ROW_WIDTH(M_WIDTH), .COL_WIDTH(N_WIDTH)
    ) u_obuf (
        .clk(clk), .reset(reset),
        .clear_valids(state == IDLE && start && m_cfg != 0 && k_cfg != 0 && n_cfg != 0 &&
                      m_cfg <= MAX_M && k_cfg <= MAX_K && n_cfg <= MAX_N && inputs_ready),
        .write_enable(obuf_write_enable), .write_row(obuf_write_row),
        .write_col(obuf_write_col), .write_data(obuf_write_data),
        .write_final(obuf_write_final), .read_row(obuf_read_row), .read_col(obuf_read_col),
        .read_data(obuf_read_data), .read_valid(obuf_read_valid), .read_final(obuf_read_final)
    );

    sysarr #(
        .ROWS(ROWS), .COLS(COLS), .DATA_WIDTH(DATA_WIDTH),
        .ACC_WIDTH(ACC_WIDTH), .WEIGHTS_PER_PE(WEIGHTS_PER_PE)
    ) u_array (
        .clk(clk), .reset(reset), .weight_load(state == LOAD),
        .activation_in(aa), .activation_valid_in(aav),
        .weight_in(aw), .weight_valid_in(awv),
        .weight_slot_in(aslot), .weight_target_row_in(atarget),
        .selected_slot(bank[SLOT_WIDTH-1:0]),
        .psum_in(ap), .psum_valid_in(apv),
        .psum_out(ao), .psum_valid_out(aov)
    );

    // Controller next-state logic.  All scheduler indexes are registered only
    // in the sequential block below; this keeps cycle boundaries explicit.
    always_comb begin
        job_accept = m_cfg != 0 && k_cfg != 0 && n_cfg != 0 &&
                     m_cfg <= MAX_M && k_cfg <= MAX_K && n_cfg <= MAX_N && inputs_ready;
        state_next = state;
        n_base_next = n_base; kset_base_next = kset_base; bank_next = bank;
        load_issue_next = load_issue; pass_cycle_next = pass_cycle;
        commits_next = commits; active_cols_next = active_cols; active_rows_next = active_rows;
        out_m_next = out_m; out_n_next = out_n;
        done_next = 1'b0;
        debug_weight_set_loads_next = debug_weight_set_loads;
        debug_mac_count_next = debug_mac_count;

        if (state == COMPUTE) begin
            for (int pc = 0; pc < COLS; pc++)
                if (aov[pc] && pc < active_cols && pass_cycle >= ROWS + pc &&
                    pass_cycle - ROWS - pc < m_dim) commits_next++;
        end

        // Blocking schedule: LOAD fills every local weight slot in a resident
        // set; COMPUTE replays one selected bank; DRAIN waits for all bottom
        // commits; then the controller advances bank, K set, N tile, or output.
        case (state)
            IDLE: if (start && job_accept) begin
                // New jobs always begin at logical N=0, K=0, local bank=0.
                state_next = LOAD;
                n_base_next = 0; kset_base_next = 0; bank_next = 0; load_issue_next = 0;
                debug_weight_set_loads_next = 1;
                debug_mac_count_next = 0;
            end
            LOAD: if (load_issue == ROWS * WEIGHTS_PER_PE - 1) begin
                // The entire resident set is present before any bank computes.
                pass_cycle_next = 0; commits_next = 0;
                active_cols_next = ((n_dim - n_base) < COLS) ? (n_dim - n_base) : COLS;
                active_rows_next = ((k_dim - (kset_base + bank * ROWS)) < ROWS) ?
                                   (k_dim - (kset_base + bank * ROWS)) : ROWS;
                state_next = COMPUTE;
            end else load_issue_next = load_issue + 1;
            COMPUTE: if (pass_cycle >= m_dim + ROWS + COLS - 2) begin
                // No more inputs are issued; existing psums may still be in flight.
                state_next = DRAIN;
                debug_mac_count_next = debug_mac_count + m_dim * active_cols * active_rows;
            end else pass_cycle_next = pass_cycle + 1;
            DRAIN: if (commits == m_dim * active_cols) begin
                // Commit count, not just a cycle counter, proves all C[m,n]
                // partials for this bank reached OBuff.
                if (!last_bank_in_set) begin
                    bank_next = bank + 1; pass_cycle_next = 0; commits_next = 0;
                    state_next = COMPUTE;
                end else if (kset_base + KR < k_dim) begin
                    kset_base_next = kset_base + KR; bank_next = 0; load_issue_next = 0;
                    debug_weight_set_loads_next = debug_weight_set_loads + 1; state_next = LOAD;
                end else if (n_base + COLS < n_dim) begin
                    n_base_next = n_base + COLS; kset_base_next = 0;
                    bank_next = 0; load_issue_next = 0;
                    debug_weight_set_loads_next = debug_weight_set_loads + 1; state_next = LOAD;
                end else begin
                    out_m_next = 0; out_n_next = 0; state_next = RESULTS;
                end
            end
            RESULTS: if (result_valid && result_ready) begin
                // Hold coordinates/data until the host accepts this result.
                if (out_n + 1 < n_dim) out_n_next = out_n + 1;
                else if (out_m + 1 < m_dim) begin out_m_next = out_m + 1; out_n_next = 0; end
                else begin done_next = 1'b1; state_next = IDLE; end
            end
            default: state_next = IDLE;
        endcase
    end

    always_ff @(posedge clk) begin
        if (reset) begin
            state <= IDLE;
            done <= 1'b0;
            job_error <= 1'b0;
            m_cfg <= '0; k_cfg <= '0; n_cfg <= '0;
            m_dim <= '0; k_dim <= '0; n_dim <= '0;
            out_m <= '0; out_n <= '0;
            n_base <= 0; kset_base <= 0; bank <= 0; load_issue <= 0;
            pass_cycle <= 0; commits <= 0; active_cols <= 0; active_rows <= 0;
            debug_weight_set_loads <= '0;
            debug_mac_count <= '0;
            for (r = 0; r < MAX_M; r++) for (c = 0; c < MAX_K; c++) begin
                ibuf_v[r][c] <= 1'b0;
            end
            for (r = 0; r < MAX_K; r++) for (c = 0; c < MAX_N; c++) begin
                wbuf_v[r][c] <= 1'b0;
            end
        end else begin
            state <= state_next;
            n_base <= n_base_next;
            kset_base <= kset_base_next;
            bank <= bank_next;
            load_issue <= load_issue_next;
            pass_cycle <= pass_cycle_next;
            commits <= commits_next;
            active_cols <= active_cols_next;
            active_rows <= active_rows_next;
            out_m <= out_m_next;
            out_n <= out_n_next;
            done <= done_next;
            debug_weight_set_loads <= debug_weight_set_loads_next;
            debug_mac_count <= debug_mac_count_next;
            if (state == IDLE && config_we) begin
                m_cfg <= config_m;
                k_cfg <= config_k;
                n_cfg <= config_n;
            end
            if (state == IDLE && a_we && a_row < MAX_M && a_col < MAX_K) begin
                ibuf_v[a_row][a_col] <= 1'b1;
            end
            if (state == IDLE && b_we && b_row < MAX_K && b_col < MAX_N) begin
                wbuf_v[b_row][b_col] <= 1'b1;
            end
   // The controller observes a bottom result one clock after its final PE
   // register update.  At observation cycle t it belongs to m=t-ROWS-c.
   // This explicit coordinate avoids relying on completion order, where
   // C[m+1,c] and C[m,c+1] can arrive in the same cycle.
            // Invalid/missing jobs never leave IDLE, so no stale partials or
            // resident weights can become externally visible.
            if (state == IDLE && start) job_error <= !job_accept;
            if (state == IDLE && start && job_accept) begin
                m_dim <= m_cfg;
                k_dim <= k_cfg;
                n_dim <= n_cfg;
            end
        end
    end
endmodule
