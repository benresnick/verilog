// Encrypted row records around the tagged weight-stationary accelerator.
// Build with ENABLE_SECURE_TAGS and ENABLE_SECURE_MEMORY. Scheduler, key,
// clear/abort, and storage-ack ports are trusted internal control interfaces.
// There are no external plaintext or ownership-tag read/write ports.
//
// DRAM record: 32-byte {"TGR1", IV[95:0], tag[127:0]} header, then ciphertext.
// The trusted configured shape supplies payload length. TGC1 AAD binds tenant,
// record type (A=1, public B=2, C=3), byte length, and logical row number.
// Ciphertext writes are tentative until header transfer and matching successful
// storage acknowledgement. Only that acknowledgement retires a complete C row.
module secure_memory_accelerator #(
    parameter int ROWS = 2, COLS = 2, DATA_WIDTH = 8, ACC_WIDTH = 32,
    parameter int WEIGHTS_PER_PE = 1,
    parameter int MAX_M = 8, MAX_K = 16, MAX_N = 8,
    parameter int AES_KEY_W = 256, MEM_DATA_W = 128, NUM_KEY_SLOTS = 8,
    parameter int SLOT_W = NUM_KEY_SLOTS <= 1 ? 1 : $clog2(NUM_KEY_SLOTS),
    parameter int M_WIDTH = MAX_M <= 1 ? 1 : $clog2(MAX_M+1),
    parameter int K_WIDTH = MAX_K <= 1 ? 1 : $clog2(MAX_K+1),
    parameter int N_WIDTH = MAX_N <= 1 ? 1 : $clog2(MAX_N+1),
    parameter int COOKIE_W = 64
) (
    input logic clk, reset, abort,
    input logic [2:0] clear,
    input logic provision_valid,
    output wire provision_ready,
    input logic [SLOT_W-1:0] provision_slot,
    input logic [95:0] provision_tenant_id,
    input logic [AES_KEY_W-1:0] provision_key,
    input logic [31:0] provision_iv_fixed_field,
    input logic [63:0] provision_counter_start,
    output wire provision_error,
    input logic invalidate_valid,
    input logic [SLOT_W-1:0] invalidate_slot,
    output wire invalidate_ready,
    input logic config_valid,
    output wire config_ready,
    input logic [M_WIDTH-1:0] config_m,
    input logic [K_WIDTH-1:0] config_k,
    input logic [N_WIDTH-1:0] config_n,
    output logic config_error,
    input logic start_valid,
    output wire start_ready,
    output wire busy, done, job_error, security_fault,

    input logic [1:0] load_valid,
    output wire [1:0] load_ready,
    input logic [1:0][95:0] load_tenant,
    input logic [1:0][31:0] load_row,
    input logic [1:0][255:0] load_header,
    input logic [1:0] load_data_valid,
    output wire [1:0] load_data_ready,
    input logic [1:0][MEM_DATA_W-1:0] load_data,
    input logic [1:0][MEM_DATA_W/8-1:0] load_keep,
    input logic [1:0] load_last,
    output wire [1:0] load_result_valid,
    input logic [1:0] load_result_ready,
    output wire [1:0][3:0] load_result_error,

    output wire store_valid,
    input logic store_ready,
    output wire [MEM_DATA_W-1:0] store_data,
    output wire [MEM_DATA_W/8-1:0] store_keep,
    output wire store_last,
    output wire store_header_valid,
    input logic store_header_ready,
    output wire [255:0] store_header,
    output wire [M_WIDTH-1:0] store_row,
    output wire [31:0] store_bytes,
    output wire [COOKIE_W-1:0] store_cookie,
    input logic store_ack_valid,
    output wire store_ack_ready,
    input logic [COOKIE_W-1:0] store_ack_cookie,
    input logic store_ack_success,
    output wire store_result_valid,
    input logic store_result_ready,
    output wire [3:0] store_result_error
);
    localparam int DATA_BYTES = DATA_WIDTH/8, ACC_BYTES = ACC_WIDTH/8;
    localparam int MEM_BYTES = MEM_DATA_W/8, WORDS_PER_BEAT = MEM_DATA_W/ACC_WIDTH;
    localparam int INPUT_LIMIT = MAX_K > MAX_N ? MAX_K*DATA_BYTES : MAX_N*DATA_BYTES;
    localparam int TXN_LIMIT = INPUT_LIMIT > MAX_N*ACC_BYTES ? INPUT_LIMIT : MAX_N*ACC_BYTES;
    localparam logic [31:0] FRAME_MAGIC = 32'h54475231;
    typedef enum logic [3:0] {O_IDLE, O_COMMAND, O_FILL, O_SEND, O_FINISH,
                              O_HEADER, O_ACK, O_RESULT} output_state_t;
    output_state_t output_state;
    logic [M_WIDTH-1:0] m_reg, output_row;
    logic [K_WIDTH-1:0] k_reg;
    logic [N_WIDTH-1:0] n_reg;
    logic configured;
    logic [95:0] output_tenant;
    logic [31:0] output_bytes, output_words, read_index, fill_words;
    logic [MEM_DATA_W-1:0] plain_reg;
    logic [MEM_BYTES-1:0] plain_keep;
    logic plain_last;
    logic [255:0] header_reg;
    logic [3:0] output_error;
    logic [COOKIE_W-1:0] cookie_counter, cookie_reg;
    logic cookie_exhausted;
    logic [1:0] local_error_valid;
    wire [1:0] stage_start_ready, stage_result_valid;
    wire [1:0][3:0] stage_result_error;
    wire [1:0] commit_valid, commit_ready;
    wire [1:0][63:0] commit_destination;
    wire [1:0][95:0] commit_tenant;
    wire [MAX_K*DATA_WIDTH-1:0] a_commit_data;
    wire [MAX_N*DATA_WIDTH-1:0] b_commit_data;
    wire core_busy, core_config_ready, core_result_valid, core_tag_valid;
    wire [M_WIDTH-1:0] core_result_row;
    wire [N_WIDTH-1:0] core_result_col;
    wire signed [ACC_WIDTH-1:0] core_result_data;
    wire [95:0] core_result_tag;
    wire [N_WIDTH-1:0] peek_col = output_state == O_FILL ? N_WIDTH'(read_index) : '0;
    wire enabled = !reset && !abort && !security_fault;
    wire inputs_idle = (&stage_start_ready) && !(|local_error_valid);
    wire legal_shape = config_m != 0 && config_k != 0 && config_n != 0 &&
        config_m <= MAX_M && config_k <= MAX_K && config_n <= MAX_N;
    assign config_ready = enabled && !(|clear) && core_config_ready && inputs_idle && output_state == O_IDLE;
    wire config_fire = config_valid && config_ready;
    assign start_ready = enabled && !(|clear) && core_config_ready && inputs_idle &&
                         output_state == O_IDLE && !config_valid;
    wire start_fire = start_valid && start_ready;
    assign busy = core_busy || !inputs_idle || output_state != O_IDLE;

    wire [2:0] crypto_cmd_ready, crypto_in_ready, crypto_out_valid, crypto_out_last, crypto_result_valid;
    wire [2:0][MEM_DATA_W-1:0] crypto_out_data;
    wire [2:0][MEM_BYTES-1:0] crypto_out_keep;
    wire [2:0][95:0] crypto_out_tenant, crypto_result_iv;
    wire [2:0][63:0] crypto_out_destination;
    wire [2:0][127:0] crypto_result_tag;
    wire [2:0][3:0] crypto_result_error;
    wire [2:0] crypto_clear, crypto_cmd_valid, crypto_in_valid, crypto_in_last;
    wire [2:0][95:0] crypto_tenant, crypto_iv;
    wire [2:0][31:0] crypto_type, crypto_bytes;
    wire [2:0][63:0] crypto_destination;
    wire [2:0][127:0] crypto_expected_tag;
    wire [2:0][MEM_DATA_W-1:0] crypto_in_data;
    wire [2:0][MEM_BYTES-1:0] crypto_in_keep;
    wire [2:0] crypto_out_ready, crypto_result_ready;
    wire bad_peek = enabled && output_state == O_FILL &&
        (!core_result_valid || !core_tag_valid || core_result_tag !== output_tenant ||
         core_result_row !== output_row || core_result_col !== N_WIDTH'(read_index));
    assign crypto_clear = clear | {3{abort || security_fault}} | {bad_peek, 2'b0};

    for (genvar p = 0; p < 2; p++) begin : g_load
        localparam int RECORD_BYTES = (p == 0 ? MAX_K : MAX_N)*DATA_BYTES;
        wire context_ok = configured && load_header[p][255:224] == FRAME_MAGIC &&
            load_row[p] < (p == 0 ? 32'(m_reg) : 32'(k_reg)) &&
            (p == 0 || load_tenant[p] == 0);
        wire window_open = enabled && !clear[p] && core_config_ready &&
            !config_fire && !start_fire && !local_error_valid[p] && stage_start_ready[p];
        wire command_fire = load_valid[p] && load_ready[p];
        wire [RECORD_BYTES*8-1:0] row_data;
        wire [31:0] row_bytes;
        assign load_ready[p] = window_open && (!context_ok || crypto_cmd_ready[p]);
        assign crypto_cmd_valid[p] = load_valid[p] && window_open && context_ok;
        assign crypto_tenant[p] = load_tenant[p];
        assign crypto_type[p] = p == 0 ? 32'd1 : 32'd2;
        assign crypto_destination[p] = {32'b0, load_row[p]};
        assign crypto_bytes[p] = p == 0 ? 32'(k_reg)*DATA_BYTES : 32'(n_reg)*DATA_BYTES;
        assign crypto_iv[p] = load_header[p][223:128];
        assign crypto_expected_tag[p] = load_header[p][127:0];
        assign crypto_in_valid[p] = enabled && load_data_valid[p];
        assign crypto_in_data[p] = load_data[p];
        assign crypto_in_keep[p] = load_keep[p];
        assign crypto_in_last[p] = load_last[p];
        assign load_data_ready[p] = enabled && !clear[p] && crypto_in_ready[p];
        assign load_result_valid[p] = enabled && !clear[p] &&
            (local_error_valid[p] || stage_result_valid[p]);
        assign load_result_error[p] = !load_result_valid[p] ? 4'b0 :
            local_error_valid[p] ? 4'd7 : stage_result_error[p];
        authenticated_row_stager #(.MEM_DATA_W(MEM_DATA_W), .MAX_RECORD_BYTES(RECORD_BYTES)) stage (
            .clk(clk), .reset(reset), .clear(crypto_clear[p]),
            .start_valid(command_fire && context_ok), .start_ready(stage_start_ready[p]),
            .start_bytes(crypto_bytes[p]), .start_tenant(load_tenant[p]),
            .start_destination(crypto_destination[p]),
            .in_valid(crypto_out_valid[p]), .in_ready(crypto_out_ready[p]),
            .in_data(crypto_out_data[p]), .in_keep(crypto_out_keep[p]), .in_last(crypto_out_last[p]),
            .in_tenant(crypto_out_tenant[p]), .in_destination(crypto_out_destination[p]),
            .finish_valid(crypto_result_valid[p]), .finish_ready(crypto_result_ready[p]),
            .finish_error(crypto_result_error[p]), .commit_valid(commit_valid[p]),
            .commit_ready(commit_ready[p]), .commit_data(row_data), .commit_bytes(row_bytes),
            .commit_tenant(commit_tenant[p]), .commit_destination(commit_destination[p]),
            .result_valid(stage_result_valid[p]), .result_ready(load_result_ready[p]),
            .result_error(stage_result_error[p])
        );
        if (p == 0) assign a_commit_data = row_data;
        else assign b_commit_data = row_data;
        always_ff @(posedge clk) begin
            if (reset || crypto_clear[p]) local_error_valid[p] <= 1'b0;
            else if (command_fire && !context_ok) local_error_valid[p] <= 1'b1;
            else if (load_result_ready[p]) local_error_valid[p] <= 1'b0;
        end
    end

    assign crypto_cmd_valid[2] = enabled && !clear[2] && output_state == O_COMMAND;
    assign crypto_tenant[2] = output_tenant;
    assign crypto_type[2] = 32'd3;
    assign crypto_destination[2] = 64'(output_row);
    assign crypto_bytes[2] = output_bytes;
    assign crypto_iv[2] = '0;
    assign crypto_expected_tag[2] = '0;
    assign crypto_in_valid[2] = enabled && output_state == O_SEND;
    assign crypto_in_data[2] = plain_reg;
    assign crypto_in_keep[2] = plain_keep;
    assign crypto_in_last[2] = plain_last;
    assign crypto_out_ready[2] = enabled && !clear[2] && store_ready;
    assign store_valid = enabled && !clear[2] && crypto_out_valid[2];
    assign store_data = store_valid ? crypto_out_data[2] : '0;
    assign store_keep = store_valid ? crypto_out_keep[2] : '0;
    assign store_last = store_valid && crypto_out_last[2];
    assign store_header_valid = enabled && !clear[2] && output_state == O_HEADER;
    assign store_header = store_header_valid ? header_reg : '0;
    wire record_visible = store_valid || store_header_valid ||
                          (enabled && !clear[2] && output_state == O_ACK);
    assign store_row = record_visible ? output_row : '0;
    assign store_bytes = record_visible ? output_bytes : 32'b0;
    assign store_cookie = record_visible ? cookie_reg : '0;
    assign store_ack_ready = enabled && !clear[2] && output_state == O_ACK;
    wire acknowledge = store_ack_valid && store_ack_ready && store_ack_cookie == cookie_reg;
    wire failed_crypto = crypto_result_valid[2] && crypto_result_error[2] != 0;
    assign crypto_result_ready[2] = enabled && !clear[2] &&
        ((output_state != O_IDLE && output_state != O_RESULT && failed_crypto) || acknowledge);
    wire retire_row = acknowledge && (store_ack_success === 1'b1) && crypto_result_valid[2] &&
                      crypto_result_error[2] == 0;
    assign store_result_valid = enabled && !clear[2] && output_state == O_RESULT;
    assign store_result_error = store_result_valid ? output_error : 4'b0;

    tenant_gcm_cluster #(.AES_KEY_W(AES_KEY_W), .MEM_DATA_W(MEM_DATA_W),
        .MAX_TXN_BYTES(TXN_LIMIT), .NUM_KEY_SLOTS(NUM_KEY_SLOTS), .SLOT_W(SLOT_W)) crypto (
        .clk(clk), .reset(reset), .clear(crypto_clear),
        .provision_valid(provision_valid), .provision_ready(provision_ready),
        .provision_slot(provision_slot), .provision_tenant_id(provision_tenant_id),
        .provision_key(provision_key), .provision_iv_fixed_field(provision_iv_fixed_field),
        .provision_counter_start(provision_counter_start), .provision_error(provision_error),
        .invalidate_valid(invalidate_valid), .invalidate_slot(invalidate_slot), .invalidate_ready(invalidate_ready),
        .cmd_valid(crypto_cmd_valid), .cmd_ready(crypto_cmd_ready), .cmd_tenant_id(crypto_tenant),
        .cmd_record_type(crypto_type), .cmd_destination(crypto_destination), .cmd_payload_bytes(crypto_bytes),
        .cmd_iv(crypto_iv), .cmd_expected_tag(crypto_expected_tag),
        .in_valid(crypto_in_valid), .in_ready(crypto_in_ready), .in_data(crypto_in_data),
        .in_keep(crypto_in_keep), .in_last(crypto_in_last), .out_valid(crypto_out_valid),
        .out_ready(crypto_out_ready), .out_data(crypto_out_data), .out_keep(crypto_out_keep),
        .out_last(crypto_out_last), .out_tenant_id(crypto_out_tenant), .out_destination(crypto_out_destination),
        .result_valid(crypto_result_valid), .result_ready(crypto_result_ready),
        .result_error(crypto_result_error), .result_tag(crypto_result_tag), .result_iv(crypto_result_iv)
    );

    weight_stationary_accelerator #(.ROWS(ROWS), .COLS(COLS), .DATA_WIDTH(DATA_WIDTH),
        .ACC_WIDTH(ACC_WIDTH), .WEIGHTS_PER_PE(WEIGHTS_PER_PE),
        .MAX_M(MAX_M), .MAX_K(MAX_K), .MAX_N(MAX_N),
        .M_WIDTH(M_WIDTH), .K_WIDTH(K_WIDTH), .N_WIDTH(N_WIDTH), .TAG_WIDTH(96)) core (
        .clk(clk), .reset(reset || abort), .config_we(config_fire),
        .config_m(legal_shape ? config_m : M_WIDTH'(0)),
        .config_k(legal_shape ? config_k : K_WIDTH'(0)),
        .config_n(legal_shape ? config_n : N_WIDTH'(0)),
        .a_we(1'b0), .a_row(M_WIDTH'(0)), .a_col(K_WIDTH'(0)), .a_data(DATA_WIDTH'(0)),
        .b_we(1'b0), .b_row(K_WIDTH'(0)), .b_col(N_WIDTH'(0)), .b_data(DATA_WIDTH'(0)),
        .start(start_fire), .busy(core_busy), .done(done), .job_error(job_error),
        .config_ready(core_config_ready), .a_ready(), .b_ready(),
        .result_valid(core_result_valid), .result_ready(1'b0), .result_row(core_result_row),
        .result_col(core_result_col), .result_data(core_result_data), .phase(),
        .debug_weight_set_loads(), .debug_mac_count(),
        .trusted_tag_we(1'b0), .trusted_tag_row(M_WIDTH'(0)), .trusted_tag_data(96'b0),
        .trusted_abort(abort), .security_fault(security_fault),
        .trusted_result_tag_valid(core_tag_valid), .trusted_result_tag(core_result_tag),
        .trusted_a_commit_valid(commit_valid[0]), .trusted_a_commit_ready(commit_ready[0]),
        .trusted_a_commit_row(M_WIDTH'(commit_destination[0])), .trusted_a_commit_data(a_commit_data),
        .trusted_a_commit_tenant(commit_tenant[0]),
        .trusted_b_commit_valid(commit_valid[1]), .trusted_b_commit_ready(commit_ready[1]),
        .trusted_b_commit_row(K_WIDTH'(commit_destination[1])), .trusted_b_commit_data(b_commit_data),
        .trusted_result_read_col(peek_col), .trusted_result_row_commit(retire_row)
    );

    always_ff @(posedge clk) begin
        if (reset || abort || security_fault) begin
            configured <= 1'b0;
            m_reg <= '0; k_reg <= '0; n_reg <= '0;
            config_error <= 1'b0;
        end else begin
            config_error <= 1'b0;
            if (config_fire) begin
                configured <= legal_shape;
                m_reg <= legal_shape ? config_m : '0;
                k_reg <= legal_shape ? config_k : '0;
                n_reg <= legal_shape ? config_n : '0;
                config_error <= !legal_shape;
            end
        end
    end
    // Cancellation never rewinds a storage cookie or a crypto IV counter.
    always_ff @(posedge clk) begin
        if (reset) begin cookie_counter <= '0; cookie_exhausted <= 1'b0; end
        else if (crypto_cmd_valid[2] && crypto_cmd_ready[2]) begin
            if (&cookie_counter) cookie_exhausted <= 1'b1;
            else cookie_counter <= cookie_counter + 1'b1;
        end
    end
    always_ff @(posedge clk) begin
        if (reset || abort || security_fault || clear[2]) begin
            output_state <= O_IDLE;
            output_row <= '0; output_tenant <= '0; output_bytes <= '0; output_words <= '0;
            read_index <= '0; fill_words <= '0; plain_reg <= '0; plain_keep <= '0; plain_last <= 1'b0;
            header_reg <= '0; cookie_reg <= '0; output_error <= '0;
        end else begin
            if (bad_peek || (failed_crypto && crypto_result_ready[2])) begin
                output_state <= O_RESULT;
                output_error <= bad_peek ? 4'd7 : crypto_result_error[2];
                output_tenant <= '0; plain_reg <= '0; plain_keep <= '0; plain_last <= 1'b0;
                header_reg <= '0; read_index <= '0; fill_words <= '0;
            end else case (output_state)
                O_IDLE: if (core_result_valid && core_tag_valid) begin
                    if (cookie_exhausted) begin output_state <= O_RESULT; output_error <= 4'd9; end
                    else begin
                        output_row <= core_result_row;
                        output_tenant <= core_result_tag;
                        output_words <= 32'(n_reg);
                        output_bytes <= 32'(n_reg)*ACC_BYTES;
                        read_index <= 0; fill_words <= 0;
                        output_state <= O_COMMAND;
                    end
                end
                O_COMMAND: if (crypto_cmd_ready[2]) begin
                    cookie_reg <= cookie_counter;
                    output_state <= O_FILL;
                end
                O_FILL: begin
                    plain_reg[MEM_DATA_W-1-ACC_WIDTH*fill_words -: ACC_WIDTH] <= core_result_data;
                    for (int b = 0; b < ACC_BYTES; b++) plain_keep[MEM_BYTES-1-ACC_BYTES*fill_words-b] <= 1'b1;
                    read_index <= read_index + 1;
                    fill_words <= fill_words + 1;
                    if (fill_words + 1 == WORDS_PER_BEAT || read_index + 1 == output_words) begin
                        plain_last <= read_index + 1 == output_words;
                        output_state <= O_SEND;
                    end
                end
                O_SEND: if (crypto_in_ready[2]) begin
                    plain_reg <= '0; plain_keep <= '0; plain_last <= 1'b0; fill_words <= 0;
                    if (plain_last) output_state <= O_FINISH;
                    else output_state <= O_FILL;
                end
                O_FINISH: if (crypto_result_valid[2]) begin
                    header_reg <= {FRAME_MAGIC, crypto_result_iv[2], crypto_result_tag[2]};
                    output_state <= O_HEADER;
                end
                O_HEADER: if (store_header_ready) output_state <= O_ACK;
                O_ACK: if (acknowledge) begin
                    output_error <= retire_row ? 4'd0 : 4'd8;
                    output_state <= O_RESULT;
                    header_reg <= '0; output_tenant <= '0; output_bytes <= '0; output_words <= '0;
                    read_index <= '0; fill_words <= '0; cookie_reg <= '0; output_row <= '0;
                end
                O_RESULT: if (store_result_ready) begin
                    output_state <= O_IDLE;
                    output_error <= '0;
                    output_row <= '0; output_tenant <= '0; output_bytes <= '0; output_words <= '0;
                    read_index <= '0; fill_words <= '0; cookie_reg <= '0;
                end
                default: output_state <= O_IDLE;
            endcase
        end
    end
    initial begin
`ifndef ENABLE_SECURE_MEMORY
        $fatal(1, "secure_memory_accelerator requires ENABLE_SECURE_MEMORY");
`endif
`ifndef ENABLE_SECURE_TAGS
        $fatal(1, "secure_memory_accelerator requires ENABLE_SECURE_TAGS");
`endif
        if (MAX_M < 1 || MAX_K < 1 || MAX_N < 1 || ROWS < 1 || COLS < 1 || WEIGHTS_PER_PE < 1)
            $fatal(1, "Secure memory dimensions and banks must be positive");
        if (DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0 || ACC_WIDTH < 8 || ACC_WIDTH % 8 != 0 ||
            ACC_WIDTH > MEM_DATA_W || MEM_DATA_W % ACC_WIDTH != 0)
            $fatal(1, "Secure memory needs byte widths and whole accumulator words per beat");
        if (COOKIE_W < 1 || COOKIE_W > 64) $fatal(1, "Secure memory COOKIE_W must be 1 through 64");
    end
endmodule
