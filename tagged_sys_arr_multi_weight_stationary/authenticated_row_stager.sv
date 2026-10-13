// Collect an already-authenticated plaintext stream for one atomic row write.
// This module does not authenticate ciphertext: its input and finish ports
// must connect to a trusted decrypt engine and its held terminal result.
// Bytes are MSB-first on both interfaces; unused commit bytes are zero.
//
// A successful finish remains unacknowledged until the consumer accepts the
// complete row on the same edge. This keeps the decrypt engine's key ownership
// alive until the destination and its tenant metadata commit atomically.
module authenticated_row_stager #(
    parameter int MEM_DATA_W = 128,
    parameter int MAX_RECORD_BYTES = 64
) (
    input logic clk, reset, clear,
    input logic start_valid,
    output wire start_ready,
    input logic [31:0] start_bytes,
    input logic [95:0] start_tenant,
    input logic [63:0] start_destination,
    input logic in_valid,
    output wire in_ready,
    input logic [MEM_DATA_W-1:0] in_data,
    input logic [MEM_DATA_W/8-1:0] in_keep,
    input logic in_last,
    input logic [95:0] in_tenant,
    input logic [63:0] in_destination,
    input logic finish_valid,
    output wire finish_ready,
    input logic [3:0] finish_error,
    output wire commit_valid,
    input logic commit_ready,
    output wire [MAX_RECORD_BYTES*8-1:0] commit_data,
    output wire [31:0] commit_bytes,
    output wire [95:0] commit_tenant,
    output wire [63:0] commit_destination,
    output wire result_valid,
    input logic result_ready,
    output wire [3:0] result_error
);
    localparam int MEM_BYTES = MEM_DATA_W / 8;
    localparam logic [3:0] OK = 0, LENGTH_ERROR = 3, RECORD_PROTOCOL_ERROR = 7;
    typedef enum logic [1:0] {IDLE, ACTIVE, RESULT} state_t;
    state_t state;
    logic [MAX_RECORD_BYTES*8-1:0] stage_reg;
    logic [31:0] bytes_reg, received_reg;
    logic [95:0] tenant_reg;
    logic [63:0] destination_reg;
    logic last_reg, protocol_error_reg;
    logic [3:0] result_error_reg;
    logic [MEM_BYTES-1:0] required_keep;
    wire enabled = !reset && !clear;
    wire [31:0] remaining = bytes_reg - received_reg;

    always @* begin
        for (int b = 0; b < MEM_BYTES; b++)
            required_keep[MEM_BYTES-1-b] = b < remaining;
    end
    // Case comparisons additionally fail closed on unknown provenance/framing
    // in simulation. In hardware these are ordinary full-width comparisons.
    wire malformed_beat = received_reg >= bytes_reg || last_reg ||
        in_keep !== required_keep || in_last !== (remaining <= MEM_BYTES) ||
        in_tenant !== tenant_reg || in_destination !== destination_reg;
    wire record_complete = !protocol_error_reg && received_reg === bytes_reg &&
                           (bytes_reg == 0 || last_reg);
    wire successful_finish = (finish_error === OK) && record_complete;

    assign start_ready = enabled && state == IDLE;
    // After a bad beat, continue accepting/discarding the engine's remaining
    // output so its terminal error can still arrive. Never acknowledge payload
    // on the finish edge: trusted engines finish only after their output drains.
    assign in_ready = enabled && state == ACTIVE && !finish_valid;
    assign commit_valid = enabled && state == ACTIVE && finish_valid && successful_finish;
    assign finish_ready = enabled && state == ACTIVE &&
                          (!successful_finish || commit_ready);
    assign commit_data = commit_valid ? stage_reg : '0;
    assign commit_bytes = commit_valid ? bytes_reg : 32'b0;
    assign commit_tenant = commit_valid ? tenant_reg : 96'b0;
    assign commit_destination = commit_valid ? destination_reg : 64'b0;
    assign result_valid = enabled && state == RESULT;
    assign result_error = result_valid ? result_error_reg : OK;

    initial begin
        if (MEM_DATA_W < 8 || MEM_DATA_W % 8 != 0)
            $fatal(1, "authenticated_row_stager MEM_DATA_W must be a positive whole-byte width");
        if (MAX_RECORD_BYTES < 1)
            $fatal(1, "authenticated_row_stager MAX_RECORD_BYTES must be positive");
    end

    always_ff @(posedge clk) begin
        if (reset || clear) begin
            state <= IDLE;
            stage_reg <= '0;
            bytes_reg <= '0;
            received_reg <= '0;
            tenant_reg <= '0;
            destination_reg <= '0;
            last_reg <= 1'b0;
            protocol_error_reg <= 1'b0;
            result_error_reg <= OK;
        end else begin
            case (state)
                IDLE: if (start_valid && start_ready) begin
                    if (start_bytes > MAX_RECORD_BYTES) begin
                        state <= RESULT;
                        result_error_reg <= LENGTH_ERROR;
                    end else begin
                        state <= ACTIVE;
                        bytes_reg <= start_bytes;
                        tenant_reg <= start_tenant;
                        destination_reg <= start_destination;
                    end
                end
                ACTIVE: begin
                    if (in_valid && in_ready) begin
                        if (malformed_beat || protocol_error_reg) begin
                            // A failed record can never become committable.
                            // Erase bytes immediately, while draining to finish.
                            stage_reg <= '0;
                            protocol_error_reg <= 1'b1;
                        end else begin
                            for (int b = 0; b < MEM_BYTES; b++) begin
                                if (b < remaining && received_reg + b < MAX_RECORD_BYTES)
                                    stage_reg[MAX_RECORD_BYTES*8-1-8*(received_reg+b) -: 8] <=
                                        in_data[MEM_DATA_W-1-8*b -: 8];
                            end
                            received_reg <= received_reg +
                                (remaining < MEM_BYTES ? remaining : 32'(MEM_BYTES));
                            last_reg <= in_last;
                        end
                    end
                    if (finish_valid && finish_ready) begin
                        state <= RESULT;
                        case (finish_error)
                            OK: result_error_reg <= record_complete ? OK : RECORD_PROTOCOL_ERROR;
                            1, 2, 3, 4, 5, 6: result_error_reg <= finish_error;
                            default: result_error_reg <= RECORD_PROTOCOL_ERROR;
                        endcase
                        stage_reg <= '0;
                        bytes_reg <= '0;
                        received_reg <= '0;
                        tenant_reg <= '0;
                        destination_reg <= '0;
                        last_reg <= 1'b0;
                        protocol_error_reg <= 1'b0;
                    end
                end
                RESULT: if (result_ready) begin
                    state <= IDLE;
                    result_error_reg <= OK;
                end
                default: begin
                    state <= IDLE;
                    stage_reg <= '0;
                    bytes_reg <= '0;
                    received_reg <= '0;
                    tenant_reg <= '0;
                    destination_reg <= '0;
                    last_reg <= 1'b0;
                    protocol_error_reg <= 1'b0;
                    result_error_reg <= OK;
                end
            endcase
        end
    end
endmodule
