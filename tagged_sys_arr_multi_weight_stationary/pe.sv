// One weight-stationary processing element.  A load token carries its
// destination row and slot; it is forwarded vertically until that row captures
// it.  This avoids confusing consecutive bottom-first tokens from different
// local banks.
module pe #(
    parameter int DATA_WIDTH = 8,
    parameter int ACC_WIDTH = 32,
    parameter int WEIGHTS_PER_PE = 1,
    parameter int ROW_ID = 0,
    parameter int SLOT_WIDTH = (WEIGHTS_PER_PE <= 1) ? 1 : $clog2(WEIGHTS_PER_PE),
    parameter int ROW_WIDTH = 1
) (
    input logic clk, input logic reset,
    input logic signed [DATA_WIDTH-1:0] activation_in,
    input logic activation_valid_in,
    input logic weight_load,
    input logic signed [DATA_WIDTH-1:0] weight_in,
    input logic weight_valid_in,
    input logic [SLOT_WIDTH-1:0] weight_slot_in,
    input logic [ROW_WIDTH-1:0] weight_target_row_in,
    input logic [SLOT_WIDTH-1:0] selected_slot,
    input logic signed [ACC_WIDTH-1:0] psum_in,
    input logic psum_valid_in,
    output logic signed [DATA_WIDTH-1:0] activation_out,
    output logic activation_valid_out,
    output logic signed [DATA_WIDTH-1:0] weight_out,
    output logic weight_valid_out,
    output logic [SLOT_WIDTH-1:0] weight_slot_out,
    output logic [ROW_WIDTH-1:0] weight_target_row_out,
    output logic signed [ACC_WIDTH-1:0] psum_out,
    output logic psum_valid_out
);
    localparam int PRODUCT_WIDTH = 2 * DATA_WIDTH;
    logic signed [DATA_WIDTH-1:0] stored_weight [0:WEIGHTS_PER_PE-1];
    logic stored_weight_valid [0:WEIGHTS_PER_PE-1];
    logic selected_weight_valid;
    logic signed [DATA_WIDTH-1:0] selected_weight;
    logic signed [PRODUCT_WIDTH-1:0] product;
    logic signed [ACC_WIDTH-1:0] product_extended;

    always_comb begin
        selected_weight = '0;
        selected_weight_valid = 1'b0;
        if (selected_slot < WEIGHTS_PER_PE) begin
            selected_weight = stored_weight[selected_slot];
            selected_weight_valid = stored_weight_valid[selected_slot];
        end
    end

    // Assignment to a wider signed destination performs the required
    // sign-extension of the full precision product.
    assign product          = activation_in * selected_weight;
    assign product_extended = product;

`ifndef SYNTHESIS
    initial begin
        if (ACC_WIDTH < PRODUCT_WIDTH)
            $error("pe: ACC_WIDTH (%0d) must be at least 2*DATA_WIDTH (%0d)",
                   ACC_WIDTH, PRODUCT_WIDTH);
    end
`endif

    always_ff @(posedge clk) begin
        if (reset) begin
            activation_out <= '0; activation_valid_out <= 1'b0;
            weight_out <= '0; weight_valid_out <= 1'b0;
            weight_slot_out <= '0; weight_target_row_out <= '0;
            psum_out <= '0; psum_valid_out <= 1'b0;
            for (int i = 0; i < WEIGHTS_PER_PE; i++) begin
                stored_weight[i] <= '0;
                stored_weight_valid[i] <= 1'b0;
            end
        end else begin
            activation_out <= activation_in;
            activation_valid_out <= activation_valid_in;
            weight_out <= weight_in; weight_valid_out <= weight_valid_in;
            weight_slot_out <= weight_slot_in; weight_target_row_out <= weight_target_row_in;
            if (weight_load && weight_target_row_in == ROW_ID && weight_slot_in < WEIGHTS_PER_PE) begin
                stored_weight[weight_slot_in] <= weight_in;
                stored_weight_valid[weight_slot_in] <= weight_valid_in;
            end
            if (weight_load) psum_valid_out <= 1'b0;
            else if (psum_valid_in) begin
                // A padded K row transparently forwards its valid psum.
                psum_out <= selected_weight_valid && activation_valid_in ? psum_in + product_extended : psum_in;
                psum_valid_out <= 1'b1;
            end else psum_valid_out <= 1'b0;
        end
    end
endmodule
