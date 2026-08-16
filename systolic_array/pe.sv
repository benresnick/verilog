module pe #(
    parameter DATA_WIDTH = 8,
    parameter ACC_WIDTH  = 32
)(
    input  logic clk,
    input  logic reset,
    input  logic clear_acc,

    input  logic signed [DATA_WIDTH-1:0] activation_in,
    input  logic                         activation_valid_in,

    input  logic signed [DATA_WIDTH-1:0] weight_in,
    input  logic                         weight_valid_in,

    output logic signed [DATA_WIDTH-1:0] activation_out,
    output logic                         activation_valid_out,

    output logic signed [DATA_WIDTH-1:0] weight_out,
    output logic                         weight_valid_out,

    output logic signed [ACC_WIDTH-1:0] partial_sum
);

    localparam PRODUCT_WIDTH = 2 * DATA_WIDTH;
    logic signed [PRODUCT_WIDTH-1:0] product;
    assign product = activation_in * weight_in;

    always_ff @(posedge clk) begin
        if (reset) begin
            activation_out       <= '0;
            activation_valid_out <= 1'b0;
            weight_out           <= '0;
            weight_valid_out     <= 1'b0;
            partial_sum          <= '0;
        end
        else begin
            // Pass activation to the right
            activation_out       <= activation_in;
            activation_valid_out <= activation_valid_in;

            // Pass weight downward
            weight_out           <= weight_in;
            weight_valid_out     <= weight_valid_in;

            // Control the stationary accumulator
            if (clear_acc) begin
                if(activation_valid_in && weight_valid_in)
                    partial_sum <= product;
                else
                    partial_sum <= '0;
            end
            else if (activation_valid_in && weight_valid_in) begin
                partial_sum <= partial_sum + product;
            end
        end
    end

endmodule