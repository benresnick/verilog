// GCM field multiplication, NIST SP 800-38D, section 6.3 (Algorithm 1).
// Bit 127 represents the coefficient of x^0. The reduction polynomial is
// x^128 + x^7 + x^2 + x + 1. This is a combinational, fixed-size circuit.
module gf128_mul (
    input  logic [127:0] x,
    input  logic [127:0] y,
    output wire  [127:0] product
);
    function automatic [127:0] multiply(input logic [127:0] a, b);
        logic [127:0] z, v;
        begin
            z = '0;
            v = b;
            for (int bit_index = 127; bit_index >= 0; bit_index--) begin
                z = z ^ (v & {128{a[bit_index]}});
                v = (v >> 1) ^ (128'he1000000000000000000000000000000 & {128{v[0]}});
            end
            multiply = z;
        end
    endfunction
    assign product = multiply(x, y);
endmodule
