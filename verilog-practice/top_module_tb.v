`timescale 1ns/1ps

module top_module_tb;

    reg a;
    reg b;
    wire out;

    top_module dut (
        .a(a),
        .b(b),
        .out(out)
    );

    initial begin
        $dumpfile("wave.vcd");
        $dumpvars(0, top_module_tb);
        $monitor("time=%0t a=%b b=%b out=%b",
                 $time, a, b, out);

        a = 0; b = 0;
        #10;

        a = 0; b = 1;
        #10;

        a = 1; b = 0;
        #10;

        a = 1; b = 1;
        #10;

        $finish;
    end

endmodule