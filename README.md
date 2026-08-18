# README

To compile and sim:

```bash
iverilog -o sim top_module.v top_module_tb.v
vvp sim

```

To compile and sim (system verilog):

```bash
iverilog -g2012 -s pe_tb -o pe_sim pe.sv pe_tb.sv
vvp pe_sim

```

To open up surfer app

```
surfer wave.vcd
```

To use waveforms add this to your testbench

```verilog
initial begin
    $dumpfile("wave.vcd");
    $dumpvars(0, top_module_tb);
end
```
