# README

To compile and sim:

```bash
iverilog -o sim top_module.v top_module_tb.v
vvp sim

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
