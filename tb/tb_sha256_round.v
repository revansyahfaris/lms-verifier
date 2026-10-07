// tb_sha256_round.v - uji sha256_round (kombinasional) terhadap vektor dari Python.
// Data: tv/sha256/round_in.hex (A..H, W, K = 320 bit) dan round_out.hex (A..H baru = 256 bit).
`timescale 1ns/1ps
`default_nettype none
module tb_sha256_round;
    // NV harus sama dengan jumlah baris tv/sha256/round_{in,out}.hex (dicetak oleh generator).
    localparam NV = 16;

    reg [319:0] vin  [0:NV-1];
    reg [255:0] vout [0:NV-1];

    reg  [31:0] a, b, c, d, e, f, g, h, w, k;
    wire [31:0] ao, bo, co, do_, eo, fo, go, ho;

    sha256_round dut (
        .a_i(a), .b_i(b), .c_i(c), .d_i(d), .e_i(e), .f_i(f), .g_i(g), .h_i(h),
        .w(w), .k(k),
        .a_o(ao), .b_o(bo), .c_o(co), .d_o(do_), .e_o(eo), .f_o(fo), .g_o(go), .h_o(ho)
    );

    integer i, n, errors;

    initial begin
`ifdef DUMP_VCD
        $dumpfile("build/sha256_round.vcd");
        $dumpvars(0, tb_sha256_round);
`endif
        errors = 0;
        $readmemh("tv/sha256/round_in.hex",  vin);
        $readmemh("tv/sha256/round_out.hex", vout);
        n = NV;
        for (i = 0; i < NV; i = i + 1)
            if (^vin[i] === 1'bx || ^vout[i] === 1'bx) begin
                $display("TEST FAILED: tv/sha256/round_*.hex kurang dari %0d baris (sesuaikan NV)", NV);
                $finish;
            end
        for (i = 0; i < n; i = i + 1) begin
            {a, b, c, d, e, f, g, h, w, k} = vin[i];
            #1;
            if ({ao, bo, co, do_, eo, fo, go, ho} !== vout[i]) begin
                errors = errors + 1;
                $display("  vektor %0d: keluaran ronde salah", i);
            end
        end
        $display("%0d vektor ronde", n);
        if (errors == 0) $display("TEST PASSED");
        else             $display("TEST FAILED: %0d kesalahan", errors);
        $finish;
    end

    initial begin
        #100000;
        $display("TEST FAILED: timeout");
        $finish;
    end
endmodule
`default_nettype wire
