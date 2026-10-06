// tb_sha256.v - uji sha256_compress (antarmuka kontrak 3.1) beserta sha256_core.
//
// Data dari tv/sha256/{blocks,state_in,state_out}.hex (dibuat python/gen_sha256_vectors.py):
// "abc", pesan kosong, pesan 2 blok NIST (state_in blok 2 = state_out blok 1),
// batas padding 55/56/64 byte, dan blok acak. Setiap baris dicek penuh.
// Dicek juga: done pulsa tepat 1 cycle, busy turun saat done, input dikunci saat start,
// dan latensi <= 66 cycle (target kontrak).
`timescale 1ns/1ps
`default_nettype none
module tb_sha256;
    localparam MAXV = 256;

    reg          clk = 1'b0;
    reg          rst = 1'b1;
    reg          start = 1'b0;
    reg  [511:0] block = 512'd0;
    reg  [255:0] state_in = 256'd0;
    wire [255:0] state_out;
    wire         done, busy;

    reg [511:0] blocks     [0:MAXV-1];
    reg [255:0] states_in  [0:MAXV-1];
    reg [255:0] states_out [0:MAXV-1];

    sha256_compress dut (
        .clk(clk), .rst(rst), .start(start),
        .state_in(state_in), .block(block),
        .state_out(state_out), .done(done), .busy(busy)
    );

    always #10 clk = ~clk;   // 50 MHz

    integer n, nb, ni, no;
    integer i, cycles, max_cycles, errors;

    initial begin
`ifdef DUMP_VCD
        $dumpfile("build/sha256.vcd");
        $dumpvars(0, tb_sha256);
`endif
        errors = 0;
        max_cycles = 0;
        $readmemh("tv/sha256/blocks.hex",    blocks);
        $readmemh("tv/sha256/state_in.hex",  states_in);
        $readmemh("tv/sha256/state_out.hex", states_out);

        // jumlah baris terisi = entri pertama yang masih x
        nb = 0; while (nb < MAXV && ^blocks[nb]     !== 1'bx) nb = nb + 1;
        ni = 0; while (ni < MAXV && ^states_in[ni]  !== 1'bx) ni = ni + 1;
        no = 0; while (no < MAXV && ^states_out[no] !== 1'bx) no = no + 1;
        n = nb;
        if (n == 0 || ni != nb || no != nb) begin
            $display("TEST FAILED: file tv/sha256 kosong atau jumlah barisnya tidak sama");
            $finish;
        end

        repeat (3) @(negedge clk);
        rst = 1'b0;
        @(negedge clk);
        if (done !== 1'b0 || busy !== 1'b0) begin
            errors = errors + 1;
            $display("  setelah reset done/busy harus 0");
        end

        for (i = 0; i < n; i = i + 1) begin
            block    = blocks[i];
            state_in = states_in[i];
            start    = 1'b1;
            @(negedge clk);
            start    = 1'b0;
            // input sudah dikunci; ganti dengan sampah, hasil tidak boleh berubah
            block    = ~blocks[i];
            state_in = ~states_in[i];
            cycles   = 1;
            while (!done && cycles < 200) begin
                @(negedge clk);
                cycles = cycles + 1;
            end
            if (!done) begin
                errors = errors + 1;
                $display("  vektor %0d: done tidak pernah muncul", i);
            end else begin
                if (state_out !== states_out[i]) begin
                    errors = errors + 1;
                    $display("  vektor %0d: state_out salah", i);
                    $display("    dapat  : %h", state_out);
                    $display("    harusnya: %h", states_out[i]);
                end
                if (busy !== 1'b0) begin
                    errors = errors + 1;
                    $display("  vektor %0d: busy masih 1 saat done", i);
                end
                if (cycles > 66) begin
                    errors = errors + 1;
                    $display("  vektor %0d: latensi %0d cycle (> 66)", i, cycles);
                end
                if (cycles > max_cycles) max_cycles = cycles;
                @(negedge clk);
                if (done !== 1'b0) begin
                    errors = errors + 1;
                    $display("  vektor %0d: done lebih dari 1 cycle", i);
                end
            end
            @(negedge clk);
        end

        $display("%0d vektor, latensi maks %0d cycle (dihitung dari start sampai done)", n, max_cycles);
        if (errors == 0) $display("TEST PASSED");
        else             $display("TEST FAILED: %0d kesalahan", errors);
        $finish;
    end

    initial begin
        #2000000;
        $display("TEST FAILED: timeout");
        $finish;
    end
endmodule
`default_nettype wire
