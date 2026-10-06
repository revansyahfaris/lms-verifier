`timescale 1ns/1ps
// tb_lms_verifier_stub.v - stub: PASS jika magic benar, FAIL 0x07 jika salah.
module tb_lms_verifier_stub;
    reg clk = 0;
    always #10 clk = ~clk;

    reg         rst = 1, start = 0, commit = 0, hold = 0;
    wire [9:0]  sig_addr;
    wire [11:0] img_addr;
    reg  [31:0] img_rdata, sig_rdata = 0;
    wire        busy, done, pass, fail, cpu_release, buf_lock;
    wire [7:0]  err_code;
    wire [31:0] cycles, img_version, min_version;

    reg [31:0] img_mem [0:4095];
    always @(posedge clk) img_rdata <= img_mem[img_addr];

    lms_verifier_stub #(.STUB_DELAY(100)) dut (
        .clk(clk), .rst(rst), .start(start), .commit(commit), .hold(hold),
        .img_len(16'd1024), .sig_len(16'd1296),
        .sig_addr(sig_addr), .sig_rdata(sig_rdata),
        .img_addr(img_addr), .img_rdata(img_rdata),
        .busy(busy), .done(done), .pass(pass), .fail(fail), .err_code(err_code),
        .cycles(cycles), .img_version(img_version), .min_version(min_version),
        .cpu_release(cpu_release), .buf_lock(buf_lock)
    );

    function [31:0] sw32; input [31:0] w; sw32 = {w[7:0], w[15:8], w[23:16], w[31:24]}; endfunction

    integer errors = 0;
    task pulse_start; begin @(negedge clk) start = 1; @(negedge clk) start = 0; end endtask
    task pulse_hold;  begin @(negedge clk) hold  = 1; @(negedge clk) hold  = 0; end endtask
    task run; begin pulse_start; while (!done) @(posedge clk); repeat (3) @(posedge clk); end endtask

    initial begin
`ifdef DUMP_VCD
        $dumpfile("build/lms_verifier_stub.vcd");
        $dumpvars(0, tb_lms_verifier_stub);
`endif
        img_mem[0] = sw32(32'h5046_5731);   // "PFW1"
        img_mem[1] = sw32(32'd3);
        repeat (3) @(posedge clk); rst = 0;

        run;
        if (!pass || fail || err_code != 8'h00 || !cpu_release || !buf_lock || img_version != 3) begin
            $display("  salah: magic benar tidak PASS"); errors = errors + 1; end

        pulse_hold; repeat (2) @(posedge clk);
        if (cpu_release || buf_lock) begin $display("  salah: HOLD tidak bekerja"); errors = errors + 1; end

        img_mem[0] = sw32(32'hDEAD_BEEF);
        run;
        if (pass || !fail || err_code != 8'h07 || cpu_release) begin
            $display("  salah: magic salah tidak FAIL 0x07"); errors = errors + 1; end

        if (errors == 0) $display("TEST PASSED");
        else             $display("TEST FAILED: %0d cek salah", errors);
        $finish;
    end

    initial begin #1_000_000; $display("TEST FAILED: timeout"); $finish; end
endmodule
