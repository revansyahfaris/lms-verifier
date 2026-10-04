// Contoh pola testbench. Salin file ini untuk tes baru.
// Aturan: cetak "TEST PASSED" atau "TEST FAILED: ...", lalu $finish.
`timescale 1ns/1ps
`include "lms_params.vh"

module tb_smoke;
  reg clk = 0;
  reg rst = 1;                       // reset aktif-tinggi
  always #10 clk = ~clk;             // 50 MHz -> periode 20 ns

  integer errors = 0;

  // Bantuan untuk cek
  task check(input [255:0] got, input [255:0] exp, input [8*32-1:0] what);
    if (got !== exp) begin
      $display("  salah: %0s  got=%h exp=%h", what, got, exp);
      errors = errors + 1;
    end
  endtask

  initial begin
`ifdef DUMP_VCD
    $dumpfile("build/smoke.vcd");
    $dumpvars(0, tb_smoke);
`endif
    repeat (3) @(posedge clk);
    rst = 0;

    // Cek konstanta kontrak bisa dibaca dari header bersama
    check(`LMS_P,     34,   "LMS_P");
    check(`SIG_BYTES, 1296, "SIG_BYTES");

    // Batas waktu: jangan sampai tes jalan selamanya
    repeat (10) @(posedge clk);

    if (errors == 0) $display("TEST PASSED");
    else             $display("TEST FAILED: %0d cek salah", errors);
    $finish;
  end

  initial begin
    #1_000_000;
    $display("TEST FAILED: timeout");
    $finish;
  end
endmodule
