`timescale 1ns/1ps
// TIRUAN lmots_verify, KHUSUS testbench lms_verifier_core.
// Port sama dengan kontrak 3.4. Meminta y[0..P-1] satu per satu lewat
// y_req/y_idx (menguji pengambil data di core), lalu Kc = Q ^ XOR(y).
module lmots_verify #(
  parameter W = 8, parameter P = 34, parameter LS = 0, parameter N_CORES = 1
) (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,
  input  wire [127:0] I,
  input  wire [31:0]  q,
  input  wire [255:0] Q,
  output reg          y_req,
  output reg  [6:0]   y_idx,
  input  wire [255:0] y_data,
  input  wire         y_valid,
  output reg  [255:0] Kc,
  output reg          done,
  output wire         busy
);
  integer n_start = 0;
  reg busy_r = 0;
  assign busy = busy_r;
  initial begin y_req = 0; y_idx = 0; done = 0; Kc = 0; end

  always @(posedge clk) begin : run
    integer k;
    reg [255:0] acc;
    if (start && !rst) begin
      n_start = n_start + 1;
      busy_r <= 1;
      acc = 256'd0;
      for (k = 0; k < P; k = k + 1) begin
        y_idx <= k; y_req <= 1;
        @(posedge clk); y_req <= 0;
        @(posedge clk);
        while (!y_valid) @(posedge clk);
        acc = acc ^ y_data;
      end
      Kc <= Q ^ acc;
      done <= 1; busy_r <= 0;
      @(posedge clk);
      done <= 0;
    end
  end
  // reset menghentikan proses yang sedang berjalan
  always @(posedge clk) if (rst) begin
    disable run;
    y_req <= 0; done <= 0; busy_r <= 0;
  end
endmodule
