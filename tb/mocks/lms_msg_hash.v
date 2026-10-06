`timescale 1ns/1ps
// TIRUAN lms_msg_hash, KHUSUS testbench lms_verifier_core.
// Port sama dengan kontrak 3.5. Membaca 4 word pertama IMG_RAM (menguji mux
// alamat), lalu Q = {I, q, C[95:0]} ^ {header be32, 128'b0}. Bukan SHA-256.
module lms_msg_hash (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,
  input  wire [127:0] I,
  input  wire [31:0]  q,
  input  wire [255:0] C,
  input  wire [15:0]  img_len,
  output reg  [11:0]  img_addr,
  input  wire [31:0]  img_rdata,
  output reg  [255:0] Q,
  output reg          done,
  output wire         busy
);
  integer n_start = 0;
  reg busy_r = 0;
  assign busy = busy_r;
  initial begin img_addr = 0; done = 0; Q = 0; end

  function [31:0] be32; input [31:0] w; be32 = {w[7:0], w[15:8], w[23:16], w[31:24]}; endfunction

  always @(posedge clk) begin : run
    integer k;
    reg [127:0] hdr;
    if (start && !rst) begin
      n_start = n_start + 1;
      busy_r <= 1;
      for (k = 0; k < 4; k = k + 1) begin
        img_addr <= k;
        @(posedge clk); @(posedge clk);
        hdr[127 - 32*k -: 32] = be32(img_rdata);
      end
      Q <= {I, q, C[95:0]} ^ {hdr, 128'd0};
      done <= 1; busy_r <= 0;
      @(posedge clk);
      done <= 0;
    end
  end
  // reset menghentikan proses yang sedang berjalan
  always @(posedge clk) if (rst) begin
    disable run;
    img_addr <= 0; done <= 0; busy_r <= 0;
  end
endmodule
