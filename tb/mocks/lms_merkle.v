`timescale 1ns/1ps
// TIRUAN lms_merkle, KHUSUS testbench lms_verifier_core.
// Port sama dengan kontrak 3.6. Meminta path[0..H-1], lalu
// Tc = Kc ^ XOR(path) ^ {I, q, 96'b0}. Bukan pohon Merkle sungguhan.
module lms_merkle #(
  parameter H = 5
) (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,
  input  wire [127:0] I,
  input  wire [31:0]  q,
  input  wire [255:0] Kc,
  output reg          path_req,
  output reg  [2:0]   path_idx,
  input  wire [255:0] path_data,
  input  wire         path_valid,
  output reg  [255:0] Tc,
  output reg          done,
  output wire         busy
);
  integer n_start = 0;
  reg busy_r = 0;
  assign busy = busy_r;
  initial begin path_req = 0; path_idx = 0; done = 0; Tc = 0; end

  always @(posedge clk) begin : run
    integer k;
    reg [255:0] acc;
    if (start && !rst) begin
      n_start = n_start + 1;
      busy_r <= 1;
      acc = 256'd0;
      for (k = 0; k < H; k = k + 1) begin
        path_idx <= k; path_req <= 1;
        @(posedge clk); path_req <= 0;
        @(posedge clk);
        while (!path_valid) @(posedge clk);
        acc = acc ^ path_data;
      end
      Tc <= Kc ^ acc ^ {I, q, 96'd0};
      done <= 1; busy_r <= 0;
      @(posedge clk);
      done <= 0;
    end
  end
  // reset menghentikan proses yang sedang berjalan
  always @(posedge clk) if (rst) begin
    disable run;
    path_req <= 0; done <= 0; busy_r <= 0;
  end
endmodule
