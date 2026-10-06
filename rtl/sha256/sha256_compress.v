// sha256_compress.v - antarmuka SHA-256 sesuai docs/kontrak.md bagian 3.1.
//
// Pemilik: RTL A. Pembungkus tipis di atas sha256_core (isinya ada di sana):
// hanya mengganti nama port h_in/h_out menjadi state_in/state_out.
//   start     : pulsa 1 cycle; block dan state_in dikunci saat start
//   state_in  : H0..H7 (H0 di [255:224]); blok pertama = IV SHA-256
//   block     : satu blok 64 byte, byte pertama di [511:504]
//   state_out : state_in + hasil 64 ronde (feed-forward sudah termasuk)
//   done      : pulsa 1 cycle saat state_out valid
//   busy      : tinggi selama bekerja
// Latensi: 64 cycle dari start diterima sampai done (target kontrak <= 66).
`timescale 1ns/1ps
`default_nettype none
module sha256_compress (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire [255:0] state_in,
    input  wire [511:0] block,
    output wire [255:0] state_out,
    output wire         done,
    output wire         busy
);
    sha256_core u_core (
        .clk  (clk),
        .rst  (rst),
        .start(start),
        .block(block),
        .h_in (state_in),
        .h_out(state_out),
        .busy (busy),
        .done (done)
    );
endmodule
`default_nettype wire
