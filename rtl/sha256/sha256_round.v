// sha256_round.v - satu ronde SHA-256, kombinasional (tanpa clock).
//
// Pemilik: RTL A.
// Rumus mengikuti FIPS 180-4 bagian 6.2.2 (s1, ch, temp1, s0, maj, temp2 dan
// geser A-H), struktur yang sama dengan ronde di baseline TT07
// (rtl/sha256/third_party/tt_um_xeniarose_sha256.v, xenia dragon, Apache-2.0).
// Baseline itu sendiri tidak diubah; modul ini hanya mengambil logika rondenya.
//
// input : A-H lama, W (kata schedule ronde ini), K (konstanta ronde ini)
// output: A-H baru
`timescale 1ns/1ps
`default_nettype none
module sha256_round (
    input  wire [31:0] a_i, b_i, c_i, d_i, e_i, f_i, g_i, h_i,
    input  wire [31:0] w,
    input  wire [31:0] k,
    output wire [31:0] a_o, b_o, c_o, d_o, e_o, f_o, g_o, h_o
);
    function [31:0] rotr;
        input [31:0] x;
        input integer n;
        rotr = (x >> n) | (x << (32 - n));
    endfunction

    wire [31:0] s1    = rotr(e_i, 6) ^ rotr(e_i, 11) ^ rotr(e_i, 25);
    wire [31:0] ch    = (e_i & f_i) ^ (~e_i & g_i);
    wire [31:0] temp1 = h_i + s1 + ch + k + w;
    wire [31:0] s0    = rotr(a_i, 2) ^ rotr(a_i, 13) ^ rotr(a_i, 22);
    wire [31:0] maj   = (a_i & b_i) ^ (a_i & c_i) ^ (b_i & c_i);
    wire [31:0] temp2 = s0 + maj;

    assign a_o = temp1 + temp2;
    assign b_o = a_i;
    assign c_o = b_i;
    assign d_o = c_i;
    assign e_o = d_i + temp1;
    assign f_o = e_i;
    assign g_o = f_i;
    assign h_o = g_i;
endmodule
`default_nettype wire
