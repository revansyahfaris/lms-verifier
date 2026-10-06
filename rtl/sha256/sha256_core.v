// sha256_core.v - core SHA-256 lengkap: satu blok 512-bit per perintah start.
//
// Pemilik: RTL A. Mengikuti docs/kontrak.md: clock 50 MHz, reset aktif-tinggi
// sinkron, big-endian (block[511:480] = W0, h_in[255:224] = H0).
// Padding TIDAK dilakukan di sini (tugas sha256_stream / modul hash pesan panjang).
//
// Yang ada di dalam: ROM K, message schedule (register geser 16 kata),
// penghitung ronde 0..63 dengan mesin status diam/jalan, feed-forward
// (h_out = h_in + A..H per kata 32 bit), dan antarmuka start/busy/done.
// Logika satu ronde diambil dari sha256_round (logika ronde baseline TT07).
//
// Waktu: start diterima di tepi clock ke-0; tepi ke-1 sampai ke-64 menjalankan
// ronde 0..63; setelah tepi ke-64 done = 1 selama tepat 1 cycle. h_out bertahan
// sampai blok berikutnya selesai. start saat busy diabaikan. Input dikunci saat start.
`timescale 1ns/1ps
`default_nettype none
module sha256_core (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire [511:0] block,
    input  wire [255:0] h_in,
    output reg  [255:0] h_out,
    output reg          busy,
    output reg          done
);
    // ---- ROM konstanta K (FIPS 180-4 bagian 4.2.2) ----
    function [31:0] k_rom;
        input [5:0] t;
        case (t)
            6'd0: k_rom = 32'h428a2f98;
            6'd1: k_rom = 32'h71374491;
            6'd2: k_rom = 32'hb5c0fbcf;
            6'd3: k_rom = 32'he9b5dba5;
            6'd4: k_rom = 32'h3956c25b;
            6'd5: k_rom = 32'h59f111f1;
            6'd6: k_rom = 32'h923f82a4;
            6'd7: k_rom = 32'hab1c5ed5;
            6'd8: k_rom = 32'hd807aa98;
            6'd9: k_rom = 32'h12835b01;
            6'd10: k_rom = 32'h243185be;
            6'd11: k_rom = 32'h550c7dc3;
            6'd12: k_rom = 32'h72be5d74;
            6'd13: k_rom = 32'h80deb1fe;
            6'd14: k_rom = 32'h9bdc06a7;
            6'd15: k_rom = 32'hc19bf174;
            6'd16: k_rom = 32'he49b69c1;
            6'd17: k_rom = 32'hefbe4786;
            6'd18: k_rom = 32'h0fc19dc6;
            6'd19: k_rom = 32'h240ca1cc;
            6'd20: k_rom = 32'h2de92c6f;
            6'd21: k_rom = 32'h4a7484aa;
            6'd22: k_rom = 32'h5cb0a9dc;
            6'd23: k_rom = 32'h76f988da;
            6'd24: k_rom = 32'h983e5152;
            6'd25: k_rom = 32'ha831c66d;
            6'd26: k_rom = 32'hb00327c8;
            6'd27: k_rom = 32'hbf597fc7;
            6'd28: k_rom = 32'hc6e00bf3;
            6'd29: k_rom = 32'hd5a79147;
            6'd30: k_rom = 32'h06ca6351;
            6'd31: k_rom = 32'h14292967;
            6'd32: k_rom = 32'h27b70a85;
            6'd33: k_rom = 32'h2e1b2138;
            6'd34: k_rom = 32'h4d2c6dfc;
            6'd35: k_rom = 32'h53380d13;
            6'd36: k_rom = 32'h650a7354;
            6'd37: k_rom = 32'h766a0abb;
            6'd38: k_rom = 32'h81c2c92e;
            6'd39: k_rom = 32'h92722c85;
            6'd40: k_rom = 32'ha2bfe8a1;
            6'd41: k_rom = 32'ha81a664b;
            6'd42: k_rom = 32'hc24b8b70;
            6'd43: k_rom = 32'hc76c51a3;
            6'd44: k_rom = 32'hd192e819;
            6'd45: k_rom = 32'hd6990624;
            6'd46: k_rom = 32'hf40e3585;
            6'd47: k_rom = 32'h106aa070;
            6'd48: k_rom = 32'h19a4c116;
            6'd49: k_rom = 32'h1e376c08;
            6'd50: k_rom = 32'h2748774c;
            6'd51: k_rom = 32'h34b0bcb5;
            6'd52: k_rom = 32'h391c0cb3;
            6'd53: k_rom = 32'h4ed8aa4a;
            6'd54: k_rom = 32'h5b9cca4f;
            6'd55: k_rom = 32'h682e6ff3;
            6'd56: k_rom = 32'h748f82ee;
            6'd57: k_rom = 32'h78a5636f;
            6'd58: k_rom = 32'h84c87814;
            6'd59: k_rom = 32'h8cc70208;
            6'd60: k_rom = 32'h90befffa;
            6'd61: k_rom = 32'ha4506ceb;
            6'd62: k_rom = 32'hbef9a3f7;
            6'd63: k_rom = 32'hc67178f2;
            default: k_rom = 32'h0;
        endcase
    endfunction

    function [31:0] rotr;
        input [31:0] x;
        input integer n;
        rotr = (x >> n) | (x << (32 - n));
    endfunction

    // ---- register ----
    reg [31:0]  a, b, c, d, e, f, g, h;   // A-H kerja
    reg [255:0] hin_q;                    // nilai awal, ditahan untuk feed-forward
    reg [511:0] sr;                       // jendela 16 kata W; sr[511:480] = W[t]
    reg [5:0]   t;                        // penghitung ronde 0..63

    // ---- message schedule: tiap ronde menghasilkan W[t+16] ----
    wire [31:0] w_cur = sr[511:480];      // W[t]      (kata tertua, dipakai ronde ini)
    wire [31:0] w_m15 = sr[479:448];      // W[t+1]    (= W[(t+16)-15])
    wire [31:0] w_m7  = sr[223:192];      // W[t+9]    (= W[(t+16)-7])
    wire [31:0] w_m2  = sr[63:32];        // W[t+14]   (= W[(t+16)-2])
    wire [31:0] sig0  = rotr(w_m15, 7)  ^ rotr(w_m15, 18) ^ (w_m15 >> 3);
    wire [31:0] sig1  = rotr(w_m2, 17)  ^ rotr(w_m2, 19)  ^ (w_m2 >> 10);
    wire [31:0] w_new = sig1 + w_m7 + sig0 + w_cur;

    // ---- satu ronde (kombinasional) ----
    wire [31:0] na, nb, nc, nd, ne, nf, ng, nh;
    sha256_round u_round (
        .a_i(a), .b_i(b), .c_i(c), .d_i(d), .e_i(e), .f_i(f), .g_i(g), .h_i(h),
        .w(w_cur), .k(k_rom(t)),
        .a_o(na), .b_o(nb), .c_o(nc), .d_o(nd), .e_o(ne), .f_o(nf), .g_o(ng), .h_o(nh)
    );

    always @(posedge clk) begin
        if (rst) begin
            busy  <= 1'b0;
            done  <= 1'b0;
            t     <= 6'd0;
            h_out <= 256'd0;
        end else begin
            done <= 1'b0;                          // done hanya pulsa 1 cycle
            if (!busy) begin
                if (start) begin                   // kunci input, mulai
                    {a, b, c, d, e, f, g, h} <= h_in;
                    hin_q <= h_in;
                    sr    <= block;
                    t     <= 6'd0;
                    busy  <= 1'b1;
                end
            end else begin
                {a, b, c, d, e, f, g, h} <= {na, nb, nc, nd, ne, nf, ng, nh};
                sr <= {sr[479:0], w_new};
                t  <= t + 6'd1;
                if (t == 6'd63) begin
                    // feed-forward per kata 32 bit (tanpa carry antar-kata)
                    h_out[255:224] <= hin_q[255:224] + na;
                    h_out[223:192] <= hin_q[223:192] + nb;
                    h_out[191:160] <= hin_q[191:160] + nc;
                    h_out[159:128] <= hin_q[159:128] + nd;
                    h_out[127:96]  <= hin_q[127:96]  + ne;
                    h_out[95:64]   <= hin_q[95:64]   + nf;
                    h_out[63:32]   <= hin_q[63:32]   + ng;
                    h_out[31:0]    <= hin_q[31:0]    + nh;
                    busy <= 1'b0;
                    done <= 1'b1;
                end
            end
        end
    end
endmodule
`default_nettype wire
