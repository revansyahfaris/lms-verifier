`timescale 1ns/1ps
// lms_ctrl.v - FSM pengendali utama verifier LMS
//
// Mengurutkan verifikasi: kunci buffer -> cek header -> hash pesan ->
// 34 rantai hash -> kunci kandidat (Kc) -> pohon Merkle -> pembanding ganda.
// Reset prosesor hanya dilepas di state PASS.
//
// Aturan kontrak: clock 50 MHz, reset aktif-tinggi, handshake start/done.
// TODO kontrak: samakan kode error (ERR_*) dan nama bit CTRL/STATUS
//               dengan docs/kontrak.md sebelum merge ke main.
`include "lms_params.vh"

module lms_ctrl #(
    parameter [31:0]  FW_MAGIC    = 32'h4C4D5346,   // "LMSF", TODO: samakan dengan kontrak
    parameter [31:0]  MIN_VERSION = 32'd1,          // anti-rollback (prototipe: konstanta)
    parameter [255:0] PUBKEY_ROOT = 256'h0          // akar kunci publik tertanam (T[1])
) (
    input  wire         clk,
    input  wire         rst,            // aktif-tinggi

    // Perintah dari register CTRL (pulsa 1 cycle)
    input  wire         start,

    // Field header image dan tanda tangan (dibaca dari IMG_RAM / SIG_RAM)
    input  wire [31:0]  hdr_magic,
    input  wire [31:0]  hdr_version,
    input  wire [31:0]  hdr_len,        // panjang isi program, tanpa header
    input  wire [31:0]  sig_ots_type,
    input  wire [31:0]  sig_lms_type,
    input  wire [31:0]  sig_q,

    // Modul hash multi-blok (dipakai dua kali: pesan dan Kc)
    output reg          hash_start,
    output reg          hash_sel_kc,    // 0 = hash pesan (Q), 1 = kunci kandidat (Kc)
    input  wire         hash_done,

    // Pengatur 34 rantai hash
    output reg          chains_start,
    input  wire         chains_done,

    // Pohon Merkle
    output reg          merkle_start,
    input  wire         merkle_done,
    input  wire [255:0] root,           // akar hasil rekonstruksi

    // Status untuk register STATUS dan sistem
    output reg          busy,
    output reg          done,
    output reg          pass,
    output reg  [7:0]   err_code,
    output reg          buf_lock,       // 1 = HPS tidak boleh menulis IMG_RAM/SIG_RAM
    output reg          cpu_release,    // 1 = reset PicoRV32 dilepas
    output wire [3:0]   state_dbg
);

    // ---- Tipe parameter LMS sesuai RFC 8554 ----
    localparam [31:0] LMOTS_SHA256_N32_W8 = 32'h0000_0004;
    localparam [31:0] LMS_SHA256_M32_H5   = 32'h0000_0005;

    // ---- Kode error (TODO: samakan dengan kontrak) ----
    localparam [7:0] ERR_NONE     = 8'h00;
    localparam [7:0] ERR_MAGIC    = 8'h01;
    localparam [7:0] ERR_LEN      = 8'h02;
    localparam [7:0] ERR_ROLLBACK = 8'h03;
    localparam [7:0] ERR_TYPE     = 8'h04;
    localparam [7:0] ERR_Q        = 8'h05;
    localparam [7:0] ERR_SIG      = 8'h06;
    localparam [7:0] ERR_STATE    = 8'h07;

    // ---- State ----
    localparam [3:0] S_IDLE     = 4'd0;
    localparam [3:0] S_LOCK     = 4'd1;
    localparam [3:0] S_CHECK    = 4'd2;
    localparam [3:0] S_HASH_MSG = 4'd3;
    localparam [3:0] S_CHAINS   = 4'd4;
    localparam [3:0] S_KC       = 4'd5;
    localparam [3:0] S_MERKLE   = 4'd6;
    localparam [3:0] S_COMPARE  = 4'd7;
    localparam [3:0] S_PASS     = 4'd8;
    localparam [3:0] S_FAIL     = 4'd9;

    localparam [31:0] MAX_LEN = `FW_MAX_BYTES - `FW_HDR_BYTES;
    localparam [31:0] NUM_Q   = 32'd1 << `LMS_H;   // 32 kunci sekali-pakai

    reg [3:0] state;
    reg       sub_started;   // sub-modul sudah diberi pulsa start di state ini
    assign state_dbg = state;

    // ---- Pembanding ganda ----
    // Dua cara hitung berbeda + atribut keep supaya sintesis tidak
    // menggabungkannya jadi satu. Lolos hanya kalau keduanya setuju.
    (* keep *) wire match_a = (root == PUBKEY_ROOT);
    (* keep *) wire match_b = ~|(root ^ PUBKEY_ROOT);

    // ---- Cek header (kombinasional, dipakai di S_CHECK) ----
    reg [7:0] check_err;
    always @(*) begin
        if (hdr_magic != FW_MAGIC)                         check_err = ERR_MAGIC;
        else if (hdr_len == 32'd0 || hdr_len > MAX_LEN)    check_err = ERR_LEN;
        else if (hdr_version < MIN_VERSION)                check_err = ERR_ROLLBACK;
        else if (sig_ots_type != LMOTS_SHA256_N32_W8 ||
                 sig_lms_type != LMS_SHA256_M32_H5)        check_err = ERR_TYPE;
        else if (sig_q >= NUM_Q)                           check_err = ERR_Q;
        else                                               check_err = ERR_NONE;
    end

    // ---- FSM ----
    always @(posedge clk) begin
        if (rst) begin
            state        <= S_IDLE;
            sub_started  <= 1'b0;
            hash_start   <= 1'b0;
            hash_sel_kc  <= 1'b0;
            chains_start <= 1'b0;
            merkle_start <= 1'b0;
            err_code     <= ERR_NONE;
        end else begin
            // pulsa start ke sub-modul hanya 1 cycle
            hash_start   <= 1'b0;
            chains_start <= 1'b0;
            merkle_start <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start) begin
                        err_code <= ERR_NONE;
                        state    <= S_LOCK;
                    end
                end

                S_LOCK: state <= S_CHECK;

                S_CHECK: begin
                    if (check_err != ERR_NONE) begin
                        err_code <= check_err;
                        state    <= S_FAIL;
                    end else begin
                        state <= S_HASH_MSG;
                    end
                end

                S_HASH_MSG: begin
                    if (!sub_started) begin
                        hash_sel_kc <= 1'b0;
                        hash_start  <= 1'b1;
                        sub_started <= 1'b1;
                    end else if (hash_done) begin
                        sub_started <= 1'b0;
                        state       <= S_CHAINS;
                    end
                end

                S_CHAINS: begin
                    if (!sub_started) begin
                        chains_start <= 1'b1;
                        sub_started  <= 1'b1;
                    end else if (chains_done) begin
                        sub_started <= 1'b0;
                        state       <= S_KC;
                    end
                end

                S_KC: begin
                    if (!sub_started) begin
                        hash_sel_kc <= 1'b1;
                        hash_start  <= 1'b1;
                        sub_started <= 1'b1;
                    end else if (hash_done) begin
                        sub_started <= 1'b0;
                        state       <= S_MERKLE;
                    end
                end

                S_MERKLE: begin
                    if (!sub_started) begin
                        merkle_start <= 1'b1;
                        sub_started  <= 1'b1;
                    end else if (merkle_done) begin
                        sub_started <= 1'b0;
                        state       <= S_COMPARE;
                    end
                end

                S_COMPARE: begin
                    if (match_a && match_b) begin
                        state <= S_PASS;
                    end else begin
                        err_code <= ERR_SIG;
                        state    <= S_FAIL;
                    end
                end

                // Terminal: verifikasi ulang hanya lewat reset board
                S_PASS: state <= S_PASS;

                // Tunggu image lain dari HPS
                S_FAIL: begin
                    if (start) begin
                        err_code <= ERR_NONE;
                        state    <= S_LOCK;
                    end
                end

                // State tak dikenal: selalu berakhir aman
                default: begin
                    err_code    <= ERR_STATE;
                    sub_started <= 1'b0;
                    state       <= S_FAIL;
                end
            endcase
        end
    end

    // ---- Output terdaftar (bebas glitch) ----
    always @(posedge clk) begin
        if (rst) begin
            busy        <= 1'b0;
            done        <= 1'b0;
            pass        <= 1'b0;
            buf_lock    <= 1'b0;
            cpu_release <= 1'b0;
        end else begin
            busy        <= (state != S_IDLE) && (state != S_PASS) && (state != S_FAIL);
            done        <= (state == S_PASS) || (state == S_FAIL);
            pass        <= (state == S_PASS);
            buf_lock    <= (state != S_IDLE) && (state != S_FAIL);
            cpu_release <= (state == S_PASS);
        end
    end

endmodule
