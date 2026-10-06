`timescale 1ns/1ps
`default_nettype none
// lms_verifier_core.v - pengendali utama verifier LMS (kontrak bagian 3.7)
//
// Urutan: LOAD (baca field dari SIG_RAM/IMG_RAM) -> CHECK (cek format) ->
// MSG (lms_msg_hash) -> OTS (lmots_verify) -> MRK (lms_merkle) ->
// CMP (pembanding redundan + cek versi) -> DONE.
//
// Aturan keamanan (kontrak bagian 6):
// - Public key hanya dari ROM, tidak ada register yang bisa mengubahnya.
// - Pembanding redundan: dua rangkaian berbeda, tidak sepakat -> FAULT.
// - Status PASS memakai pola multi-bit 8'hA5.
// - FSM one-hot; state ilegal -> FAULT, CPU tetap ditahan.
// - Buffer terkunci selama BUSY dan selama CPU berjalan.

module lms_verifier_core #(
    parameter N_CORES          = 1,
    parameter INIT_MIN_VERSION = 32'd1,
    parameter RAW_MSG_MODE     = 0,                 // 1 hanya untuk testbench data uji RFC
    parameter ROM_I_FILE       = "rom_I.hex",       // I: 32 karakter hex
    parameter ROM_T1_FILE      = "rom_T1.hex"       // T[1]: 64 karakter hex
) (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire         commit,
    input  wire         hold,
    input  wire [15:0]  img_len,
    input  wire [15:0]  sig_len,
    output wire [9:0]   sig_addr,
    input  wire [31:0]  sig_rdata,
    output wire [11:0]  img_addr,
    input  wire [31:0]  img_rdata,
    output wire         busy,
    output wire         done,
    output wire         pass,
    output wire         fail,
    output wire [7:0]   err_code,
    output wire [31:0]  cycles,
    output wire [31:0]  img_version,
    output wire [31:0]  min_version,
    output wire         cpu_release,
    output wire         buf_lock
);

    // ------------------------------------------------------------------
    // Konstanta (kontrak bagian 1 dan 4)
    // ------------------------------------------------------------------
    localparam [31:0] IMG_MAGIC  = 32'h5046_5731;   // "PFW1"
    localparam [31:0] OTS_TYPE   = 32'h0000_0004;   // LMOTS_SHA256_N32_W8
    localparam [31:0] LMS_TYPE   = 32'h0000_0005;   // LMS_SHA256_M32_H5
    localparam [15:0] SIG_BYTES  = 16'd1296;
    localparam [15:0] IMG_MIN    = 16'd16;
    localparam [15:0] IMG_MAX    = 16'd16384;
    localparam [31:0] NUM_LEAVES = 32'd32;
    localparam        P          = 34;
    localparam        H          = 5;

    // Alamat word di SIG_RAM (offset byte / 4)
    localparam [9:0] W_NSPK  = 10'd0;     // offset 0
    localparam [9:0] W_Q     = 10'd1;     // offset 4
    localparam [9:0] W_OTS   = 10'd2;     // offset 8
    localparam [9:0] W_C0    = 10'd3;     // offset 12..43
    localparam [9:0] W_Y0    = 10'd11;    // offset 44 + 32*i
    localparam [9:0] W_LMS   = 10'd283;   // offset 1132
    localparam [9:0] W_PATH0 = 10'd284;   // offset 1136 + 32*i

    // Kode error (kontrak bagian 4)
    localparam [7:0] E_OK          = 8'h00;
    localparam [7:0] E_SIG_LEN     = 8'h01;
    localparam [7:0] E_HSS_LEVELS  = 8'h02;
    localparam [7:0] E_OTS_TYPE    = 8'h03;
    localparam [7:0] E_LMS_TYPE    = 8'h04;
    localparam [7:0] E_Q           = 8'h05;
    localparam [7:0] E_IMG_LEN     = 8'h06;
    localparam [7:0] E_IMG_HEADER  = 8'h07;
    localparam [7:0] E_SIG_INVALID = 8'h08;
    localparam [7:0] E_ROLLBACK    = 8'h09;
    localparam [7:0] E_FAULT       = 8'h0A;

    localparam [7:0] PASS_PATTERN = 8'hA5;

    // State one-hot
    localparam S_IDLE = 0, S_LOAD = 1, S_CHECK = 2, S_MSG = 3,
               S_OTS  = 4, S_MRK  = 5, S_CMP   = 6, S_DONE = 7;

    function [31:0] be32;
        input [31:0] w;
        be32 = {w[7:0], w[15:8], w[23:16], w[31:24]};
    endfunction

    // ------------------------------------------------------------------
    // ROM public key
    // ------------------------------------------------------------------
    reg [127:0] rom_i  [0:0];
    reg [255:0] rom_t1 [0:0];
    initial begin
        $readmemh(ROM_I_FILE,  rom_i);
        $readmemh(ROM_T1_FILE, rom_t1);
        if (RAW_MSG_MODE != 0)
            $display("PERINGATAN: lms_verifier_core RAW_MSG_MODE=1 (hanya untuk testbench)");
    end
    wire [127:0] key_I  = rom_i[0];
    wire [255:0] key_T1 = rom_t1[0];

    // ------------------------------------------------------------------
    // Register
    // ------------------------------------------------------------------
    reg [7:0]   st;
    reg [7:0]   pass_pat;
    reg         fail_r, done_r, cpu_run, cpu_rel_q;
    reg [7:0]   err_r;
    reg [31:0]  cyc_cnt, cycles_r, min_ver, img_ver_r;
    reg [15:0]  img_len_q, sig_len_q;

    // Field yang dibaca saat LOAD
    reg [31:0]  f_nspk, f_q, f_ots, f_lms;
    reg [255:0] f_C;
    reg [31:0]  h_magic, h_ver, h_plen, h_rsv;

    // LOAD: 16 langkah baca (12 dari SIG_RAM, 4 dari IMG_RAM)
    reg [4:0]   ld_step, ld_prev;
    // nomor word C (0..7) untuk ld_prev 4..11; sama dengan (ld_prev - 4) mod 8
    wire [2:0]  c_word = ld_prev[2:0] ^ 3'b100;
    reg         ld_prev_v;

    // Handshake sub-modul
    reg         msg_start, ots_start, mrk_start, sub_started;
    // Reset sub-modul di setiap START baru: kalau verifikasi sebelumnya
    // berhenti di tengah (FAULT), sub-modul tidak tertinggal dalam keadaan sibuk.
    reg         sub_rst;
    wire        sub_rst_all = rst | sub_rst;
    wire        msg_done, ots_done, mrk_done;
    wire [255:0] Q_w, Kc_w, Tc_w;
    wire [11:0] msg_img_addr;

    // Pengambil data 256 bit (y[i] dan path[i]) dari SIG_RAM
    wire        y_req, path_req;
    wire [6:0]  y_idx;
    wire [2:0]  path_idx;
    reg         f_busy, f_valid, f_prev_v;
    reg [3:0]   f_cnt;
    reg [2:0]   f_prev;
    reg [9:0]   f_base;
    reg [255:0] f_buf;

    // ------------------------------------------------------------------
    // Pembanding redundan (dua rangkaian berbeda, jangan digabung sintesis)
    // ------------------------------------------------------------------
    (* keep = 1 *) wire match_a = (Tc_w == key_T1);
    (* keep = 1 *) wire match_b = ~|(Tc_w ^ key_T1);

    wire st_legal  = (st != 8'd0) && ((st & (st - 8'd1)) == 8'd0);
    wire is_busy   = !(st[S_IDLE] || st[S_DONE]);
    wire pass_ok   = (pass_pat == PASS_PATTERN);

    // ------------------------------------------------------------------
    // Alamat RAM
    // ------------------------------------------------------------------
    reg [9:0]  ld_sig_addr;
    reg [11:0] ld_img_addr;
    always @(*) begin
        ld_sig_addr = 10'd0;
        ld_img_addr = 12'd0;
        case (ld_step)
            5'd0: ld_sig_addr = W_NSPK;
            5'd1: ld_sig_addr = W_Q;
            5'd2: ld_sig_addr = W_OTS;
            5'd3: ld_sig_addr = W_LMS;
            default: begin
                if (ld_step <= 5'd11) ld_sig_addr = W_C0 + {5'd0, ld_step} - 10'd4;
                else                  ld_img_addr = {7'd0, ld_step} - 12'd12;
            end
        endcase
    end

    assign sig_addr = st[S_LOAD]                       ? ld_sig_addr :
                      ((st[S_OTS] || st[S_MRK]) && f_busy) ? (f_base + {6'd0, f_cnt}) :
                      10'd0;
    assign img_addr = st[S_LOAD] ? ld_img_addr :
                      st[S_MSG]  ? msg_img_addr :
                      12'd0;

    // ------------------------------------------------------------------
    // Cek format (kombinasional, dipakai di CHECK), urutan sesuai tabel error
    // ------------------------------------------------------------------
    reg [7:0] check_err;
    always @(*) begin
        if      (sig_len_q != SIG_BYTES)                       check_err = E_SIG_LEN;
        else if (f_nspk != 32'd0)                              check_err = E_HSS_LEVELS;
        else if (f_ots != OTS_TYPE)                            check_err = E_OTS_TYPE;
        else if (f_lms != LMS_TYPE)                            check_err = E_LMS_TYPE;
        else if (f_q >= NUM_LEAVES)                            check_err = E_Q;
        else if (img_len_q < IMG_MIN || img_len_q > IMG_MAX)   check_err = E_IMG_LEN;
        else if (RAW_MSG_MODE == 0 &&
                 (h_magic != IMG_MAGIC ||
                  h_plen  != {16'd0, img_len_q - 16'd16} ||
                  h_rsv   != 32'd0))                           check_err = E_IMG_HEADER;
        else                                                   check_err = E_OK;
    end

    // ------------------------------------------------------------------
    // Sub-modul
    // ------------------------------------------------------------------
    // busy sub-modul tidak dipakai: core memakai done dan state sendiri
    /* verilator lint_off PINCONNECTEMPTY */
    lms_msg_hash u_msg (
        .clk(clk), .rst(sub_rst_all), .start(msg_start),
        .I(key_I), .q(f_q), .C(f_C), .img_len(img_len_q),
        .img_addr(msg_img_addr), .img_rdata(img_rdata),
        .Q(Q_w), .done(msg_done), .busy()
    );

    lmots_verify #(.W(8), .P(P), .LS(0), .N_CORES(N_CORES)) u_ots (
        .clk(clk), .rst(sub_rst_all), .start(ots_start),
        .I(key_I), .q(f_q), .Q(Q_w),
        .y_req(y_req), .y_idx(y_idx), .y_data(f_buf), .y_valid(f_valid && st[S_OTS]),
        .Kc(Kc_w), .done(ots_done), .busy()
    );

    lms_merkle #(.H(H)) u_mrk (
        .clk(clk), .rst(sub_rst_all), .start(mrk_start),
        .I(key_I), .q(f_q), .Kc(Kc_w),
        .path_req(path_req), .path_idx(path_idx), .path_data(f_buf),
        .path_valid(f_valid && st[S_MRK]),
        .Tc(Tc_w), .done(mrk_done), .busy()
    );
    /* verilator lint_on PINCONNECTEMPTY */

    // ------------------------------------------------------------------
    // FSM utama
    // ------------------------------------------------------------------
    task finish;
        input       ok;
        input [7:0] code;
        begin
            st          <= 8'd1 << S_DONE;
            done_r      <= 1'b1;
            pass_pat    <= ok ? PASS_PATTERN : 8'h00;
            fail_r      <= ~ok;
            err_r       <= code;
            cpu_run     <= ok;
            if (!ok) cpu_rel_q <= 1'b0;
            cycles_r    <= cyc_cnt;
            sub_started <= 1'b0;
        end
    endtask

    always @(posedge clk) begin
        if (rst) begin
            st          <= 8'd1 << S_IDLE;
            pass_pat    <= 8'h00;
            fail_r      <= 1'b0;
            done_r      <= 1'b0;
            err_r       <= E_OK;
            cpu_run     <= 1'b0;
            cpu_rel_q   <= 1'b0;
            cyc_cnt     <= 32'd0;
            cycles_r    <= 32'd0;
            min_ver     <= INIT_MIN_VERSION;
            img_ver_r   <= 32'd0;
            img_len_q   <= 16'd0;
            sig_len_q   <= 16'd0;
            ld_step     <= 5'd0;
            ld_prev     <= 5'd0;
            ld_prev_v   <= 1'b0;
            msg_start   <= 1'b0;
            ots_start   <= 1'b0;
            mrk_start   <= 1'b0;
            sub_started <= 1'b0;
            sub_rst     <= 1'b0;
            f_nspk <= 32'd0; f_q <= 32'd0; f_ots <= 32'd0; f_lms <= 32'd0;
            f_C    <= 256'd0;
            h_magic <= 32'd0; h_ver <= 32'd0; h_plen <= 32'd0; h_rsv <= 32'd0;
        end else begin
            done_r    <= 1'b0;
            sub_rst   <= 1'b0;
            msg_start <= 1'b0;
            ots_start <= 1'b0;
            mrk_start <= 1'b0;
            cpu_rel_q <= cpu_run && pass_ok;
            if (is_busy) cyc_cnt <= cyc_cnt + 32'd1;

            if (hold) begin
                cpu_run   <= 1'b0;
                cpu_rel_q <= 1'b0;
            end

            if (commit && !is_busy && pass_ok && (img_ver_r > min_ver))
                min_ver <= img_ver_r;

            if (!st_legal) begin
                finish(1'b0, E_FAULT);
            end else begin
                case (1'b1)
                    st[S_IDLE], st[S_DONE]: begin
                        if (start) begin
                            st        <= 8'd1 << S_LOAD;
                            pass_pat  <= 8'h00;
                            fail_r    <= 1'b0;
                            err_r     <= E_OK;
                            cpu_run   <= 1'b0;
                            cpu_rel_q <= 1'b0;
                            cyc_cnt   <= 32'd0;
                            img_len_q <= img_len;
                            sig_len_q <= sig_len;
                            ld_step   <= 5'd0;
                            ld_prev_v <= 1'b0;
                            sub_rst   <= 1'b1;
                        end
                    end

                    st[S_LOAD]: begin
                        if (ld_prev_v) begin
                            case (ld_prev)
                                5'd0:  f_nspk  <= be32(sig_rdata);
                                5'd1:  f_q     <= be32(sig_rdata);
                                5'd2:  f_ots   <= be32(sig_rdata);
                                5'd3:  f_lms   <= be32(sig_rdata);
                                5'd12: h_magic <= be32(img_rdata);
                                5'd13: h_ver   <= be32(img_rdata);
                                5'd14: h_plen  <= be32(img_rdata);
                                5'd15: h_rsv   <= be32(img_rdata);
                                default: f_C[255 - 32*c_word -: 32] <= be32(sig_rdata);
                            endcase
                        end
                        if (ld_step == 5'd16) begin
                            ld_prev_v <= 1'b0;
                            st        <= 8'd1 << S_CHECK;
                        end else begin
                            ld_prev   <= ld_step;
                            ld_prev_v <= 1'b1;
                            ld_step   <= ld_step + 5'd1;
                        end
                    end

                    st[S_CHECK]: begin
                        if (check_err != E_OK) begin
                            finish(1'b0, check_err);
                        end else begin
                            img_ver_r <= (RAW_MSG_MODE != 0) ? 32'd0 : h_ver;
                            st        <= 8'd1 << S_MSG;
                        end
                    end

                    st[S_MSG]: begin
                        if (!sub_started) begin
                            msg_start   <= 1'b1;
                            sub_started <= 1'b1;
                        end else if (msg_done) begin
                            sub_started <= 1'b0;
                            st          <= 8'd1 << S_OTS;
                        end
                    end

                    st[S_OTS]: begin
                        if (!sub_started) begin
                            ots_start   <= 1'b1;
                            sub_started <= 1'b1;
                        end else if (y_req && y_idx >= P) begin
                            finish(1'b0, E_FAULT);          // permintaan di luar batas
                        end else if (ots_done) begin
                            sub_started <= 1'b0;
                            st          <= 8'd1 << S_MRK;
                        end
                    end

                    st[S_MRK]: begin
                        if (!sub_started) begin
                            mrk_start   <= 1'b1;
                            sub_started <= 1'b1;
                        end else if (path_req && path_idx >= H) begin
                            finish(1'b0, E_FAULT);
                        end else if (mrk_done) begin
                            sub_started <= 1'b0;
                            st          <= 8'd1 << S_CMP;
                        end
                    end

                    st[S_CMP]: begin
                        if (match_a && match_b) begin
                            if (RAW_MSG_MODE == 0 && h_ver < min_ver)
                                finish(1'b0, E_ROLLBACK);
                            else
                                finish(1'b1, E_OK);
                        end else if (!match_a && !match_b) begin
                            finish(1'b0, E_SIG_INVALID);
                        end else begin
                            finish(1'b0, E_FAULT);          // pembanding tidak sepakat
                        end
                    end

                    default: finish(1'b0, E_FAULT);
                endcase
            end
        end
    end

    // ------------------------------------------------------------------
    // Pengambil y[i] / path[i]: 8 word dari SIG_RAM, latensi 1
    // ------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst || !(st[S_OTS] || st[S_MRK])) begin
            f_busy   <= 1'b0;
            f_valid  <= 1'b0;
            f_prev_v <= 1'b0;
            f_cnt    <= 4'd0;
            f_prev   <= 3'd0;
            f_base   <= 10'd0;
        end else begin
            f_valid <= 1'b0;
            if (f_prev_v)
                f_buf[255 - 32*f_prev -: 32] <= be32(sig_rdata);

            if (f_busy) begin
                if (f_cnt == 4'd8) begin
                    f_busy   <= 1'b0;
                    f_valid  <= 1'b1;
                    f_prev_v <= 1'b0;
                end else begin
                    f_prev   <= f_cnt[2:0];
                    f_prev_v <= 1'b1;
                    f_cnt    <= f_cnt + 4'd1;
                end
            end else if (!f_valid) begin
                if (st[S_OTS] && y_req && y_idx < P) begin
                    f_base <= W_Y0 + {y_idx, 3'b000};
                    f_busy <= 1'b1;
                    f_cnt  <= 4'd0;
                end else if (st[S_MRK] && path_req && path_idx < H) begin
                    f_base <= W_PATH0 + {4'd0, path_idx, 3'b000};
                    f_busy <= 1'b1;
                    f_cnt  <= 4'd0;
                end
            end
        end
    end

    // ------------------------------------------------------------------
    // Output
    // ------------------------------------------------------------------
    assign busy        = is_busy;
    assign done        = done_r;
    assign pass        = pass_ok;
    assign fail        = fail_r;
    assign err_code    = err_r;
    assign cycles      = cycles_r;
    assign img_version = img_ver_r;
    assign min_version = min_ver;
    assign cpu_release = cpu_rel_q;
    assign buf_lock    = is_busy || cpu_run;

endmodule

`default_nettype wire
