`timescale 1ns/1ps
`default_nettype none
// lms_verifier_stub.v - verifier palsu untuk integrasi awal (kontrak bagian 3.9)
//
// Port sama persis dengan lms_verifier_core. Setelah START, menunggu
// STUB_DELAY cycle, lalu PASS jika word pertama IMG_RAM adalah magic "PFW1",
// selain itu FAIL dengan err 0x07. TIDAK memeriksa tanda tangan: jangan
// pernah dipakai di luar integrasi board dan program HPS.

/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off UNUSEDSIGNAL */
// Port dan parameter sengaja sama dengan lms_verifier_core walau tidak semua dipakai.
module lms_verifier_stub #(
    parameter N_CORES          = 1,
    parameter INIT_MIN_VERSION = 32'd1,
    parameter RAW_MSG_MODE     = 0,
    parameter ROM_I_FILE       = "rom_I.hex",
    parameter ROM_T1_FILE      = "rom_T1.hex",
    parameter STUB_DELAY       = 1000
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
/* verilator lint_on UNUSEDSIGNAL */
/* verilator lint_on UNUSEDPARAM */

    localparam [31:0] IMG_MAGIC    = 32'h5046_5731;
    localparam [7:0]  PASS_PATTERN = 8'hA5;

    function [31:0] be32;
        input [31:0] w;
        be32 = {w[7:0], w[15:8], w[23:16], w[31:24]};
    endfunction

    reg        busy_r, done_r, fail_r, cpu_run, cpu_rel_q;
    reg [7:0]  pass_pat, err_r;
    reg [31:0] cnt, cycles_r, min_ver, img_ver_r;
    reg [31:0] word0, word1;

    wire pass_ok = (pass_pat == PASS_PATTERN);

    // Selama BUSY, baca terus word 0 dan 1 IMG_RAM (magic dan versi)
    assign img_addr = (cnt[0]) ? 12'd1 : 12'd0;
    assign sig_addr = 10'd0;

    always @(posedge clk) begin
        if (rst) begin
            busy_r    <= 1'b0;
            done_r    <= 1'b0;
            fail_r    <= 1'b0;
            cpu_run   <= 1'b0;
            cpu_rel_q <= 1'b0;
            pass_pat  <= 8'h00;
            err_r     <= 8'h00;
            cnt       <= 32'd0;
            cycles_r  <= 32'd0;
            min_ver   <= INIT_MIN_VERSION;
            img_ver_r <= 32'd0;
            word0     <= 32'd0;
            word1     <= 32'd0;
        end else begin
            done_r    <= 1'b0;
            cpu_rel_q <= cpu_run && pass_ok;

            if (hold) begin
                cpu_run   <= 1'b0;
                cpu_rel_q <= 1'b0;
            end

            if (commit && !busy_r && pass_ok && (img_ver_r > min_ver))
                min_ver <= img_ver_r;

            if (!busy_r) begin
                if (start) begin
                    busy_r    <= 1'b1;
                    cnt       <= 32'd0;
                    pass_pat  <= 8'h00;
                    fail_r    <= 1'b0;
                    err_r     <= 8'h00;
                    cpu_run   <= 1'b0;
                    cpu_rel_q <= 1'b0;
                end
            end else begin
                cnt <= cnt + 32'd1;
                // data RAM tiba satu cycle setelah alamat
                if (cnt[0]) word0 <= be32(img_rdata);   // alamat 0 diberikan saat cnt genap
                else        word1 <= be32(img_rdata);
                if (cnt >= STUB_DELAY) begin
                    busy_r    <= 1'b0;
                    done_r    <= 1'b1;
                    cycles_r  <= cnt;
                    img_ver_r <= word1;
                    if (word0 == IMG_MAGIC) begin
                        pass_pat <= PASS_PATTERN;
                        cpu_run  <= 1'b1;
                    end else begin
                        fail_r    <= 1'b1;
                        err_r     <= 8'h07;
                        cpu_rel_q <= 1'b0;
                    end
                end
            end
        end
    end

    assign busy        = busy_r;
    assign done        = done_r;
    assign pass        = pass_ok;
    assign fail        = fail_r;
    assign err_code    = err_r;
    assign cycles      = cycles_r;
    assign img_version = img_ver_r;
    assign min_version = min_ver;
    assign cpu_release = cpu_rel_q;
    assign buf_lock    = busy_r || cpu_run;

endmodule

`default_nettype wire
