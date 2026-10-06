`timescale 1ns/1ps
// tb_lms_verifier_core.v - menguji pengendali utama dengan sub-modul TIRUAN
// (tb/mocks/). Yang diuji: pembacaan field dari RAM (urutan byte), cek format
// dan urutan kode error, pengambil y/path, pembanding redundan, anti-rollback,
// COMMIT/HOLD, kunci buffer, reset gate, FAULT, dan penolakan START saat BUSY.
// Kriptografi sungguhan diuji terpisah di testbench modul masing-masing.

module tb_lms_verifier_core;
    localparam [31:0] MAGIC = 32'h5046_5731;

    reg clk = 0;
    always #10 clk = ~clk;   // 50 MHz

    reg         rst = 1, start = 0, commit = 0, hold = 0;
    reg  [15:0] img_len, sig_len;
    wire [9:0]  sig_addr;
    wire [11:0] img_addr;
    reg  [31:0] sig_rdata, img_rdata;
    wire        busy, done, pass, fail, cpu_release, buf_lock;
    wire [7:0]  err_code;
    wire [31:0] cycles, img_version, min_version;

    // RAM tiruan: 32 bit, latensi baca 1, isi little-endian seperti memcpy HPS
    reg [31:0] sig_mem [0:1023];
    reg [31:0] img_mem [0:4095];
    always @(posedge clk) begin
        sig_rdata <= sig_mem[sig_addr];
        img_rdata <= img_mem[img_addr];
    end

    lms_verifier_core #(
        .INIT_MIN_VERSION(32'd1),
        .ROM_I_FILE("tv/core_mock/rom_I.hex"),
        .ROM_T1_FILE("tv/core_mock/rom_T1.hex")
    ) dut (
        .clk(clk), .rst(rst), .start(start), .commit(commit), .hold(hold),
        .img_len(img_len), .sig_len(sig_len),
        .sig_addr(sig_addr), .sig_rdata(sig_rdata),
        .img_addr(img_addr), .img_rdata(img_rdata),
        .busy(busy), .done(done), .pass(pass), .fail(fail), .err_code(err_code),
        .cycles(cycles), .img_version(img_version), .min_version(min_version),
        .cpu_release(cpu_release), .buf_lock(buf_lock)
    );

    integer errors = 0;

    // Pengawas: reset CPU tidak boleh lepas tanpa PASS
    always @(posedge clk)
        if (cpu_release && !pass) begin
            $display("  salah: cpu_release aktif tanpa pass");
            errors = errors + 1;
        end

    // ---------------- Bantuan data ----------------
    function [31:0] sw32; input [31:0] w; sw32 = {w[7:0], w[15:8], w[23:16], w[31:24]}; endfunction

    function [255:0] pat256; input [31:0] seed; integer j; begin
        for (j = 0; j < 8; j = j + 1) pat256[255 - 32*j -: 32] = seed * 32'h9E37_79B9 + j * 32'h0101_0101;
    end endfunction

    task put256; input integer base; input [255:0] v; integer j; begin
        for (j = 0; j < 8; j = j + 1) sig_mem[base + j] = sw32(v[255 - 32*j -: 32]);
    end endtask

    function [255:0] get256; input integer base; integer j; begin
        for (j = 0; j < 8; j = j + 1) get256[255 - 32*j -: 32] = sw32(sig_mem[base + j]);
    end endfunction

    // Isi RAM dengan tanda tangan dan image yang formatnya benar
    task make_valid; input [31:0] q; input [31:0] version; integer k; begin
        for (k = 0; k < 1024; k = k + 1) sig_mem[k] = 32'd0;
        sig_mem[0]   = sw32(32'd0);          // Nspk
        sig_mem[1]   = sw32(q);
        sig_mem[2]   = sw32(32'd4);          // LMOTS_SHA256_N32_W8
        put256(3, pat256(32'hC0));           // C
        for (k = 0; k < 34; k = k + 1) put256(11 + 8*k, pat256(32'h100 + k));
        sig_mem[283] = sw32(32'd5);          // LMS_SHA256_M32_H5
        for (k = 0; k < 5; k = k + 1) put256(284 + 8*k, pat256(32'h200 + k));
        sig_len = 16'd1296;

        img_len = 16'd1024;
        for (k = 0; k < 4096; k = k + 1) img_mem[k] = k * 32'h0001_0001;
        img_mem[0] = sw32(MAGIC);
        img_mem[1] = sw32(version);
        img_mem[2] = sw32(32'd1024 - 32'd16);
        img_mem[3] = 32'd0;
    end endtask

    // Model tiruan yang sama dengan tb/mocks, dari isi RAM saat ini
    function [255:0] model_tc; input dummy; reg [255:0] C, Q, Kc, acc; reg [127:0] I; reg [31:0] q; integer k; begin
        I   = dut.key_I;
        q   = sw32(sig_mem[1]);
        C   = get256(3);
        Q   = {I, q, C[95:0]} ^
              {sw32(img_mem[0]), sw32(img_mem[1]), sw32(img_mem[2]), sw32(img_mem[3]), 128'd0};
        acc = 256'd0;
        for (k = 0; k < 34; k = k + 1) acc = acc ^ get256(11 + 8*k);
        Kc  = Q ^ acc;
        acc = 256'd0;
        for (k = 0; k < 5; k = k + 1) acc = acc ^ get256(284 + 8*k);
        model_tc = Kc ^ acc ^ {I, q, 96'd0};
    end endfunction

    // Tanam public key yang cocok (atau sengaja tidak cocok) di ROM DUT
    task set_rom; input good; begin
        dut.rom_t1[0] = good ? model_tc(0) : ~model_tc(0);
    end endtask

    // ---------------- Bantuan kontrol ----------------
    // Pulsa 1 cycle (task terpisah: argumen inout baru disalin di akhir task)
    task pulse_start;  begin @(negedge clk) start  = 1; @(negedge clk) start  = 0; end endtask
    task pulse_commit; begin @(negedge clk) commit = 1; @(negedge clk) commit = 0; end endtask
    task pulse_hold;   begin @(negedge clk) hold   = 1; @(negedge clk) hold   = 0; end endtask

    task run_and_wait; integer t; begin
        pulse_start;
        t = 0;
        while (!done && t < 5000) begin @(posedge clk); t = t + 1; end
        if (!done) begin $display("  salah: timeout menunggu done"); errors = errors + 1; end
        repeat (3) @(posedge clk);
    end endtask

    task check_result; input [8*20-1:0] name; input exp_pass; input [7:0] exp_err; begin
        if (pass !== exp_pass || fail !== !exp_pass || err_code !== exp_err) begin
            $display("  salah [%0s]: pass=%b fail=%b err=%h (harapan pass=%b err=%h)",
                     name, pass, fail, err_code, exp_pass, exp_err);
            errors = errors + 1;
        end
        if (cpu_release !== exp_pass) begin
            $display("  salah [%0s]: cpu_release=%b", name, cpu_release); errors = errors + 1;
        end
    end endtask

    // Kasus gagal format: sub-modul tidak boleh dijalankan
    task check_no_crypto; input [8*20-1:0] name; input [31:0] n_before; begin
        if (dut.u_msg.n_start != n_before) begin
            $display("  salah [%0s]: kriptografi tetap dijalankan", name); errors = errors + 1;
        end
    end endtask

    integer n0;

    initial begin
`ifdef DUMP_VCD
        $dumpfile("build/lms_verifier_core.vcd");
        $dumpvars(0, tb_lms_verifier_core);
`endif
        img_len = 0; sig_len = 0;
        repeat (3) @(posedge clk); rst = 0; @(posedge clk);

        // 1. Valid versi 1 -> PASS, buffer terkunci karena CPU jalan
        make_valid(32'd7, 32'd1); set_rom(1); run_and_wait;
        check_result("valid v1", 1, 8'h00);
        if (!buf_lock)            begin $display("  salah: buffer tidak terkunci saat CPU jalan"); errors = errors + 1; end
        if (cycles == 0)          begin $display("  salah: CYCLES = 0"); errors = errors + 1; end
        if (img_version != 32'd1) begin $display("  salah: IMG_VERSION=%0d", img_version); errors = errors + 1; end

        // 2. COMMIT dengan versi sama -> MIN_VERSION tetap 1
        pulse_commit; @(posedge clk);
        if (min_version != 32'd1) begin $display("  salah: MIN_VERSION naik tanpa alasan"); errors = errors + 1; end

        // 3. HOLD -> CPU ditahan, buffer terbuka
        pulse_hold; repeat (2) @(posedge clk);
        if (cpu_release || buf_lock) begin $display("  salah: HOLD tidak menahan CPU / membuka buffer"); errors = errors + 1; end

        // 4. Valid versi 2 -> PASS, lalu COMMIT -> MIN_VERSION = 2
        make_valid(32'd8, 32'd2); set_rom(1); run_and_wait;
        check_result("valid v2", 1, 8'h00);
        pulse_commit; @(posedge clk);
        if (min_version != 32'd2) begin $display("  salah: COMMIT gagal, MIN_VERSION=%0d", min_version); errors = errors + 1; end

        // 5. Tanda tangan sah tapi versi 1 -> ROLLBACK
        make_valid(32'd9, 32'd1); set_rom(1); run_and_wait;
        check_result("rollback", 0, 8'h09);

        // 6. Kesalahan format, urutan sesuai tabel kode error
        make_valid(32'd3, 32'd2); set_rom(1); sig_len = 16'd1295;
        n0 = dut.u_msg.n_start; run_and_wait; check_result("sig_len", 0, 8'h01); check_no_crypto("sig_len", n0);

        make_valid(32'd3, 32'd2); set_rom(1); sig_mem[0] = sw32(32'd1);
        n0 = dut.u_msg.n_start; run_and_wait; check_result("nspk", 0, 8'h02); check_no_crypto("nspk", n0);

        make_valid(32'd3, 32'd2); set_rom(1); sig_mem[2] = sw32(32'd3);
        n0 = dut.u_msg.n_start; run_and_wait; check_result("ots_type", 0, 8'h03); check_no_crypto("ots_type", n0);

        make_valid(32'd3, 32'd2); set_rom(1); sig_mem[283] = sw32(32'd6);
        n0 = dut.u_msg.n_start; run_and_wait; check_result("lms_type", 0, 8'h04); check_no_crypto("lms_type", n0);

        make_valid(32'd32, 32'd2); set_rom(1);
        n0 = dut.u_msg.n_start; run_and_wait; check_result("q=32", 0, 8'h05); check_no_crypto("q=32", n0);

        make_valid(32'd3, 32'd2); set_rom(1); img_len = 16'd15;
        n0 = dut.u_msg.n_start; run_and_wait; check_result("img_len", 0, 8'h06); check_no_crypto("img_len", n0);

        make_valid(32'd3, 32'd2); set_rom(1); img_mem[0] = sw32(32'hDEAD_BEEF);
        n0 = dut.u_msg.n_start; run_and_wait; check_result("magic", 0, 8'h07); check_no_crypto("magic", n0);

        make_valid(32'd3, 32'd2); set_rom(1); img_mem[2] = sw32(32'd100);
        n0 = dut.u_msg.n_start; run_and_wait; check_result("payload len", 0, 8'h07); check_no_crypto("payload len", n0);

        make_valid(32'd3, 32'd2); set_rom(1); img_mem[3] = 32'd1;
        n0 = dut.u_msg.n_start; run_and_wait; check_result("cadangan", 0, 8'h07); check_no_crypto("cadangan", n0);

        // 7. Tanda tangan dirusak setelah public key ditetapkan -> SIG_INVALID
        make_valid(32'd4, 32'd2); set_rom(1); sig_mem[11 + 8*17 + 3] = sig_mem[11 + 8*17 + 3] ^ 32'h0000_0100;
        run_and_wait; check_result("y[17] dibalik", 0, 8'h08);

        make_valid(32'd4, 32'd2); set_rom(1); sig_mem[284 + 8*3] = sig_mem[284 + 8*3] ^ 32'h8000_0000;
        run_and_wait; check_result("path[3] dibalik", 0, 8'h08);

        make_valid(32'd4, 32'd2); set_rom(1); sig_mem[3 + 7] = sig_mem[3 + 7] ^ 32'h1;   // C[31:0]
        run_and_wait; check_result("C dibalik", 0, 8'h08);

        make_valid(32'd4, 32'd2); set_rom(1); img_mem[100] = img_mem[100] ^ 32'h1;
        // tiruan hash hanya membaca header; perubahan payload tidak terdeteksi tiruan.
        // Yang diuji di sini hanya bahwa header dibaca benar: hasil harus tetap PASS.
        run_and_wait; check_result("payload (tiruan)", 1, 8'h00);

        make_valid(32'd4, 32'd2); set_rom(0);
        run_and_wait; check_result("kunci lain", 0, 8'h08);

        // 8. Pembanding tidak sepakat -> FAULT
        make_valid(32'd5, 32'd2); set_rom(1);
        force dut.match_b = 1'b0;
        run_and_wait; check_result("pembanding", 0, 8'h0A);
        release dut.match_b;

        // 9. State ilegal di tengah verifikasi -> FAULT
        make_valid(32'd5, 32'd2); set_rom(1);
        pulse_start;
        repeat (60) @(posedge clk);
        @(negedge clk) force dut.st = 8'b0001_0010;
        @(negedge clk) release dut.st;
        while (busy) @(posedge clk);   // done (pulsa) bisa terlewat saat force
        repeat (3) @(posedge clk);
        check_result("state ilegal", 0, 8'h0A);

        // 10. START saat BUSY diabaikan
        make_valid(32'd6, 32'd2); set_rom(1);
        n0 = dut.u_msg.n_start;
        pulse_start;
        repeat (30) @(posedge clk);
        pulse_start;
        while (!done) @(posedge clk);
        repeat (3) @(posedge clk);
        check_result("start ganda", 1, 8'h00);
        if (dut.u_msg.n_start != n0 + 1) begin $display("  salah: START saat BUSY tidak diabaikan"); errors = errors + 1; end

        // 11. START baru setelah PASS langsung menahan CPU
        make_valid(32'd6, 32'd2); set_rom(0);
        pulse_start; @(posedge clk);
        if (cpu_release) begin $display("  salah: CPU tetap jalan setelah START baru"); errors = errors + 1; end
        while (!done) @(posedge clk);

        if (errors == 0) $display("TEST PASSED");
        else             $display("TEST FAILED: %0d cek salah", errors);
        $finish;
    end

    initial begin
        #20_000_000;
        $display("TEST FAILED: timeout");
        $finish;
    end
endmodule
