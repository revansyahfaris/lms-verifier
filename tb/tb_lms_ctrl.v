// tb_lms_ctrl.v - testbench FSM pengendali utama
// Sub-modul (hash, rantai, Merkle) diganti tiruan yang menjawab done
// setelah beberapa cycle. Mencetak TEST PASSED / TEST FAILED.
`timescale 1ns/1ps
`include "lms_params.vh"

module tb_lms_ctrl;
    localparam [31:0]  MAGIC   = 32'h4C4D5346;
    localparam [31:0]  MINVER  = 32'd3;
    localparam [255:0] PK_ROOT = {8{32'hA5A5_1234}};

    reg clk = 0;
    reg rst = 1;
    always #10 clk = ~clk;   // 50 MHz

    reg         start = 0;
    reg  [31:0] hdr_magic, hdr_version, hdr_len, sig_ots_type, sig_lms_type, sig_q;
    reg  [255:0] root;

    wire hash_start, hash_sel_kc, chains_start, merkle_start;
    reg  hash_done = 0, chains_done = 0, merkle_done = 0;
    wire busy, done, pass, buf_lock, cpu_release;
    wire [7:0] err_code;
    wire [3:0] state_dbg;

    lms_ctrl #(.FW_MAGIC(MAGIC), .MIN_VERSION(MINVER), .PUBKEY_ROOT(PK_ROOT)) dut (
        .clk(clk), .rst(rst), .start(start),
        .hdr_magic(hdr_magic), .hdr_version(hdr_version), .hdr_len(hdr_len),
        .sig_ots_type(sig_ots_type), .sig_lms_type(sig_lms_type), .sig_q(sig_q),
        .hash_start(hash_start), .hash_sel_kc(hash_sel_kc), .hash_done(hash_done),
        .chains_start(chains_start), .chains_done(chains_done),
        .merkle_start(merkle_start), .merkle_done(merkle_done), .root(root),
        .busy(busy), .done(done), .pass(pass), .err_code(err_code),
        .buf_lock(buf_lock), .cpu_release(cpu_release), .state_dbg(state_dbg)
    );

    // ---- Sub-modul tiruan: jawab done 5 cycle setelah start ----
    integer n_hash = 0, n_chains = 0, n_merkle = 0;
    always @(posedge clk) begin
        if (hash_start)   begin n_hash   = n_hash + 1;   repeat (5) @(posedge clk); hash_done   <= 1; @(posedge clk); hash_done   <= 0; end
    end
    always @(posedge clk) begin
        if (chains_start) begin n_chains = n_chains + 1; repeat (5) @(posedge clk); chains_done <= 1; @(posedge clk); chains_done <= 0; end
    end
    always @(posedge clk) begin
        if (merkle_start) begin n_merkle = n_merkle + 1; repeat (5) @(posedge clk); merkle_done <= 1; @(posedge clk); merkle_done <= 0; end
    end

    // Reset gate tidak boleh pernah lepas tanpa pass
    integer errors = 0;
    always @(posedge clk) begin
        if (cpu_release && !pass) begin
            $display("  salah: cpu_release aktif tanpa pass");
            errors = errors + 1;
        end
    end

    task set_valid;
        begin
            hdr_magic    = MAGIC;
            hdr_version  = MINVER;
            hdr_len      = 32'd1024;
            sig_ots_type = 32'd4;
            sig_lms_type = 32'd5;
            sig_q        = 32'd7;
            root         = PK_ROOT;
        end
    endtask

    task do_reset;
        begin
            rst = 1; repeat (3) @(posedge clk); rst = 0; @(posedge clk);
            n_hash = 0; n_chains = 0; n_merkle = 0;
        end
    endtask

    task pulse_start;
        begin
            @(negedge clk) start = 1;
            @(negedge clk) start = 0;
        end
    endtask

    task wait_done;
        integer t;
        begin
            t = 0;
            while (!done && t < 500) begin @(posedge clk); t = t + 1; end
            if (!done) begin $display("  salah: timeout menunggu done"); errors = errors + 1; end
            @(posedge clk);
        end
    endtask

    // Jalankan satu kasus dan bandingkan hasil
    task run_case(input [8*24-1:0] name, input exp_pass, input [7:0] exp_err, input exp_subs);
        begin
            do_reset;
            pulse_start;
            @(posedge clk); @(posedge clk);
            if (!buf_lock) begin $display("  salah [%0s]: buffer tidak dikunci saat jalan", name); errors = errors + 1; end
            wait_done;
            if (pass !== exp_pass)        begin $display("  salah [%0s]: pass=%b exp=%b", name, pass, exp_pass); errors = errors + 1; end
            if (cpu_release !== exp_pass) begin $display("  salah [%0s]: cpu_release=%b", name, cpu_release); errors = errors + 1; end
            if (err_code !== exp_err)     begin $display("  salah [%0s]: err=%h exp=%h", name, err_code, exp_err); errors = errors + 1; end
            if (exp_subs  && (n_hash != 2 || n_chains != 1 || n_merkle != 1)) begin
                $display("  salah [%0s]: urutan sub-modul hash=%0d chains=%0d merkle=%0d", name, n_hash, n_chains, n_merkle); errors = errors + 1; end
            if (!exp_subs && (n_hash != 0 || n_chains != 0 || n_merkle != 0)) begin
                $display("  salah [%0s]: sub-modul jalan padahal header ditolak", name); errors = errors + 1; end
            if (!exp_pass && buf_lock)    begin $display("  salah [%0s]: buffer masih terkunci setelah FAIL", name); errors = errors + 1; end
        end
    endtask

    initial begin
`ifdef DUMP_VCD
        $dumpfile("build/lms_ctrl.vcd");
        $dumpvars(0, tb_lms_ctrl);
`endif
        // 1. Tanda tangan valid
        set_valid;                               run_case("valid",        1, 8'h00, 1);
        // 2. Akar tidak cocok (tanda tangan palsu)
        set_valid; root = ~PK_ROOT;               run_case("akar salah",   0, 8'h06, 1);
        // 3. Magic header salah
        set_valid; hdr_magic = 32'hDEAD_BEEF;     run_case("magic",        0, 8'h01, 0);
        // 4. Panjang melebihi batas
        set_valid; hdr_len = 32'd20000;           run_case("panjang",      0, 8'h02, 0);
        // 5. Firmware versi lama (rollback)
        set_valid; hdr_version = MINVER - 1;      run_case("rollback",     0, 8'h03, 0);
        // 6. Tipe LM-OTS salah
        set_valid; sig_ots_type = 32'd3;          run_case("tipe",         0, 8'h04, 0);
        // 7. q di luar 0..31
        set_valid; sig_q = 32'd32;                run_case("q",            0, 8'h05, 0);

        // 8. Setelah PASS, start lagi diabaikan dan reset tetap lepas
        set_valid; run_case("valid lagi", 1, 8'h00, 1);
        root = ~PK_ROOT;
        pulse_start; repeat (60) @(posedge clk);
        if (!pass || !cpu_release) begin $display("  salah: PASS bisa diulang dengan start baru"); errors = errors + 1; end

        // 9. Setelah FAIL, HPS bisa mencoba lagi dan lolos
        do_reset; set_valid; root = ~PK_ROOT;
        pulse_start; wait_done;
        root = PK_ROOT; n_hash = 0; n_chains = 0; n_merkle = 0;
        pulse_start; @(posedge clk); @(posedge clk); wait_done;
        if (!pass) begin $display("  salah: coba ulang setelah FAIL tidak lolos"); errors = errors + 1; end

        if (errors == 0) $display("TEST PASSED");
        else             $display("TEST FAILED: %0d cek salah", errors);
        $finish;
    end

    initial begin
        #2_000_000;
        $display("TEST FAILED: timeout");
        $finish;
    end
endmodule
