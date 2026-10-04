# Kontrak Teknis Tim — Verifier LMS (PERURI Chip Hackathon 2026)

Status: **DRAF v0.3, untuk direview bersama**. Setelah disepakati, perubahan apa pun harus lewat diskusi tim dan dicatat di bagian Riwayat Perubahan.

Dokumen ini adalah "kesepakatan colokan": parameter, antarmuka modul, format data uji, peta register, dan aturan repo. Selama semua orang mengikuti dokumen ini, empat orang bisa bekerja paralel dan hasilnya tetap bisa disambung.

Cara membaca: setiap bagian punya baris **Kenapa** yang menjelaskan alasannya dengan singkat. Bagian bertanda **[PERLU DICEK]** belum pasti dan harus dikonfirmasi minggu ini.

---

## 1. Parameter kriptografi

| Hal | Keputusan | Kode tipe (typecode) |
| --- | --- | --- |
| Skema LMS | `LMS_SHA256_M32_H5` (tinggi pohon h = 5, 32 tanda tangan) | `0x00000005` |
| Skema LM-OTS | `LMOTS_SHA256_N32_W8` (w = 8, p = 34 rantai, ls = 0) | `0x00000004` |
| Hash | SHA-256, n = m = 32 byte | — |
| Format pembungkus | HSS dengan L = 1 (satu level, tanpa pohon bertingkat) | — |
| Konfigurasi kedua (opsional, untuk benchmark) | `LMOTS_SHA256_N32_W4` (w = 4, p = 67, ls = 4) | `0x00000003` |

**Kenapa:**
- **w = 8** menghasilkan tanda tangan terkecil (relevan untuk chip dengan memori kecil) tetapi butuh hash paling banyak saat verifikasi (rata-rata sekitar 4.300 kali). Ini justru tempat hardware paralel kita paling terlihat manfaatnya.
- **h = 5** cukup untuk demo (32 versi firmware), dan pembuatan kunci di Python selesai dalam hitungan detik.
- **HSS L = 1** karena RFC 8554 mewajibkan dukungan format HSS, dan library Python/C umumnya menghasilkan format ini. Overhead-nya hanya 4 byte.
- **w = 4** dipakai belakangan untuk menunjukkan trade-off: tanda tangan 2× lebih besar tetapi hash jauh lebih sedikit.

**Sudah dicek:** Appendix F RFC 8554 memuat **tiga tanda tangan LMS resmi dengan parameter persis sama** (H5 + W8), ditambah satu dengan H10 + W4. Detailnya di bagian 5.

### Ukuran yang menjadi acuan

| Objek | Ukuran |
| --- | --- |
| Public key LMS (disimpan di ROM chip) | 56 byte |
| Tanda tangan HSS L=1 lengkap | **1.296 byte** (harus persis, selain itu ditolak) |
| Image firmware maksimum | 16.384 byte (16 KB), termasuk header 16 byte |

### Tata letak tanda tangan (byte offset di SIG_RAM)

| Offset | Panjang | Isi | Wajib bernilai |
| --- | --- | --- | --- |
| 0 | 4 | Nspk (jumlah level tambahan HSS) | `0` |
| 4 | 4 | q (nomor daun / nomor tanda tangan) | `< 32` |
| 8 | 4 | tipe LM-OTS | `0x00000004` |
| 12 | 32 | C (bilangan acak dari penanda tangan) | — |
| 44 | 34 × 32 = 1.088 | y[0] … y[33] (titik awal tiap rantai) | — |
| 1.132 | 4 | tipe LMS | `0x00000005` |
| 1.136 | 5 × 32 = 160 | path[0] … path[4] (jalur Merkle) | — |

Semua angka multi-byte di dalam tanda tangan memakai urutan **big-endian** (byte paling penting di depan), sesuai RFC.

### Format image firmware (yang ditandatangani)

| Offset | Panjang | Isi |
| --- | --- | --- |
| 0 | 4 | Magic `0x50465731` (ASCII "PFW1") |
| 4 | 4 | Versi firmware (u32 big-endian) |
| 8 | 4 | Panjang payload (u32 big-endian) = IMG_LEN − 16 |
| 12 | 4 | Cadangan, harus `0` |
| 16 | sisanya | Payload: program PicoRV32 |

Pesan yang ditandatangani = **seluruh image, termasuk header**. Dengan begitu nomor versi ikut terlindungi tanda tangan dan tidak bisa diubah penyerang.

---

## 2. Aturan umum desain

- **Bahasa:** Verilog-2001 (agar jalan sama di Icarus, Verilator, dan Quartus). Setiap file diawali `` `default_nettype none ``.
- **Clock:** satu domain clock 50 MHz (`FPGA_CLK1_50`). Target Fmax IP ≥ 50 MHz; nilai lebih tinggi adalah bonus.
- **Reset:** `rst` aktif-tinggi, sinkron.
- **Jabat tangan modul:** `start` = pulsa 1 cycle untuk memulai; `done` = pulsa 1 cycle saat hasil valid; `busy` = tinggi selama bekerja. Input dikunci (di-latch) saat `start`. Pengecualian: modul streaming memakai `valid/ready`.
- **Urutan byte di dalam IP:** big-endian. Bus 256 bit menyimpan byte pertama di bit `[255:248]`. Bus 512 bit menyimpan byte pertama di `[511:504]`.
- **Urutan byte di RAM (dilihat dari HPS):** HPS menulis byte apa adanya (`memcpy`). Karena ARM dan Avalon little-endian, satu word 32-bit di RAM berisi byte alamat `4k` di bit `[7:0]`. **IP yang membalik urutan saat membaca**, bukan program C. Gunakan fungsi bantu:
  ```verilog
  // ubah word RAM (little-endian) menjadi big-endian
  function [31:0] be32; input [31:0] w; be32 = {w[7:0], w[15:8], w[23:16], w[31:24]}; endfunction
  ```
- **Port baca RAM:** lebar 32 bit, alamat dalam satuan word, **latensi 1 cycle**.
- **Tanpa latch, tanpa clock turunan.** Semua register di `always @(posedge clk)`.
- **Penamaan:** satu modul per file dengan nama file = nama modul; sinyal `snake_case`; parameter `HURUF_BESAR`.

---

## 3. Daftar modul dan port

Ringkasan kepemilikan:

| Modul | Pemilik | Target selesai (lolos testbench) |
| --- | --- | --- |
| `sha256_compress` | RTL A | 6 Okt |
| `sha256_stream` | RTL A | 9 Okt |
| `lmots_chain` | RTL A | 8 Okt |
| `lmots_verify` | RTL A | 11 Okt |
| `lms_msg_hash` | RTL B | 10 Okt |
| `lms_merkle` | RTL B | 11 Okt |
| `lms_verifier_core` | RTL B | 12 Okt |
| `lms_avalon_ip` (+ RAM, ROM, reset gate) | RTL B | 14 Okt |
| `lms_verifier_stub` | RTL B | 7 Okt |
| Testbench semua modul | Verifikasi | satu hari sebelum target modulnya |

Pada MVP, setiap modul boleh memiliki core SHA-256 sendiri. Berbagi satu core antar-modul adalah optimasi fase berikutnya, bukan syarat awal.

### 3.1 `sha256_compress` — satu kali kompresi SHA-256

```verilog
module sha256_compress (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,      // pulsa: kunci block dan state_in
  input  wire [255:0] state_in,   // H0..H7, H0 di [255:224]; untuk blok pertama = IV SHA-256
  input  wire [511:0] block,      // satu blok 64 byte, byte pertama di [511:504]
  output reg  [255:0] state_out,  // = state_in + hasil kompresi (feed-forward sudah termasuk)
  output reg          done,
  output wire         busy
);
```
- Target ≤ 66 cycle per blok (iteratif, satu ronde per cycle).
- Kalau core referensi TT07 punya port berbeda, bungkus dengan adaptor agar port di atas tetap sama.
- Konstanta IV disediakan di file `rtl/sha256_pkg.vh` sebagai `` `SHA256_IV ``.

### 3.2 `sha256_stream` — hash pesan panjang sembarang (dengan padding)

```verilog
module sha256_stream (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,      // pulsa: kunci total_len, mulai dari IV
  input  wire [15:0]  total_len,  // panjang pesan dalam byte
  input  wire [31:0]  in_data,    // 4 byte big-endian, byte pertama di [31:24]
  input  wire         in_valid,
  output wire         in_ready,
  output reg  [255:0] digest,
  output reg          done
);
```
- Jumlah word yang dikirim = ceil(total_len / 4). Pada word terakhir, hanya (total_len mod 4) byte pertama yang dipakai (jika mod = 0, keempatnya).
- Padding SHA-256 (byte `0x80`, nol, panjang 64-bit) dilakukan di dalam modul ini.
- Dipakai oleh: `lms_msg_hash` (hash pesan Q), `lmots_verify` (hash Kc), `lms_merkle` (node internal).

### 3.3 `lmots_chain` — satu rantai Winternitz

```verilog
module lmots_chain #(
  parameter W = 8
) (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,
  input  wire [127:0] I,          // identifier kunci (16 byte)
  input  wire [31:0]  q,
  input  wire [15:0]  i,          // nomor rantai, 0..p-1
  input  wire [7:0]   a,          // nilai j awal (koefisien dari Q||Cksm(Q))
  input  wire [255:0] y,          // titik awal dari tanda tangan
  output reg  [255:0] z,          // ujung rantai
  output reg          done,
  output wire         busy
);
```
- Melakukan `tmp = H(I || u32(q) || u16(i) || u8(j) || tmp)` untuk j = a sampai 2^W − 2. Jumlah langkah = (2^W − 1) − a; jika a = 2^W − 1 maka z = y tanpa hash.
- Setiap langkah tepat **satu blok** SHA-256 dengan format tetap:

| Byte | Isi |
| --- | --- |
| 0–15 | I |
| 16–19 | q |
| 20–21 | i |
| 22 | j |
| 23–54 | tmp (32 byte) |
| 55 | `0x80` |
| 56–63 | panjang = 440 bit = `0x00000000000001B8` |

  Karena formatnya tetap, modul ini memakai `sha256_compress` langsung (tanpa `sha256_stream`) dengan `state_in` = IV.

### 3.4 `lmots_verify` — semua rantai LM-OTS sampai kandidat Kc

```verilog
module lmots_verify #(
  parameter W       = 8,
  parameter P       = 34,
  parameter LS      = 0,
  parameter N_CORES = 1          // jumlah lmots_chain paralel: 1, 2, atau 4
) (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,
  input  wire [127:0] I,
  input  wire [31:0]  q,
  input  wire [255:0] Q,          // hash pesan dari lms_msg_hash
  // permintaan y[idx] (diambil top-level dari SIG_RAM, offset 44 + 32*idx)
  output wire         y_req,
  output wire [6:0]   y_idx,
  input  wire [255:0] y_data,
  input  wire         y_valid,
  output reg  [255:0] Kc,
  output reg          done,
  output wire         busy
);
```
- Menghitung checksum `Cksm(Q)` dan koefisien `a_i = coef(Q || Cksm(Q), i, W)` sesuai RFC 8554 bagian 4.4 dan 4.6.
- Penjadwalan: rantai berikutnya diberikan ke core yang sedang kosong (panjang rantai tidak sama, jadi penjadwalan dinamis lebih efisien daripada pembagian tetap).
- Terakhir: `Kc = H(I || u32(q) || u16(0x8080) || z[0] || … || z[P-1])`, panjang 22 + 32P byte (1.110 byte untuk W=8), dihitung dengan `sha256_stream`.

### 3.5 `lms_msg_hash` — hash pesan Q

```verilog
module lms_msg_hash (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,
  input  wire [127:0] I,
  input  wire [31:0]  q,
  input  wire [255:0] C,
  input  wire [15:0]  img_len,    // panjang image dalam byte
  output wire [11:0]  img_addr,   // alamat word IMG_RAM
  input  wire [31:0]  img_rdata,  // data mentah RAM (little-endian), latensi 1
  output reg  [255:0] Q,
  output reg          done,
  output wire         busy
);
```
- `Q = H(I || u32(q) || u16(0x8181) || C || image)`, panjang 54 + img_len byte.
- Catatan: 54 bukan kelipatan 4, jadi byte image perlu digeser saat dirangkai ke stream. Ini titik rawan bug; uji dengan beberapa panjang image (termasuk yang bukan kelipatan 4).

### 3.6 `lms_merkle` — naik pohon Merkle sampai kandidat root

```verilog
module lms_merkle #(
  parameter H = 5
) (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,
  input  wire [127:0] I,
  input  wire [31:0]  q,
  input  wire [255:0] Kc,
  // permintaan path[idx] (dari SIG_RAM, offset 1136 + 32*idx)
  output wire         path_req,
  output wire [2:0]   path_idx,
  input  wire [255:0] path_data,
  input  wire         path_valid,
  output reg  [255:0] Tc,
  output reg          done,
  output wire         busy
);
```
- Daun: `node = 2^H + q`, `tmp = H(I || u32(node) || u16(0x8282) || Kc)` (54 byte, satu blok).
- Setiap level: jika `node` ganjil, `tmp = H(I || u32(node/2) || u16(0x8383) || path[i] || tmp)`; jika genap, `… || tmp || path[i]`. Panjang 86 byte (dua blok). Lalu `node = node/2`.

### 3.7 `lms_verifier_core` — pengendali utama

```verilog
module lms_verifier_core #(
  parameter N_CORES          = 1,
  parameter INIT_MIN_VERSION = 32'd1,
  parameter RAW_MSG_MODE     = 0      // 1 hanya untuk testbench data uji RFC
) (
  input  wire         clk,
  input  wire         rst,
  input  wire         start,
  input  wire         commit,       // naikkan min_version ke versi image yang baru lolos
  input  wire         hold,         // tahan CPU di reset dan buka kunci buffer
  input  wire [15:0]  img_len,
  input  wire [15:0]  sig_len,
  output wire [9:0]   sig_addr,     // SIG_RAM, latensi 1
  input  wire [31:0]  sig_rdata,
  output wire [11:0]  img_addr,     // IMG_RAM, latensi 1
  input  wire [31:0]  img_rdata,
  output wire         busy,
  output wire         done,
  output wire         pass,
  output wire         fail,
  output wire [7:0]   err_code,
  output wire [31:0]  cycles,       // jumlah cycle verifikasi terakhir
  output wire [31:0]  img_version,
  output wire [31:0]  min_version,
  output wire         cpu_release,  // 1 = PicoRV32 boleh jalan
  output wire         buf_lock      // 1 = buffer tidak boleh ditulis HPS
);
```
Urutan kerja:
1. **Cek format** (murah, sebelum kriptografi): `sig_len == 1296`, Nspk = 0, tipe LM-OTS dan LMS cocok dengan ROM, q < 32, `16 ≤ img_len ≤ 16384`, magic dan panjang payload di header benar.
2. `lms_msg_hash` → Q.
3. `lmots_verify` → Kc.
4. `lms_merkle` → Tc.
5. **Bandingkan Tc dengan T[1] dari ROM** secara redundan (lihat bagian 6).
6. Jika cocok, cek versi: `img_version ≥ min_version`. Jika lebih kecil → ROLLBACK.
7. PASS → `cpu_release = 1`. Selain itu → FAIL dengan kode error.

### 3.8 `lms_avalon_ip` — pembungkus untuk Platform Designer

```verilog
module lms_avalon_ip #(
  parameter N_CORES = 1
) (
  input  wire         clk,
  input  wire         reset,
  // Avalon-MM slave (dari HPS lightweight bridge)
  input  wire [12:0]  avs_address,     // alamat word, rentang 32 KB
  input  wire         avs_read,
  input  wire         avs_write,
  input  wire [31:0]  avs_writedata,
  input  wire [3:0]   avs_byteenable,
  output reg  [31:0]  avs_readdata,    // readLatency = 1, tanpa waitrequest
  // conduit ke PicoRV32
  output wire         cpu_rst_n,       // 0 = PicoRV32 ditahan reset
  input  wire [11:0]  cpu_img_addr,    // port B IMG_RAM, hanya-baca
  output wire [31:0]  cpu_img_rdata,
  // conduit status
  output wire [3:0]   status_led       // [0]=busy [1]=pass [2]=fail [3]=cpu jalan
);
```
- Berisi: register kontrol (bagian 4), SIG_RAM 4 KB, IMG_RAM 16 KB dual-port (port A untuk HPS, port B untuk PicoRV32), ROM public key, dan `lms_verifier_core`.
- **Catatan antarmuka:** bridge HPS memakai AXI, tetapi Platform Designer otomatis mengonversinya. IP kita cukup menyediakan **Avalon-MM slave** yang lebih sederhana.

### 3.9 `lms_verifier_stub` — verifier palsu untuk integrasi awal

Port **sama persis** dengan `lms_verifier_core`. Setelah `start`, menunggu 1.000 cycle, lalu PASS jika word pertama IMG_RAM adalah magic yang benar, selain itu FAIL dengan `err = 0x07`. Dipakai RTL B dan Verifikasi untuk menyiapkan board dan program C sebelum verifier asli selesai.

---

## 4. Peta register IP (dilihat dari HPS)

Alamat relatif terhadap base address IP di lightweight bridge (ditentukan Platform Designer). Rentang total 32 KB.

| Offset | Nama | Akses | Isi |
| --- | --- | --- | --- |
| `0x0000` | ID | R | Konstan `0x4C4D5301` ("LMS" versi 1). Untuk cek koneksi. |
| `0x0004` | CTRL | W | bit0 START · bit1 COMMIT · bit2 CLEAR (hapus status) · bit3 HOLD |
| `0x0008` | STATUS | R | bit0 BUSY · bit1 DONE · bit2 PASS · bit3 FAIL · bit4 CPU_RUNNING · bit5 BUF_LOCK · bit[15:8] ERR_CODE |
| `0x000C` | IMG_LEN | R/W | Panjang image (byte) |
| `0x0010` | SIG_LEN | R/W | Panjang tanda tangan (byte) |
| `0x0014` | CYCLES | R | Jumlah cycle verifikasi terakhir (dari START diterima sampai DONE) |
| `0x0018` | MIN_VERSION | R | Versi minimum yang diizinkan |
| `0x001C` | IMG_VERSION | R | Versi dari header image terakhir yang diverifikasi |
| `0x0020` | CONFIG | R | bit[3:0] N_CORES · bit[7:4] H · bit[11:8] W |
| `0x1000`–`0x1FFF` | SIG_RAM | R/W | Tanda tangan (4 KB) |
| `0x4000`–`0x7FFF` | IMG_RAM | R/W | Image firmware (16 KB) |

### Aturan perilaku (wajib, ini bagian dari keamanan)

1. **Urutan pemakaian dari HPS:** tulis HOLD → tulis SIG_RAM, IMG_RAM, SIG_LEN, IMG_LEN → tulis START → baca STATUS sampai DONE.
2. **HOLD** menahan PicoRV32 di reset dan membuka kunci buffer.
3. **Buffer terkunci** (tulisan HPS diabaikan) selama BUSY dan selama CPU berjalan. **Kenapa:** tanpa kunci ini, penyerang bisa mengganti image *setelah* diverifikasi tetapi *sebelum/saat* dijalankan (serangan time-of-check to time-of-use).
4. **START** saat BUSY diabaikan. START selalu menahan CPU di reset dulu.
5. **COMMIT** hanya berlaku jika status terakhir PASS dan `IMG_VERSION > MIN_VERSION`; lalu `MIN_VERSION = IMG_VERSION`. MIN_VERSION tidak pernah bisa turun lewat register apa pun.
6. Di FPGA, MIN_VERSION kembali ke nilai awal saat board dimatikan. Pada chip sungguhan ini berupa penghitung OTP. **Sebutkan keterbatasan ini secara jujur di proposal.**

### Kode error (ERR_CODE)

Dicek sesuai urutan di bawah; error pertama yang ditemukan yang dilaporkan.

| Kode | Nama | Arti |
| --- | --- | --- |
| `0x00` | OK | Lolos |
| `0x01` | BAD_SIG_LEN | SIG_LEN ≠ 1296 |
| `0x02` | BAD_HSS_LEVELS | Nspk ≠ 0 |
| `0x03` | BAD_OTS_TYPE | Tipe LM-OTS tidak cocok |
| `0x04` | BAD_LMS_TYPE | Tipe LMS tidak cocok |
| `0x05` | BAD_Q | q ≥ 32 |
| `0x06` | BAD_IMG_LEN | IMG_LEN di luar 16…16384 |
| `0x07` | BAD_IMG_HEADER | Magic salah, panjang payload salah, atau cadangan ≠ 0 |
| `0x08` | SIG_INVALID | Tc ≠ T[1]: tanda tangan tidak sah |
| `0x09` | ROLLBACK | Tanda tangan sah tetapi versi < MIN_VERSION |
| `0x0A` | FAULT | Comparator redundan tidak sepakat atau FSM masuk state ilegal |

---

## 5. Data uji dan format file `.hex`

Semua data uji dihasilkan skrip Python dan **tidak diedit manual**. Kunci demo dibuat dari **seed tetap** supaya file yang dihasilkan selalu sama di komputer siapa pun.

### Aturan format

| Jenis | Format per baris | Contoh pemakaian |
| --- | --- | --- |
| Nilai 256 bit | 64 karakter hex, huruf kecil, tanpa `0x`, big-endian (sama dengan `bytes.hex()` di Python) | Q, z[i], Kc, Tc |
| Nilai 512 bit | 128 karakter hex, big-endian | Blok SHA-256 |
| Nilai kecil | Lebar tetap sesuai bit (mis. 2 karakter untuk 8 bit) | koefisien a_i |
| Isi RAM | 8 karakter hex per word 32 bit, **little-endian seperti yang dilihat RAM** | memuat SIG_RAM / IMG_RAM di testbench |

Contoh isi RAM: byte `01 02 03 04` ditulis sebagai baris `04030201`. Ini persis meniru hasil `memcpy` dari HPS, sehingga testbench dan board memakai jalur yang sama.

### Struktur folder data uji

```
tv/
  sha256/            blocks.hex, state_in.hex, state_out.hex   (baris sejajar)
  <nama_kasus>/
    pubkey.bin  sig.bin  img.bin          berkas mentah
    sig.words.hex  img.words.hex          untuk $readmemh ke RAM
    rom_I.hex  rom_T1.hex                 isi ROM (I 32 hex, T1 64 hex)
    Q.hex                                 1 baris
    coef.hex                              P baris, 2 hex
    y.hex  z.hex                          P baris, 64 hex
    Kc.hex                                1 baris
    merkle.hex                            H+1 baris: hash daun, lalu tiap level
    Tc.hex                                1 baris
    expect.txt                            result=PASS|FAIL, err=0x.., version=..
```

### Daftar kasus uji minimum

| Kasus | Yang diubah | Hasil yang diharapkan |
| --- | --- | --- |
| `valid_q0` | — (daun pertama) | PASS |
| `valid_q31` | — (daun terakhir, menguji arah kiri/kanan di Merkle) | PASS |
| `valid_v2` | versi 2 | PASS |
| `valid_len_odd` | panjang image bukan kelipatan 4 | PASS |
| `bad_img_bit` | 1 bit payload dibalik | FAIL `0x08` |
| `bad_sig_C` | 1 bit C dibalik | FAIL `0x08` |
| `bad_sig_y17` | 1 bit y[17] dibalik | FAIL `0x08` |
| `bad_sig_path3` | 1 bit path[3] dibalik | FAIL `0x08` |
| `wrong_key` | ditandatangani kunci lain | FAIL `0x08` |
| `bad_sig_len` | tanda tangan 1.295 byte | FAIL `0x01` |
| `bad_nspk` | Nspk = 1 | FAIL `0x02` |
| `bad_ots_type` | tipe LM-OTS = 3 | FAIL `0x03` |
| `bad_lms_type` | tipe LMS = 6 | FAIL `0x04` |
| `bad_q_range` | q = 32 | FAIL `0x05` |
| `bad_magic` | magic salah | FAIL `0x07` |
| `rollback` | versi 1 setelah MIN_VERSION dinaikkan ke 2 | FAIL `0x09` |
| `random_flip_NNN` | 200+ kasus bit acak di image/tanda tangan | semua FAIL |

### Data uji resmi dari RFC 8554 Appendix F

Kedua test case di RFC berbentuk HSS dua level. Setiap level berisi satu tanda tangan LMS biasa, jadi bisa dipisah menjadi vektor LMS tunggal. Untuk dimasukkan ke SIG_RAM, tambahkan 4 byte `00000000` (Nspk = 0) di depan tanda tangan LMS-nya, sehingga totalnya 1.296 byte sesuai format kita.

| Kasus | Asal | Parameter | q | Public key yang dipakai | Pesan | Panjang pesan |
| --- | --- | --- | --- | --- | --- | --- |
| `rfc_tc1_l0` | TC1, `sig[0]` | H5 + W8 | 5 | Public key HSS TC1 (I = `61a5d57d…`) | Public key LMS level 1 (56 byte: `00000005 00000004 d2f14ff6… 6c500491…`) | 56 byte |
| `rfc_tc1_l1` | TC1, `final_signature` | H5 + W8 | 10 | Public key LMS level 1 (I = `d2f14ff6…`) | Teks "The powers not delegated…" | 162 byte |
| `rfc_tc2_l1` | TC2, `final_signature` | H5 + W8 | 4 | Public key LMS level 1 TC2 (I = `215f83b7…`) | Teks "The enumeration in the Constitution…" | 131 byte |
| `rfc_tc2_l0` | TC2, `sig[0]` | H10 + W4 | 3 | Public key HSS TC2 (I = `d08fabd4…`) | Public key LMS level 1 TC2 (56 byte) | 56 byte |

Kenapa berguna:
- Tiga vektor pertama memakai **parameter yang sama persis** dengan desain kita, jadi bisa menguji verifier lengkap, bukan hanya potongan modul.
- Nilai q (4, 5, 10) dan panjang pesan (56, 131, 162 byte; dua di antaranya bukan kelipatan 4) sekaligus menguji arah kiri/kanan di pohon Merkle dan penggeseran byte di `lms_msg_hash`.
- `rfc_tc2_l0` (H10 + W4) dipakai nanti jika konfigurasi kedua dibuat.
- TC2 juga menyertakan SEED dan I kunci privat (metode Appendix A). Ini bisa dipakai untuk memastikan **pembuatan kunci** di model Python juga benar: hasil K harus sama dengan public key di RFC.

Karena pesan RFC tidak memakai header image kita, testbench menjalankan `lms_verifier_core` dengan parameter `RAW_MSG_MODE = 1` (lewati cek header dan versi, seluruh isi IMG_RAM dianggap pesan). Parameter ini **hanya untuk testbench** dan wajib `0` saat sintesis; `make lint` harus memeriksa hal ini.

Cara mengambil datanya: salin teks Appendix F ke `python/rfc8554_appendix_f.txt`, lalu `gen_vectors.py` mem-parsing nilai hex-nya (gabungkan baris lanjutan) dan membuat folder `tv/rfc_*` dengan format yang sama seperti kasus lain.

---

## 6. Aturan keamanan desain

1. **Hanya ROM yang dipercaya.** Public key (tipe, I, T[1]) ada di ROM, diisi dari `rom_I.hex` dan `rom_T1.hex` saat sintesis. Tidak ada register yang bisa mengubahnya.
2. **Semua isi RAM dianggap buatan penyerang.** Parser tidak boleh membaca di luar batas buffer apa pun nilai panjang yang diberikan.
3. **Perbandingan akhir redundan:** Tc dibandingkan dengan T[1] oleh dua rangkaian berbeda (kesamaan langsung dan XOR-OR ≠ 0). PASS hanya jika keduanya sepakat; jika berbeda → FAULT.
4. **Status PASS internal multi-bit**, misalnya pola `8'hA5`, bukan satu bit. Satu bit yang terbalik akibat glitch tidak cukup untuk menghasilkan PASS.
5. **FSM one-hot dengan penjebak state ilegal:** state tidak valid langsung → FAULT, CPU tetap di reset.
6. **Reset gate default tertutup:** setelah reset board, CPU selalu ditahan sampai ada PASS.

---

## 7. Sisi software

| Berkas | Pemilik | Fungsi |
| --- | --- | --- |
| `python/lms_ref.py` | Verifikasi | Model referensi: keygen dengan seed tetap, sign, verify, dan ekspor nilai perantara |
| `python/make_image.py` | Verifikasi | Membuat image (header + payload PicoRV32) |
| `python/gen_vectors.py` | Verifikasi | Membuat seluruh folder `tv/` termasuk kasus rusak |
| `python/signer_state.json` | Verifikasi | Mencatat q terakhir yang dipakai. Jangan pernah memakai q yang sama untuk dua image berbeda, bahkan untuk demo |
| `sw/hps/lms_load.c` | RTL B + Verifikasi | Program di HPS: HOLD, tulis buffer, START, tunggu, cetak STATUS dan CYCLES |
| `sw/pico/` | RTL B | Firmware PicoRV32 (kedip LED). PicoRV32 mulai dari alamat payload (offset 16 IMG_RAM) |
| `sw/bench/` | Verifikasi | Verifikasi LMS versi software untuk PicoRV32 dan ARM (pembanding benchmark) |

Kunci di repo adalah **kunci demo**, bukan rahasia. Tulis peringatan ini di README.

---

## 8. Struktur repo dan aturan kerja

```
rtl/        modul Verilog (+ sha256_pkg.vh)
tb/         testbench, satu per modul: tb_<nama_modul>.v
tv/         data uji hasil generate (boleh di-commit agar semua memakai data sama)
python/     model referensi dan generator
sw/         hps/, pico/, bench/
quartus/    project Quartus dan Platform Designer
docs/       kontrak.md, proposal, diagram, hasil benchmark
Makefile    make tv · make test · make lint
```

- `make tv` membuat ulang semua data uji; `make test` menjalankan semua testbench di Icarus dan menampilkan PASS/FAIL; `make lint` menjalankan `verilator --lint-only` untuk semua modul.
- Setiap orang bekerja di branch `feat/<nama-modul>`. Penggabungan ke `main` lewat pull request dengan review satu orang.
- `main` harus selalu lolos `make test`.

### Definisi "modul selesai"

1. Lolos semua kasus uji yang relevan di testbench otomatis.
2. Bersih dari peringatan `verilator --lint-only`.
3. Bisa disintesis di Quartus tanpa latch.
4. Jumlah cycle dan resource (ALM, register, M10K) dicatat di `docs/hasil.md`.

---

## 9. Hal yang harus dicek minggu ini

- [x] Parameter contoh data uji di Appendix F RFC 8554: cocok (H5 + W8), lihat bagian 5.
- [ ] Port core SHA-256 referensi TT07, dan apakah lolos test vector standar (bagian 3.1).
- [ ] Versi Quartus Prime Lite yang dipakai mendukung Cyclone V.
- [ ] Library Python LMS yang hasilnya cocok dengan RFC 8554.
- [ ] FAQ panitia soal pemakaian komponen referensi.

---

## Aturan testbench dan lingkungan kerja

### Testbench
- Setiap tes punya dua file: `tb/tb_<nama>.v` (testbench) dan `tb/<nama>.f`
  (daftar file yang di-compile, path dari root repo).
- Testbench wajib mencetak tepat salah satu:
  - `TEST PASSED` kalau semua cek benar
  - `TEST FAILED: <alasan>` kalau ada yang salah
- Testbench wajib memanggil `$finish` dan punya batas waktu (timeout).
- Data uji dibaca dari `tv/` dengan `$readmemh`, tidak ditulis manual.
- `make test` harus lolos di laptop sebelum push. CI di GitHub menjalankan
  perintah yang sama di setiap push ke `main` dan setiap Pull Request.
- Kalau `main` merah, orang yang terakhir push memperbaikinya dulu.

### Instal alat
| OS | Perintah |
| --- | --- |
| Arch / EndeavourOS | `sudo pacman -S iverilog gtkwave python-pytest make` |
| Ubuntu / WSL | `sudo apt install iverilog gtkwave python3-pytest make` |
| Windows | Pakai WSL (Ubuntu), lalu ikuti baris Ubuntu |

Cek setup: `make test` harus menampilkan `smoke  lolos`.

___

## Riwayat perubahan

| Versi | Tanggal | Perubahan | Disetujui |
| --- | --- | --- | --- |
| 0.1 | 3 Okt 2026 | Draf awal | — |
| 0.2 | 3 Okt 2026 | Data uji resmi RFC 8554 ditambahkan; parameter `RAW_MSG_MODE` | — |
| 0.3 | 3 Okt 2026 | Tambah aturan testbench, CI, dan perintah install per OS | - |
