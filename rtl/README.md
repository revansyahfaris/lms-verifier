# rtl/

Setiap modul mengikuti aturan colokan di `docs/kontrak.md`:
port `start` / `done` / `busy`, clock 50 MHz, reset **aktif-tinggi**, data big-endian.

Pakai konstanta dari `rtl/common/lms_params.vh` (`` `include "lms_params.vh" ``),
jangan tulis angka seperti 34 atau 1296 langsung di kode.

Satu file = satu modul, nama file = nama modul (`sha256_core.v` berisi `module sha256_core`).
Kode dari luar (misalnya SHA-256 referensi TT07) taruh apa adanya dan catat sumber + lisensinya
di header file; perubahan kita taruh di file wrapper terpisah.
