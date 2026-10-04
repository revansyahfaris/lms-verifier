# Cara Kerja di Repo Ini

## Versi singkat

1. Ambil `main` terbaru: `git switch main && git pull`
2. Buat branch untuk modulmu: `git switch -c rtla/sha256-core`
3. Kerjakan, commit sering.
4. Pastikan `make test` lolos di laptopmu.
5. `git push -u origin <nama-branch>` → buka Pull Request di GitHub.
6. Minta **1 orang** review. Setelah di-approve dan CI hijau → merge.

`main` dikunci: tidak ada yang bisa push langsung, termasuk ketua.

## Nama branch

Format: `<peran>/<modul>` — huruf kecil, pakai tanda hubung.

| Peran      | Prefix     | Contoh                          |
|------------|------------|---------------------------------|
| RTL A      | `rtla/`    | `rtla/sha256-core`, `rtla/chain` |
| RTL B      | `rtlb/`    | `rtlb/stub`, `rtlb/merkle`       |
| Verifikasi | `verif/`   | `verif/lms-model`, `verif/tb-chain` |
| Security   | `sec/`     | `sec/threat-model`, `sec/proposal` |
| Kontrak    | `kontrak/` | `kontrak/v0.3-error-codes`       |

Satu branch = satu modul / satu hal. Jangan campur dua modul dalam satu PR.

## Pesan commit

Singkat, kata kerja di depan, boleh Bahasa Indonesia:

```
sha256: tambah wrapper port start/done/busy
tb: testbench rantai hash dengan vektor RFC
docs: perbarui peta register
```

## Aturan Pull Request

- **Reviewer** mengecek: sesuai `kontrak.md`? testbench ada dan lolos? tidak ada file hasil build?
- PR yang **mengubah `docs/kontrak.md` atau `rtl/common/`** harus disetujui ketua,
  karena mengubah "colokan" yang dipakai semua orang. Umumkan juga di grup chat.
- Lebih baik PR kecil yang sering daripada satu PR raksasa di akhir.

## Aturan testbench

Supaya CI bisa menilai otomatis:

1. Setiap testbench `tb/tb_<nama>.v` punya file daftar `tb/<nama>.f`
   berisi semua file `.v` yang dibutuhkan (path relatif dari root repo).
2. Testbench **wajib** mencetak tepat salah satu:
   - `TEST PASSED` kalau semua cek benar
   - `TEST FAILED: <alasan>` kalau ada yang salah
3. Testbench wajib memanggil `$finish` (jangan sampai jalan selamanya).
4. Data uji dibaca dari `tv/` dengan `$readmemh`, bukan ditulis manual di testbench.

Contoh lengkap: `tb/tb_smoke.v` + `tb/smoke.f`.

## Yang TIDAK boleh di-commit

Hasil build Quartus (`db/`, `output_files/`, `incremental_db/`), file waveform
(`.vcd`, `.fst`), `build/`, dan file besar lain. Sudah diatur di `.gitignore`.
Pengecualian: file `.sof` final untuk demo boleh ditaruh di `quartus/release/`.
