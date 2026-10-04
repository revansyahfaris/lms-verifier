# LMS Secure-Boot Verifier — PERURI Chip Hackathon 2026

IP hardware di FPGA yang **menahan prosesor dalam reset** sampai tanda tangan firmware-nya
terbukti asli. Tanda tangannya pakai **LMS (RFC 8554)**, skema tanda tangan
*post-quantum* berbasis hash.

Target board: **DE10-Nano (Cyclone V SoC)** — HPS mengirim image, IP memverifikasi,
lalu melepas reset PicoRV32 kalau lolos.

> Semua angka dan aturan bersama ada di **[`docs/kontrak.md`](docs/kontrak.md)**.
> Kalau README ini berbeda dengan kontrak, **kontrak yang benar**.

## Peta folder

| Folder      | Isi                                                        | Pemilik utama |
|-------------|------------------------------------------------------------|---------------|
| `rtl/common`| Konstanta bersama (`lms_params.vh`) — dipakai semua modul   | Semua (lewat PR) |
| `rtl/sha256`| Core SHA-256 + wrapper port sesuai kontrak                 | RTL A |
| `rtl/lms`   | Hash pesan panjang, rantai hash, pengatur rantai           | RTL A |
| `rtl/stub`  | Verifier palsu untuk integrasi awal                        | RTL B |
| `rtl/top`   | Merkle, pengendali utama, register & RAM untuk HPS         | RTL B |
| `tb/`       | Testbench + daftar file per tes (`*.f`)                    | Verifikasi |
| `tv/`       | Data uji `.hex` hasil generator Python                     | Verifikasi |
| `python/`   | Model LMS, generator data uji, unit test                   | Verifikasi |
| `sw/`       | Program C di HPS, firmware PicoRV32, benchmark software    | Verifikasi + RTL B |
| `quartus/`  | Proyek Quartus & Platform Designer                         | RTL B |
| `docs/`     | Kontrak, model ancaman, proposal, diagram                  | Security & proposal |

## Mulai cepat (≤ 5 menit)

Butuh: Git, Python 3, Icarus Verilog, GTKWave, `make`.

```bash
git clone <url-repo>
cd lms-verifier
make test        # jalankan semua testbench + unit test Python
make sim TB=smoke   # jalankan satu testbench, lalu buka build/smoke.vcd di GTKWave
```

Kalau `make test` hijau, setup kamu sudah benar.

## Cara kerja tim

Ringkasnya: **satu branch per modul → Pull Request → direview 1 orang → merge ke `main`.**
Detail lengkap di [`CONTRIBUTING.md`](CONTRIBUTING.md).
