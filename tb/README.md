# tb/

Pasangan file per tes:

- `tb_<nama>.v` — testbench
- `<nama>.f` — daftar file yang di-compile (path dari root repo), contoh:

```
rtl/sha256/sha256_core.v
rtl/sha256/sha256_wrap.v
tb/tb_sha256.v
```

`make test` otomatis menemukan semua `*.f`. Aturan output ada di `CONTRIBUTING.md`.
