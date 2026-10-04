# tv/ — data uji

Dibuat oleh skrip di `python/`, jangan diedit tangan. Format `.hex` mengikuti
`docs/kontrak.md` (bagian format file `.hex`) supaya bisa dibaca `$readmemh`.

Penamaan yang disarankan:

- `rfc_tc1_*.hex` — dari RFC 8554 Appendix F
- `valid_*.hex` — tanda tangan asli, harus lolos
- `bad_<serangan>_*.hex` — sengaja dirusak, harus gagal (dari daftar skenario Security)
