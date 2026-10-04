# python/

- `rfc8554_appendix_f.txt` — salinan teks Appendix F RFC 8554
- model LMS, generator data uji ke `tv/`, dan `tests/`

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r python/requirements.txt
make py-test
```
