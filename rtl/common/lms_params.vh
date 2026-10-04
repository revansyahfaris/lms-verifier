// Konstanta bersama. Sumber kebenaran: docs/kontrak.md (bagian 1-2).
// Mengubah file ini = mengubah kontrak -> wajib PR yang disetujui ketua.
`ifndef LMS_PARAMS_VH
`define LMS_PARAMS_VH

// LMS: LMS_SHA256_M32_H5, LM-OTS: LMOTS_SHA256_N32_W8
`define LMS_N          32      // byte per nilai hash
`define LMS_H          5       // tinggi pohon Merkle -> 32 kunci
`define LMS_W          8       // parameter Winternitz
`define LMS_P          34      // jumlah rantai hash (32 pesan + 2 checksum)
`define LMS_CHAIN_MAX  255     // langkah maksimum per rantai = 2^W - 1

// Ukuran batas
`define SIG_BYTES      1296
`define FW_MAX_BYTES   16384   // 16 KB, termasuk header
`define FW_HDR_BYTES   16

// Sistem
`define CLK_HZ         50000000

`endif
