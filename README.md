# AL STUDIO PIXEL

Website dashboard untuk workflow Roblox creator tools. Project ini **terpisah** dari repository lama `AL-STUDIO-UPLOUAD-ID`.

## Yang sudah bisa dipakai
- Responsive dashboard dengan navigasi.
- GUI & Asset Library: contoh UI cards, pencarian/filter, upload gambar milik sendiri, download dan hapus asset lokal.
- Live Icon Catalog: pencarian icon SVG melalui Iconify API (butuh internet), menampilkan hasil icon dari berbagai koleksi dan menyediakan open/download SVG.
- Luau Script Scanner: analisis pola dasar dengan nomor baris dan penjelasan.
- 3D Model Library: upload/download `.rbxm`, `.rbxmx`, dan `.zip` (disimpan di server yang menjalankan website).
- Roblox Publisher readiness form dan status konfigurasi.
- Export metadata library ke JSON.
- Node.js backend tanpa dependency tambahan.

## Menjalankan di komputer
1. Install Node.js 18 atau lebih baru.
2. Extract ZIP.
3. Buka folder project di VS Code.
4. Buka Terminal di folder itu, jalankan:
   ```bash
   npm start
   ```
   atau:
   ```bash
   node server.js
   ```
5. Buka `http://localhost:3000`.

## Deploy
Bisa dijalankan pada host yang mendukung Node.js dan penyimpanan file persisten. Untuk GitHub, buat repository BARU bernama `AL-STUDIO-PIXEL`, lalu upload isi folder ini. GitHub Pages saja tidak dapat menjalankan `server.js`/API; gunakan host Node.js untuk backend. Simpan data/ dan uploads/ pada disk persisten atau ubah storage menjadi database/object storage.

## Batasan penting
- Kartu asset contoh adalah referensi UI, bukan ribuan file yang dibundel di ZIP. Live Icon Catalog mencari icon secara online melalui Iconify API saat website punya koneksi internet; icon tidak disimpan offline otomatis. Tambahkan hanya asset yang dibuat sendiri atau yang lisensinya mengizinkan distribusi.
- Scanner menggunakan heuristik regex, bukan parser Luau penuh. Ia bisa melewatkan backdoor atau memberi false positive. Ia tidak menjamin keamanan.
- Upload model saat ini hanya menyimpan file di server lokal; belum mengunggah model ke Roblox.
- Roblox Publisher sengaja tidak berpura-pura sukses. Untuk mengaktifkan publikasi, implementasikan endpoint Open Cloud yang tepat untuk jenis asset, gunakan API key server-side, creator ID yang benar, permission minimum, autentikasi pengguna, rate limiting, dan validasi file. Jangan pernah menyimpan API key di frontend.
- Sebelum membuka website untuk publik, tambahkan login, authorization, rate limiting, malware scanning, storage quota, logging, backup, dan proteksi CSRF/abuse. Versi ini adalah functional self-hosted starter, bukan layanan publik production-hardened.

## Keamanan
Jangan commit `.env` atau Roblox API key. File `.env.example` hanya template. Jangan upload file milik orang lain tanpa izin.
