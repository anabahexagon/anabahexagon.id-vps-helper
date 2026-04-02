# Anaba Hexagon VPS Helper

API Utility untuk menangani operasi SSH Key (Generate & Derive) yang tidak didukung oleh Cloudflare Workers.

## Cara Instalasi di VPS:

1. Pastikan Node.js sudah terinstal di VPS.
2. Unggah folder ini ke VPS Anda.
3. Masuk ke folder tersebut dan jalankan:
   ```bash
   npm install
   ```
4. Edit file `.env` dan ganti `SECRET_KEY` dengan kunci rahasia Anda.
5. Jalankan aplikasi:
   ```bash
   node server.js
   ```
   Atau menggunakan PM2 agar berjalan di background:
   ```bash
   pm2 start server.js --name anaba-vps-helper
   ```
6. Pastikan port `3005` (atau yang Anda atur di `.env`) terbuka di Firewall VPS Anda.

## Endpoint:
- `POST /generate`: Membuat SSH Key baru.
- `POST /derive`: Mengambil Public Key dari Private Key.

**Headers Wajib:**
- `User-Agent: Anaba-Admin-App`
- `X-Anaba-Secret-Key: <SECRET_KEY_ANDA>`
