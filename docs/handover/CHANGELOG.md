# Nhật ký thay đổi (bàn giao) — MEDORA

## 2026-07-21 — Khởi tạo kiểm soát truy cập
- Thêm Lớp A: `robots.txt`, meta `noindex`, `assets/gate.js` + `gate.css`, wire vào `index.html`.
- Thêm `tools/encrypt.mjs`, `tools/set-password.mjs`.
- Thêm `.github/workflows/handover.yml`.
- Backend (Lớp C) dùng chung từ repo `baominhle77-glitch.github.io`.

<!-- Mục mới thêm phía trên. STATUS.md do máy tự sinh sau mỗi push. -->

## 2026-07-21 (b) — Mã hóa MEDORA
- Mã hóa AES-256-GCM nội dung MEDORA (mode:'encrypted'); thêm tools/decrypt.mjs; .gitignore chặn *.src.html.
- Đã test trình duyệt thật: mở/khóa/sai-mật-khẩu/không-lỗi.
