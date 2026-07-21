# 📋 BÀN GIAO — MEDORA (Y đa khoa)

> Repo này chứa app **MEDORA — Học Y đa khoa** (`index.html`).
> Hệ thống kiểm soát truy cập dùng CHUNG thiết kế với repo chính
> `baominhle77-glitch.github.io`. Đọc `HANDOVER.md` + `docs/ARCHITECTURE.md`
> ở repo đó để hiểu đầy đủ 3 lớp bảo vệ.

**Cập nhật:** 2026-07-21 · **Nhánh:** `claude/webapp-automation-access-control-3sierx`

## Đã làm ở repo này
- ✅ **Lớp A**: `robots.txt`, meta `noindex/nofollow/noarchive`, `referrer:no-referrer`.
- ✅ Khóa mật khẩu: `assets/gate.js` + `assets/gate.css`, wire vào `index.html`
  (`window.GATE.app = 'medora'`).
- 🟡 **Lớp B** (mã hóa): công cụ có sẵn trong `tools/encrypt.mjs`. Xem hướng dẫn repo chính.
- 🟡 **Lớp C** (duyệt + Telegram): backend nằm ở repo chính (`baominhle77-glitch.github.io/backend/`).
  Một Worker phục vụ cả 3 app qua trường `app`. Để bật: đặt `window.GATE.mode='approval'`
  và `backend='https://baominh-gate.<ban>.workers.dev'` trong `index.html`.
- ✅ `.github/workflows/handover.yml`: tự cập nhật `docs/handover/STATUS.md` sau mỗi push.

## Mật khẩu
- Mật khẩu cổng bàn giao riêng trong hội thoại (KHÔNG lưu trong repo — chỉ hash PBKDF2).
- Đổi: `node tools/set-password.mjs "mk-moi"` → dán khối `pbkdf2` vào `window.GATE` trong `index.html`.

## Lên web
- Repo project (tên có dấu `-` ở cuối). Bật Pages tại Settings → Pages → Source = `main`/root.
- Merge nhánh vào `main` → tự xuất bản.
