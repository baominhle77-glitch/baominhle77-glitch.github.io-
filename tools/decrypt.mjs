#!/usr/bin/env node
/*
 * decrypt.mjs — Khôi phục nội dung gốc từ trang đã mã hóa (cần mật khẩu).
 * -----------------------------------------------------------------------------
 * Dùng khi muốn SỬA nội dung một app đã bật Lớp B:
 *   node tools/decrypt.mjs index.html "<mat-khau>" > index.src.html
 *   # sửa index.src.html, đổi mode về 'local' để xem thử nếu muốn
 *   node tools/encrypt.mjs index.src.html index.html "<mat-khau>"   # mã hóa lại
 *
 * Nhờ vậy KHÔNG cần commit bản gốc (plaintext) lên repo public — có mật khẩu là
 * tái tạo lại được bất cứ lúc nào.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';

const [input, pass] = process.argv.slice(2);
if (!input || !pass) {
  console.error('Cách dùng: node tools/decrypt.mjs <input.html> "<mat-khau>" > out.src.html');
  process.exit(1);
}
const html = fs.readFileSync(input, 'utf8');
const m = html.match(/<script type="application\/gate-payload">([\s\S]*?)<\/script>/);
if (!m) { console.error('Không tìm thấy payload mã hóa trong file.'); process.exit(1); }
const pl = JSON.parse(m[1]);

const salt = Buffer.from(pl.saltB64, 'base64');
const iv = Buffer.from(pl.ivB64, 'base64');
const both = Buffer.from(pl.ctB64, 'base64');
const tag = both.subarray(both.length - 16);      // WebCrypto ghép ct||tag (tag 16 byte)
const ct = both.subarray(0, both.length - 16);
const key = crypto.pbkdf2Sync(pass, salt, pl.iterations || 200000, 32, 'sha256');
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(tag);
let plain;
try {
  plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
} catch (e) {
  console.error('Sai mật khẩu hoặc dữ liệu hỏng.'); process.exit(1);
}

// Ghép lại thành file HTML gốc (thay vùng payload bằng nội dung đã giải mã).
const before = html.slice(0, m.index).replace('<div id="gate-content"></div>', '').replace(/\n$/, '');
const after = html.slice(m.index + m[0].length).replace(/^\s*/, '');
process.stdout.write(before + '\n' + plain + '\n' + after);
