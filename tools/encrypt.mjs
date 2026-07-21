#!/usr/bin/env node
/*
 * encrypt.mjs — Mã hóa NỘI DUNG một trang HTML (lớp bảo vệ THẬT, offline).
 * -----------------------------------------------------------------------------
 * Sau khi mã hóa, mã nguồn tĩnh CHỈ chứa chuỗi mã hóa AES-GCM. Không có mật khẩu
 * đúng thì tải về cũng không đọc được nội dung. gate.js (mode:'encrypted') sẽ
 * giải mã ngay trong trình duyệt khi nhập đúng mật khẩu.
 *
 * CÁCH DÙNG:
 *   node tools/encrypt.mjs <input.html> <output.html> "<mat-khau>"
 *
 * Kịch bản khuyến nghị (để bản gốc không bị mất):
 *   1) Đổi tên trang gốc: index.html  ->  index.src.html   (giữ lại để chỉnh sau)
 *   2) node tools/encrypt.mjs index.src.html index.html "mat-khau-cua-ban"
 *   3) Chỉ commit index.html (đã mã hóa). Giữ index.src.html ở máy/nhánh riêng.
 *
 * Vùng được mã hóa:
 *   - Nếu có cặp dấu   <!-- gate:begin --> ... <!-- gate:end -->  -> mã hóa phần giữa.
 *   - Nếu không, mã hóa toàn bộ phần bên trong <body>.
 * Phần <head> (style/meta/gate config) giữ nguyên để trang vẫn có khung + cổng khóa.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';

const [input, output, pass] = process.argv.slice(2);
if (!input || !output || !pass) {
  console.error('Cách dùng: node tools/encrypt.mjs <input.html> <output.html> "<mat-khau>"');
  process.exit(1);
}

const src = fs.readFileSync(input, 'utf8');

// 1) Tách vùng bí mật
let secret, before, after;
const begin = '<!-- gate:begin -->', end = '<!-- gate:end -->';
if (src.includes(begin) && src.includes(end)) {
  before = src.slice(0, src.indexOf(begin) + begin.length);
  after = src.slice(src.indexOf(end));
  secret = src.slice(src.indexOf(begin) + begin.length, src.indexOf(end));
} else {
  const m = src.match(/<body[^>]*>([\s\S]*)<\/body>/i);
  if (!m) { console.error('Không tìm thấy <body>. Hãy thêm <!-- gate:begin/end --> quanh vùng cần mã hóa.'); process.exit(1); }
  before = src.slice(0, m.index) + src.slice(m.index, m.index + m[0].indexOf('>') + 1); // tới hết <body ...>
  after = '</body>' + src.slice(m.index + m[0].length);
  secret = m[1];
}

// 2) Mã hóa AES-GCM, khóa dẫn xuất PBKDF2-SHA256 (khớp gate.js)
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const iterations = 200000;
const key = crypto.pbkdf2Sync(pass, salt, iterations, 32, 'sha256');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();
// WebCrypto AES-GCM ghép ciphertext||tag, nên ta nối lại đúng thứ tự đó.
const payload = {
  saltB64: salt.toString('base64'),
  ivB64: iv.toString('base64'),
  ctB64: Buffer.concat([ct, tag]).toString('base64'),
  iterations
};

// 3) Ghép trang đã mã hóa: chỉ còn khung + container rỗng + payload
const encryptedRegion =
  '\n<div id="gate-content"></div>\n' +
  '<script type="application/gate-payload">' + JSON.stringify(payload) + '</script>\n';

// Tự chuyển mode của window.GATE trong <head> sang 'encrypted' ở file xuất ra
// (file master giữ nguyên mode:'local' để còn xem thử được).
before = before.replace(/mode:\s*'[^']*'/, "mode: 'encrypted'");

const out = before + encryptedRegion + after;
fs.writeFileSync(output, out, 'utf8');

console.log('✅ Đã mã hóa:', input, '->', output);
console.log('   Nhớ đặt mode:\'encrypted\' trong window.GATE của trang này.');
console.log('   Kích thước bí mật:', secret.length, 'ký tự  ->  ciphertext', payload.ctB64.length, 'ký tự base64');
