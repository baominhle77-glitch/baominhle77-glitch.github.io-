#!/usr/bin/env node
/*
 * set-password.mjs — Tạo khối cấu hình pbkdf2 mới cho một mật khẩu.
 * Dùng để ĐỔI MẬT KHẨU cổng truy cập.
 *
 *   node tools/set-password.mjs "mat-khau-moi-cua-ban"
 *
 * Sao chép khối "pbkdf2: {...}" in ra rồi dán đè vào window.GATE trong:
 *   - index.html                (app SPARE)
 *   - boitoan/index.html        (app Bói toán)
 *   - (repo MEDORA) index.html  (app Y đa khoa)
 * Mật khẩu KHÔNG bao giờ được lưu ở dạng gốc trong repo — chỉ lưu hash.
 */
import crypto from 'node:crypto';

const pass = process.argv[2];
if (!pass) {
  console.error('Cách dùng: node tools/set-password.mjs "mat-khau-moi"');
  process.exit(1);
}

const salt = crypto.randomBytes(16);
const iterations = 200000;
const keylen = 32;
const hash = crypto.pbkdf2Sync(pass, salt, iterations, keylen, 'sha256');

const block = `pbkdf2: { saltB64: '${salt.toString('base64')}', hashB64: '${hash.toString('base64')}', iterations: ${iterations}, keylen: ${keylen} }`;

console.log('\n// ===== Dán khối này vào window.GATE (thay dòng pbkdf2 cũ) =====');
console.log(block);
console.log('\n// Mật khẩu mới:', JSON.stringify(pass), '(hãy nhớ kỹ — không lưu trong repo)\n');
