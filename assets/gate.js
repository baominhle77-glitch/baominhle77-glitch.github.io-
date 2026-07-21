/*!
 * gate.js — Cổng truy cập dùng chung cho các webapp của BaoMinh
 * ----------------------------------------------------------------------------
 * MỤC TIÊU: chặn người lạ đọc nội dung khi chưa "đăng nhập".
 *
 * 3 chế độ (đặt trong window.GATE.mode):
 *   'local'    — Khóa bằng mật khẩu, kiểm tra bằng PBKDF2 ngay trong trình duyệt.
 *                Hoạt động OFFLINE. Đây là lớp NGĂN CHẶN (deterrent): người
 *                thường/không rành sẽ bị chặn, nhưng người rành kỹ thuật vẫn có
 *                thể đọc mã nguồn tĩnh. Muốn "tải về cũng không đọc được" thì
 *                bật thêm mã hóa (xem 'encrypted') hoặc dùng backend 'approval'.
 *   'encrypted'— Nội dung thật được mã hóa AES-GCM (xem tools/encrypt.mjs).
 *                Không có mật khẩu đúng thì trong mã nguồn chỉ là chuỗi mã hóa.
 *                Đây là lớp bảo vệ THẬT, vẫn chạy offline, dùng chung 1 mật khẩu.
 *   'approval' — Gọi backend (Cloudflare Worker). Backend ghi lại IP/thiết bị,
 *                gửi Telegram cho chủ để DUYỆT từng người. Chỉ khi được duyệt
 *                mới cấp phiên + (tùy chọn) khóa giải mã. Đây là lớp KIỂM SOÁT
 *                đầy đủ theo yêu cầu "chỉ tôi phê duyệt".
 *
 * Cấu hình: đặt window.GATE = {...} TRƯỚC khi nạp file này. Xem docs/ARCHITECTURE.md
 */
(function () {
  "use strict";

  var CFG = window.GATE || {};
  var APP = CFG.app || "app";
  var MODE = CFG.mode || "local";
  var BACKEND = (CFG.backend || "").replace(/\/+$/, "");
  var TITLE = CFG.title || "Khu vực riêng tư";
  var SUBTITLE = CFG.subtitle || "Nhập mật khẩu để tiếp tục.";
  var SESSION_KEY = "gate_ok_" + APP;
  var REMEMBER_KEY = "gate_remember_" + APP;
  var TOKEN_KEY = "gate_token_" + APP;

  /* -------------------------- tiện ích mã hóa -------------------------- */
  function b64ToBuf(b64) {
    var bin = atob(b64), len = bin.length, buf = new Uint8Array(len);
    for (var i = 0; i < len; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  }
  function bufToB64(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // Dẫn xuất "bits" từ mật khẩu để so khớp hash (PBKDF2-SHA256).
  function deriveBits(pass, saltBuf, iterations, keylen) {
    return crypto.subtle
      .importKey("raw", new TextEncoder().encode(pass), { name: "PBKDF2" }, false, ["deriveBits"])
      .then(function (baseKey) {
        return crypto.subtle.deriveBits(
          { name: "PBKDF2", salt: saltBuf, iterations: iterations, hash: "SHA-256" },
          baseKey,
          keylen * 8
        );
      });
  }

  // Dẫn xuất khóa AES-GCM từ mật khẩu (dùng cho chế độ mã hóa).
  function deriveAesKey(pass, saltBuf, iterations) {
    return crypto.subtle
      .importKey("raw", new TextEncoder().encode(pass), { name: "PBKDF2" }, false, ["deriveKey"])
      .then(function (baseKey) {
        return crypto.subtle.deriveKey(
          { name: "PBKDF2", salt: saltBuf, iterations: iterations, hash: "SHA-256" },
          baseKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );
      });
  }

  /* -------------------------- kiểm tra mật khẩu (local) -------------------------- */
  function verifyLocal(pass) {
    var p = CFG.pbkdf2 || {};
    var salt = b64ToBuf(p.saltB64);
    return deriveBits(pass, salt, p.iterations, p.keylen).then(function (bits) {
      var got = new Uint8Array(bits);
      var want = b64ToBuf(p.hashB64);
      return timingSafeEqual(got, want);
    });
  }

  /* -------------------------- giải mã nội dung (encrypted) -------------------------- */
  // Trang mã hóa chứa: <script type="application/gate-payload">{saltB64,ivB64,ctB64,iterations}</script>
  function decryptPayload(pass) {
    var el = document.querySelector('script[type="application/gate-payload"]');
    if (!el) return Promise.reject(new Error("Không tìm thấy nội dung mã hóa."));
    var pl = JSON.parse(el.textContent);
    var salt = b64ToBuf(pl.saltB64);
    var iv = b64ToBuf(pl.ivB64);
    var ct = b64ToBuf(pl.ctB64);
    return deriveAesKey(pass, salt, pl.iterations || 200000).then(function (key) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ct);
    }).then(function (plainBuf) {
      return new TextDecoder().decode(plainBuf);
    });
  }

  function injectHtml(html) {
    var host = document.getElementById("gate-content") || document.body;
    host.innerHTML = html;
    // innerHTML không tự chạy <script>, phải tạo lại từng thẻ.
    var scripts = host.querySelectorAll("script");
    scripts.forEach(function (old) {
      var s = document.createElement("script");
      for (var i = 0; i < old.attributes.length; i++) {
        s.setAttribute(old.attributes[i].name, old.attributes[i].value);
      }
      s.textContent = old.textContent;
      old.parentNode.replaceChild(s, old);
    });
  }

  /* -------------------------- backend duyệt (approval) -------------------------- */
  function fingerprint() {
    // Dấu vết thiết bị nhẹ (không xâm phạm) để chủ nhận diện phiên yêu cầu.
    return {
      ua: navigator.userAgent,
      lang: navigator.language,
      tz: (Intl.DateTimeFormat().resolvedOptions() || {}).timeZone || "",
      screen: (screen.width + "x" + screen.height),
      platform: navigator.platform || ""
    };
  }

  function requestApproval(name, note) {
    return fetch(BACKEND + "/api/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ app: APP, name: name, note: note, device: fingerprint() })
    }).then(function (r) {
      if (!r.ok) throw new Error("Không gửi được yêu cầu (" + r.status + ").");
      return r.json();
    });
  }

  function pollStatus(id, onUpdate) {
    var stopped = false;
    function tick() {
      if (stopped) return;
      fetch(BACKEND + "/api/status?id=" + encodeURIComponent(id) + "&app=" + encodeURIComponent(APP))
        .then(function (r) { return r.json(); })
        .then(function (data) {
          onUpdate(data);
          if (data.status === "approved" || data.status === "denied") { stopped = true; return; }
          setTimeout(tick, 3000);
        })
        .catch(function () { setTimeout(tick, 4000); });
    }
    tick();
    return function () { stopped = true; };
  }

  /* -------------------------- mở khóa / hiện nội dung -------------------------- */
  function reveal() {
    document.documentElement.classList.remove("gate-locked");
    var root = document.getElementById("gate-root");
    if (root) root.parentNode.removeChild(root);
  }

  function unlockLocalOrEncrypted(pass, remember) {
    var work;
    if (MODE === "encrypted") {
      work = decryptPayload(pass).then(function (html) { injectHtml(html); });
    } else {
      work = verifyLocal(pass).then(function (ok) {
        if (!ok) throw new Error("BAD_PASS");
      });
    }
    return work.then(function () {
      try {
        sessionStorage.setItem(SESSION_KEY, "1");
        if (remember) localStorage.setItem(REMEMBER_KEY, "1");
      } catch (e) {}
      reveal();
    });
  }

  /* -------------------------- giao diện khóa -------------------------- */
  function buildUI() {
    var root = document.createElement("div");
    root.id = "gate-root";
    root.innerHTML =
      '<div class="gate-card" role="dialog" aria-modal="true" aria-label="Cổng truy cập">' +
        '<div class="gate-sigil">🔒</div>' +
        '<h1 class="gate-title"></h1>' +
        '<p class="gate-sub"></p>' +
        '<form class="gate-form" autocomplete="off">' +
          '<div class="gate-approval-fields" style="display:none">' +
            '<input class="gate-input" name="gname" type="text" placeholder="Tên của bạn" autocomplete="off">' +
            '<input class="gate-input" name="gnote" type="text" placeholder="Lý do truy cập (tùy chọn)" autocomplete="off">' +
          '</div>' +
          '<div class="gate-pass-field">' +
            '<input class="gate-input" name="gpass" type="password" placeholder="Mật khẩu" autocomplete="off" autofocus>' +
          '</div>' +
          '<label class="gate-remember"><input type="checkbox" name="gremember"> Ghi nhớ máy này</label>' +
          '<button class="gate-btn" type="submit">Mở khóa</button>' +
          '<div class="gate-msg" aria-live="polite"></div>' +
        '</form>' +
        '<div class="gate-foot">Khu vực riêng tư · Không lập chỉ mục · Truy cập được ghi nhận</div>' +
      '</div>';
    document.body.appendChild(root);

    root.querySelector(".gate-title").textContent = TITLE;
    root.querySelector(".gate-sub").textContent = SUBTITLE;

    var form = root.querySelector(".gate-form");
    var msg = root.querySelector(".gate-msg");
    var passField = root.querySelector(".gate-pass-field");
    var approvalFields = root.querySelector(".gate-approval-fields");
    var btn = root.querySelector(".gate-btn");

    if (MODE === "approval") {
      approvalFields.style.display = "";
      // Chế độ approval: mật khẩu có thể không cần (backend cấp quyền). Ẩn nếu không cấu hình.
      if (!CFG.approvalPassword) passField.style.display = "none";
      btn.textContent = "Gửi yêu cầu truy cập";
      SUBTITLE = CFG.subtitle || "Gửi yêu cầu — chủ sẽ duyệt qua Telegram hoặc máy của họ.";
      root.querySelector(".gate-sub").textContent = SUBTITLE;
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      msg.className = "gate-msg";
      var pass = form.gpass ? form.gpass.value : "";
      var remember = form.gremember && form.gremember.checked;

      if (MODE === "approval") {
        var name = (form.gname.value || "").trim();
        if (!name) { msg.textContent = "Vui lòng nhập tên."; msg.className = "gate-msg err"; return; }
        btn.disabled = true; msg.textContent = "Đang gửi yêu cầu…";
        requestApproval(name, (form.gnote.value || "").trim()).then(function (res) {
          msg.className = "gate-msg wait";
          msg.textContent = "Đã gửi. Đang chờ chủ duyệt…";
          form.querySelectorAll("input,button").forEach(function (x) { x.disabled = true; });
          pollStatus(res.id, function (data) {
            if (data.status === "approved") {
              try {
                sessionStorage.setItem(SESSION_KEY, "1");
                if (data.token) localStorage.setItem(TOKEN_KEY, data.token);
              } catch (e) {}
              msg.className = "gate-msg ok"; msg.textContent = "Đã được duyệt. Đang mở…";
              // Nếu backend trả khóa giải mã và trang được mã hóa:
              if (data.key && document.querySelector('script[type="application/gate-payload"]')) {
                decryptPayload(data.key).then(function (html) { injectHtml(html); reveal(); })
                  .catch(function () { reveal(); });
              } else {
                setTimeout(reveal, 500);
              }
            } else if (data.status === "denied") {
              msg.className = "gate-msg err"; msg.textContent = "Yêu cầu bị từ chối.";
            }
          });
        }).catch(function (err) {
          btn.disabled = false; msg.className = "gate-msg err";
          msg.textContent = err.message || "Lỗi kết nối backend.";
        });
        return;
      }

      // local / encrypted
      if (!pass) { msg.textContent = "Nhập mật khẩu."; msg.className = "gate-msg err"; return; }
      btn.disabled = true; msg.textContent = "Đang kiểm tra…";
      unlockLocalOrEncrypted(pass, remember).catch(function (err) {
        btn.disabled = false; msg.className = "gate-msg err";
        msg.textContent = (err && err.message === "BAD_PASS")
          ? "Sai mật khẩu." : "Không mở được: " + (err.message || "lỗi");
      });
    });
  }

  /* -------------------------- khởi động -------------------------- */
  function alreadyUnlocked() {
    try {
      if (sessionStorage.getItem(SESSION_KEY) === "1") return true;
      if (localStorage.getItem(REMEMBER_KEY) === "1" && MODE !== "encrypted") return true;
    } catch (e) {}
    return false;
  }

  function start() {
    // Nếu đã mở khóa trong phiên: hiện luôn.
    if (alreadyUnlocked() && MODE !== "encrypted") { reveal(); return; }
    // Chế độ mã hóa: dù "remember" cũng phải nhập lại để lấy khóa giải mã (nội dung chưa có trong DOM).
    buildUI();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
