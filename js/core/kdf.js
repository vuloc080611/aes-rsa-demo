/**
 * kdf.js — HMAC-SHA256 (RFC 2104) và PBKDF2-HMAC-SHA256 (RFC 8018) tự cài đặt.
 *   HMAC: xác thực dữ liệu (phát hiện file bị sửa hoặc sai mật khẩu).
 *   PBKDF2: biến mật khẩu người dùng thành khóa AES, lặp nhiều lần để làm chậm dò mật khẩu.
 */
(function (root) {
  'use strict';
  const SHA256 = root.SHA256 || (typeof require !== 'undefined' && require('./sha256.js'));
  const U = root.CryptoUtils || (typeof require !== 'undefined' && require('./utils.js'));

  /** Tạo bộ HMAC với khóa cố định; tính sẵn trạng thái sau (K ⊕ ipad) và (K ⊕ opad). */
  function hmacFactory(key) {
    let k = key.length > 64 ? SHA256.hash(key) : key;
    const block = new Uint8Array(64);
    block.set(k);
    const ipad = block.map((b) => b ^ 0x36);
    const opad = block.map((b) => b ^ 0x5c);
    const inner = new SHA256.Hasher().update(ipad);
    const outer = new SHA256.Hasher().update(opad);
    return function mac(...parts) {
      const i = inner.clone();
      for (const p of parts) i.update(p);
      return outer.clone().update(i.digest()).digest();   // H((K⊕opad) || H((K⊕ipad) || m))
    };
  }

  function hmac(key, data) {
    return hmacFactory(key)(data);
  }

  /** PBKDF2: T_i = U_1 ⊕ U_2 ⊕ … ⊕ U_c, với U_1 = HMAC(P, S || i), U_j = HMAC(P, U_{j-1}). */
  function pbkdf2(password, salt, iterations, dkLen) {
    if (iterations < 1) throw new Error('Số vòng lặp PBKDF2 phải ≥ 1.');
    const prf = hmacFactory(password);
    const out = new Uint8Array(dkLen);
    for (let block = 1, pos = 0; pos < dkLen; block++) {
      const idx = Uint8Array.of(block >>> 24, (block >>> 16) & 0xff, (block >>> 8) & 0xff, block & 0xff);
      let u = prf(salt, idx);
      const t = Uint8Array.from(u);
      for (let c = 1; c < iterations; c++) {
        u = prf(u);
        for (let j = 0; j < 32; j++) t[j] ^= u[j];
      }
      const n = Math.min(32, dkLen - pos);
      out.set(t.subarray(0, n), pos);
      pos += n;
    }
    return out;
  }

  /** So sánh hai mảng byte trong thời gian hằng (không thoát sớm). */
  function constantTimeEqual(a, b) {
    return U.bytesEqual(a, b);
  }

  const api = { hmac, hmacFactory, pbkdf2, constantTimeEqual };
  root.KDF = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
