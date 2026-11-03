/**
 * utils.js — Tiện ích dùng chung cho RSA và AES.
 * Chuyển đổi giữa văn bản (UTF-8), byte, hex, Base64 và BigInt.
 * Nguồn ngẫu nhiên duy nhất: crypto.getRandomValues (CSPRNG của trình duyệt).
 */
(function (root) {
  'use strict';

  function utf8Encode(text) {
    return new TextEncoder().encode(text);
  }

  function utf8Decode(bytes) {
    // fatal: true -> báo lỗi nếu byte không phải UTF-8 hợp lệ (ví dụ giải mã sai khóa)
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }

  function bytesToHex(bytes) {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
  }

  function hexToBytes(hex) {
    const clean = String(hex).replace(/\s+/g, '').toLowerCase();
    if (clean.length % 2 !== 0 || /[^0-9a-f]/.test(clean)) {
      throw new Error('Chuỗi hex không hợp lệ: chỉ dùng 0-9, a-f và số ký tự phải chẵn.');
    }
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    let bin;
    try {
      bin = atob(String(b64).replace(/\s+/g, ''));
    } catch (e) {
      throw new Error('Chuỗi Base64 không hợp lệ.');
    }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function base64UrlFromBytes(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function randomBytes(n) {
    const out = new Uint8Array(n);
    // getRandomValues giới hạn 65536 byte mỗi lần gọi
    for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
    return out;
  }

  function xorBytes(a, b) {
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  function concatBytes(...parts) {
    const total = parts.reduce((s, p) => s + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function countDiffBits(a, b) {
    let count = 0;
    for (let i = 0; i < a.length; i++) {
      let x = a[i] ^ b[i];
      while (x) { count += x & 1; x >>= 1; }
    }
    return count;
  }

  // ---- BigInt <-> byte (big-endian, đúng I2OSP/OS2IP của RFC 8017) ----
  function bytesToBigInt(bytes) {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    return n;
  }

  function bigIntToBytes(n, length) {
    if (n < 0n) throw new Error('Không chuyển được số âm sang byte.');
    const hex = n.toString(16);
    const minLen = Math.ceil(hex.length / 2);
    const len = length === undefined ? Math.max(minLen, 1) : length;
    if (minLen > len) throw new Error('Số quá lớn so với độ dài byte yêu cầu.');
    return hexToBytes(hex.padStart(len * 2, '0'));
  }

  function bitLength(n) {
    return n === 0n ? 0 : n.toString(2).length;
  }

  /** Số ngẫu nhiên đúng `bits` bit (bit cao nhất luôn = 1). */
  function randomBigIntBits(bits) {
    const bytes = randomBytes(Math.ceil(bits / 8));
    const extra = bytes.length * 8 - bits;
    bytes[0] &= 0xff >> extra;
    bytes[0] |= 0x80 >> extra;
    return bytesToBigInt(bytes);
  }

  /** Số ngẫu nhiên đều trong [min, max] (lấy mẫu loại bỏ để không lệch). */
  function randomBigIntRange(min, max) {
    const range = max - min + 1n;
    const bits = bitLength(range);
    const bytes = Math.ceil(bits / 8);
    const mask = (1n << BigInt(bits)) - 1n;
    for (;;) {
      const r = bytesToBigInt(randomBytes(bytes)) & mask;
      if (r < range) return min + r;
    }
  }

  function formatBigInt(n, max = 64) {
    const s = n.toString();
    return s.length <= max ? s : `${s.slice(0, max / 2)}…${s.slice(-max / 2)} (${s.length} chữ số)`;
  }

  const api = {
    utf8Encode, utf8Decode, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes, base64UrlFromBytes,
    randomBytes, xorBytes, concatBytes, bytesEqual, countDiffBits,
    bytesToBigInt, bigIntToBytes, bitLength, randomBigIntBits, randomBigIntRange, formatBigInt,
  };
  root.CryptoUtils = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
