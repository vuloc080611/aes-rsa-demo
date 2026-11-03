/**
 * modes.js — Chế độ hoạt động của AES (NIST SP 800-38A) và padding PKCS#7 (RFC 5652 §6.3).
 *   ECB: chỉ dùng để minh họa điểm yếu, không dùng cho dữ liệu thật.
 *   CBC: Ci = E(Pi xor Ci-1), C0 dùng IV ngẫu nhiên; cần padding.
 *   CTR: Ci = Pi xor E(bộ đếm), bộ đếm 128 bit tăng dần; không cần padding.
 */
(function (root) {
  'use strict';
  const AES = root.AES || (typeof require !== 'undefined' && require('./aes.js'));
  const U = root.CryptoUtils || (typeof require !== 'undefined' && require('./utils.js'));

  function pkcs7Pad(data, block = 16) {
    const k = block - (data.length % block);       // luôn thêm 1..16 byte
    const out = new Uint8Array(data.length + k);
    out.set(data);
    out.fill(k, data.length);
    return out;
  }

  function pkcs7Unpad(data, block = 16) {
    if (data.length === 0 || data.length % block !== 0) throw new Error('Độ dài bản giải mã không phải bội của 16 byte.');
    const k = data[data.length - 1];
    if (k < 1 || k > block) throw new Error('Padding PKCS#7 không hợp lệ – thường do sai khóa hoặc bản mã bị sửa.');
    for (let i = data.length - k; i < data.length; i++) {
      if (data[i] !== k) throw new Error('Padding PKCS#7 không hợp lệ – thường do sai khóa hoặc bản mã bị sửa.');
    }
    return data.subarray(0, data.length - k);
  }

  function checkLen(data) {
    if (data.length % 16 !== 0) throw new Error('Dữ liệu ECB/CBC phải là bội số của 16 byte.');
  }

  function ecbEncrypt(data, key, { pad = true } = {}) {
    const { roundKeys } = AES.expandKey(key);
    const input = pad ? pkcs7Pad(data) : data;
    checkLen(input);
    const out = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i += 16) out.set(AES.encryptBlock(input.subarray(i, i + 16), roundKeys), i);
    return out;
  }

  function ecbDecrypt(data, key, { pad = true } = {}) {
    checkLen(data);
    const { roundKeys } = AES.expandKey(key);
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 16) out.set(AES.decryptBlock(data.subarray(i, i + 16), roundKeys), i);
    return pad ? pkcs7Unpad(out) : out;
  }

  function cbcEncrypt(data, key, iv, { pad = true } = {}) {
    if (iv.length !== 16) throw new Error('IV phải dài 16 byte.');
    const { roundKeys } = AES.expandKey(key);
    const input = pad ? pkcs7Pad(data) : data;
    checkLen(input);
    const out = new Uint8Array(input.length);
    let prev = iv;
    for (let i = 0; i < input.length; i += 16) {
      const x = U.xorBytes(input.subarray(i, i + 16), prev);   // Pi xor Ci-1
      prev = AES.encryptBlock(x, roundKeys);
      out.set(prev, i);
    }
    return out;
  }

  function cbcDecrypt(data, key, iv, { pad = true } = {}) {
    if (iv.length !== 16) throw new Error('IV phải dài 16 byte.');
    checkLen(data);
    const { roundKeys } = AES.expandKey(key);
    const out = new Uint8Array(data.length);
    let prev = iv;
    for (let i = 0; i < data.length; i += 16) {
      const c = data.subarray(i, i + 16);
      out.set(U.xorBytes(AES.decryptBlock(c, roundKeys), prev), i);   // Pi = D(Ci) xor Ci-1
      prev = c;
    }
    return pad ? pkcs7Unpad(out) : out;
  }

  function incrementCounter(counter) {
    const c = Uint8Array.from(counter);
    for (let i = 15; i >= 0; i--) {             // cộng 1 theo big-endian trên toàn bộ 128 bit
      c[i] = (c[i] + 1) & 0xff;
      if (c[i] !== 0) break;
    }
    return c;
  }

  /** CTR: mã hóa và giải mã là cùng một phép toán. */
  function ctrCrypt(data, key, initialCounter) {
    if (initialCounter.length !== 16) throw new Error('Bộ đếm khởi tạo phải dài 16 byte.');
    const { roundKeys } = AES.expandKey(key);
    const out = new Uint8Array(data.length);
    let counter = Uint8Array.from(initialCounter);
    for (let i = 0; i < data.length; i += 16) {
      const ks = AES.encryptBlock(counter, roundKeys);       // dòng khóa
      const n = Math.min(16, data.length - i);
      for (let j = 0; j < n; j++) out[i + j] = data[i + j] ^ ks[j];
      counter = incrementCounter(counter);
    }
    return out;
  }


  // ---------- Bản bất đồng bộ cho file lớn: xử lý từng đoạn, nhường giao diện và báo tiến độ ----------
  const CHUNK_BLOCKS = 4096;                   // 64 KB mỗi lần
  const tick = () => new Promise((r) => setTimeout(r, 0));

  async function cbcEncryptAsync(data, key, iv, onProgress) {
    const { roundKeys } = AES.expandKey(key);
    const input = pkcs7Pad(data);
    const out = new Uint8Array(input.length);
    let prev = iv;
    for (let i = 0; i < input.length; i += 16) {
      prev = AES.encryptBlock(U.xorBytes(input.subarray(i, i + 16), prev), roundKeys);
      out.set(prev, i);
      if ((i / 16) % CHUNK_BLOCKS === CHUNK_BLOCKS - 1) { if (onProgress) onProgress(i / input.length); await tick(); }
    }
    if (onProgress) onProgress(1);
    return out;
  }

  async function cbcDecryptAsync(data, key, iv, onProgress) {
    checkLen(data);
    const { roundKeys } = AES.expandKey(key);
    const out = new Uint8Array(data.length);
    let prev = iv;
    for (let i = 0; i < data.length; i += 16) {
      const c = data.subarray(i, i + 16);
      out.set(U.xorBytes(AES.decryptBlock(c, roundKeys), prev), i);
      prev = c;
      if ((i / 16) % CHUNK_BLOCKS === CHUNK_BLOCKS - 1) { if (onProgress) onProgress(i / data.length); await tick(); }
    }
    if (onProgress) onProgress(1);
    return pkcs7Unpad(out);
  }

  async function ctrCryptAsync(data, key, initialCounter, onProgress) {
    const { roundKeys } = AES.expandKey(key);
    const out = new Uint8Array(data.length);
    let counter = Uint8Array.from(initialCounter);
    for (let i = 0; i < data.length; i += 16) {
      const ks = AES.encryptBlock(counter, roundKeys);
      const n = Math.min(16, data.length - i);
      for (let j = 0; j < n; j++) out[i + j] = data[i + j] ^ ks[j];
      counter = incrementCounter(counter);
      if ((i / 16) % CHUNK_BLOCKS === CHUNK_BLOCKS - 1) { if (onProgress) onProgress(i / data.length); await tick(); }
    }
    if (onProgress) onProgress(1);
    return out;
  }

  const api = { cbcEncryptAsync, cbcDecryptAsync, ctrCryptAsync, pkcs7Pad, pkcs7Unpad, ecbEncrypt, ecbDecrypt, cbcEncrypt, cbcDecrypt, ctrCrypt, incrementCounter };
  root.Modes = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
