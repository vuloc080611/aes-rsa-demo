/**
 * webcrypto.js — Thư viện mật mã chuẩn của trình duyệt (W3C Web Cryptography API),
 * chỉ dùng để ĐỐI CHỨNG với phần code tay, không dùng trong lõi thuật toán.
 * Web Crypto không hỗ trợ AES-ECB và RSA thuần (không padding) vì không an toàn.
 */
(function (root) {
  'use strict';
  const U = root.CryptoUtils || (typeof require !== 'undefined' && require('../core/utils.js'));
  const subtle = () => {
    if (!globalThis.crypto || !crypto.subtle) throw new Error('Trình duyệt không cho dùng Web Crypto ở trang này (cần https hoặc localhost).');
    return crypto.subtle;
  };

  async function aesKey(raw, name) {
    return subtle().importKey('raw', raw, { name }, false, ['encrypt', 'decrypt']);
  }

  async function aesCbcEncrypt(data, key, iv) {
    // Web Crypto tự thêm padding PKCS#7 – giống phần code tay
    return new Uint8Array(await subtle().encrypt({ name: 'AES-CBC', iv }, await aesKey(key, 'AES-CBC'), data));
  }

  async function aesCbcDecrypt(data, key, iv) {
    return new Uint8Array(await subtle().decrypt({ name: 'AES-CBC', iv }, await aesKey(key, 'AES-CBC'), data));
  }

  async function aesCtr(data, key, counter) {
    // length = 128: tăng bộ đếm trên toàn bộ 128 bit – giống phần code tay
    return new Uint8Array(await subtle().encrypt({ name: 'AES-CTR', counter, length: 128 }, await aesKey(key, 'AES-CTR'), data));
  }

  function jwk(key, withPrivate) {
    const b = (n) => U.base64UrlFromBytes(U.bigIntToBytes(n));
    const out = { kty: 'RSA', alg: 'RSA-OAEP-256', ext: true, n: b(key.n), e: b(key.e) };
    if (withPrivate) Object.assign(out, { d: b(key.d), p: b(key.p), q: b(key.q), dp: b(key.dP), dq: b(key.dQ), qi: b(key.qInv) });
    return out;
  }

  async function rsaOaepEncrypt(data, key) {
    const pub = await subtle().importKey('jwk', jwk(key, false), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    return new Uint8Array(await subtle().encrypt({ name: 'RSA-OAEP' }, pub, data));
  }

  async function rsaOaepDecrypt(data, key) {
    const priv = await subtle().importKey('jwk', jwk(key, true), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    return new Uint8Array(await subtle().decrypt({ name: 'RSA-OAEP' }, priv, data));
  }

  /** Đo thời gian trung bình (ms) của một hàm bất đồng bộ hoặc đồng bộ. */
  async function timeIt(fn, iterations) {
    await fn();                                             // chạy nóng 1 lần
    const t0 = performance.now();
    for (let i = 0; i < iterations; i++) await fn();
    return (performance.now() - t0) / iterations;
  }

  const api = { aesCbcEncrypt, aesCbcDecrypt, aesCtr, rsaOaepEncrypt, rsaOaepDecrypt, jwk, timeIt };
  root.WebCryptoLib = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
