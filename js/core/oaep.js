/**
 * oaep.js — RSAES-OAEP (RFC 8017 §7.1) với SHA-256 và MGF1-SHA-256, nhãn rỗng.
 * Toàn bộ tự cài đặt: MGF1, ghép/tách khối, kiểm tra và cả hàm băm SHA-256 (sha256.js).
 * Cấu hình này trùng với RSA-OAEP + SHA-256 của Web Crypto nên giải mã chéo được.
 */
(function (root) {
  'use strict';
  const U = root.CryptoUtils || (typeof require !== 'undefined' && require('./utils.js'));
  const RSA = root.RSA || (typeof require !== 'undefined' && require('./rsa.js'));
  const SHA = root.SHA256 || (typeof require !== 'undefined' && require('./sha256.js'));
  const H_LEN = 32;

  async function sha256(bytes) {
    return SHA.hash(bytes);            // SHA-256 tự viết, không gọi Web Crypto
  }

  /** MGF1 (RFC 8017 phụ lục B.2.1): nối Hash(seed || counter) cho đủ maskLen byte. */
  async function mgf1(seed, maskLen) {
    const out = new Uint8Array(maskLen);
    let filled = 0;
    for (let counter = 0; filled < maskLen; counter++) {
      const c = Uint8Array.of(counter >>> 24, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff);
      const h = await sha256(U.concatBytes(seed, c));
      const n = Math.min(h.length, maskLen - filled);
      out.set(h.subarray(0, n), filled);
      filled += n;
    }
    return out;
  }

  function keyBytes(key) { return Math.ceil(U.bitLength(key.n) / 8); }
  function maxMessageBytes(key) { return keyBytes(key) - 2 * H_LEN - 2; }

  /** Mã hóa một khối: trả về bản mã k byte. `seedOverride` chỉ dùng cho kiểm thử. */
  async function encrypt(message, key, seedOverride) {
    const k = keyBytes(key);
    if (maxMessageBytes(key) < 1) throw new Error(`Khóa RSA ${U.bitLength(key.n)} bit quá ngắn cho OAEP-SHA256 (cần từ 1024 bit). Khóa 512 bit chỉ dùng để xem tốc độ sinh khóa.`);
    if (message.length > maxMessageBytes(key)) throw new Error(`Thông điệp quá dài cho một khối OAEP (tối đa ${maxMessageBytes(key)} byte).`);
    const lHash = await sha256(new Uint8Array(0));
    const ps = new Uint8Array(k - message.length - 2 * H_LEN - 2);
    const db = U.concatBytes(lHash, ps, Uint8Array.of(1), message);   // DB = lHash || PS || 0x01 || M
    const seed = seedOverride || U.randomBytes(H_LEN);
    const maskedDB = U.xorBytes(db, await mgf1(seed, k - H_LEN - 1));
    const maskedSeed = U.xorBytes(seed, await mgf1(maskedDB, H_LEN));
    const em = U.concatBytes(Uint8Array.of(0), maskedSeed, maskedDB);  // EM = 0x00 || maskedSeed || maskedDB
    const c = RSA.encryptInt(U.bytesToBigInt(em), key);
    return U.bigIntToBytes(c, k);
  }

  async function decrypt(cipher, key, useCRT = true) {
    const k = keyBytes(key);
    const fail = () => new Error('Giải mã OAEP thất bại – sai khóa hoặc bản mã đã bị sửa.');
    if (cipher.length !== k || k < 2 * H_LEN + 2) throw fail();
    const c = U.bytesToBigInt(cipher);
    if (c >= key.n) throw fail();
    const m = useCRT ? RSA.decryptCRT(c, key) : RSA.decryptInt(c, key);
    const em = U.bigIntToBytes(m, k);
    const maskedSeed = em.subarray(1, 1 + H_LEN);
    const maskedDB = em.subarray(1 + H_LEN);
    const seed = U.xorBytes(maskedSeed, await mgf1(maskedDB, H_LEN));
    const db = U.xorBytes(maskedDB, await mgf1(seed, k - H_LEN - 1));
    const lHash = await sha256(new Uint8Array(0));
    // Kiểm tra gộp, không thoát sớm, để không lộ thông tin qua thông báo lỗi khác nhau
    let bad = em[0] !== 0 ? 1 : 0;
    if (!U.bytesEqual(db.subarray(0, H_LEN), lHash)) bad = 1;
    let idx = -1;
    for (let i = H_LEN; i < db.length; i++) {
      if (idx < 0 && db[i] === 1) idx = i;
      else if (idx < 0 && db[i] !== 0) bad = 1;
    }
    if (bad || idx < 0) throw fail();
    return db.slice(idx + 1);
  }

  /** Văn bản dài: chia thành nhiều khối OAEP, nối các bản mã (mỗi khối k byte). */
  async function encryptText(text, key) {
    const data = U.utf8Encode(text);
    const max = maxMessageBytes(key);
    const parts = [];
    for (let i = 0; i < data.length || i === 0; i += max) {
      parts.push(await encrypt(data.subarray(i, i + max), key));
      if (data.length === 0) break;
    }
    return { cipher: U.concatBytes(...parts), blocks: parts.length, blockBytes: keyBytes(key), maxPerBlock: max };
  }

  async function decryptText(cipher, key) {
    const k = keyBytes(key);
    if (cipher.length === 0 || cipher.length % k !== 0) throw new Error(`Bản mã phải là bội của ${k} byte với khóa này.`);
    const parts = [];
    for (let i = 0; i < cipher.length; i += k) parts.push(await decrypt(cipher.subarray(i, i + k), key));
    return U.utf8Decode(U.concatBytes(...parts));
  }

  const api = { H_LEN, sha256, mgf1, encrypt, decrypt, encryptText, decryptText, maxMessageBytes, keyBytes };
  root.OAEP = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
