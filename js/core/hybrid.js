/**
 * hybrid.js — Mã hóa lai: AES-256-CBC mã hóa dữ liệu bằng khóa phiên ngẫu nhiên,
 * RSA-OAEP bọc khóa phiên bằng khóa công khai của người nhận (cách làm của S/MIME, PGP).
 */
(function (root) {
  'use strict';
  const U = root.CryptoUtils || (typeof require !== 'undefined' && require('./utils.js'));
  const Modes = root.Modes || (typeof require !== 'undefined' && require('./modes.js'));
  const OAEP = root.OAEP || (typeof require !== 'undefined' && require('./oaep.js'));

  async function encrypt(text, rsaKey) {
    const sessionKey = U.randomBytes(32);                  // khóa phiên AES-256
    const iv = U.randomBytes(16);
    const data = Modes.cbcEncrypt(U.utf8Encode(text), sessionKey, iv);
    const wrappedKey = await OAEP.encrypt(sessionKey, rsaKey);
    return {
      packet: {
        alg: 'RSA-OAEP-SHA256 + AES-256-CBC',
        wrappedKey: U.bytesToBase64(wrappedKey),
        iv: U.bytesToHex(iv),
        ciphertext: U.bytesToBase64(data),
      },
      sessionKey,
    };
  }

  async function decrypt(packet, rsaKey) {
    if (!packet || !packet.wrappedKey || !packet.iv || !packet.ciphertext) {
      throw new Error('Gói tin thiếu trường wrappedKey, iv hoặc ciphertext.');
    }
    const sessionKey = await OAEP.decrypt(U.base64ToBytes(packet.wrappedKey), rsaKey);
    const plain = Modes.cbcDecrypt(U.base64ToBytes(packet.ciphertext), sessionKey, U.hexToBytes(packet.iv));
    let text;
    try { text = U.utf8Decode(plain); } catch (e) {
      throw new Error('Giải mã ra dữ liệu không phải văn bản hợp lệ: gói tin đã bị sửa. Gói lai văn bản dùng CBC nên chưa có thẻ HMAC; chức năng mã hóa file thì có.');
    }
    return { text, sessionKey };
  }

  const api = { encrypt, decrypt };
  root.Hybrid = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
