/**
 * filecrypt.js — Ứng dụng thực tế, ghép từ các thuật toán tự cài đặt:
 *   1) Mã hóa file bằng mật khẩu:  PBKDF2-HMAC-SHA256 → khóa AES → AES-CBC/CTR → HMAC-SHA256.
 *   2) Gửi file cho người khác:     khóa ngẫu nhiên, bọc bằng RSA-OAEP (khóa công khai người nhận).
 *   3) Lưu / nạp khóa RSA dưới dạng file JSON.
 *
 * Định dạng file .enc (số nguyên ghi big-endian):
 *   "N01ENC" (6) | phiên bản (1) | loại: 1 = mật khẩu, 2 = RSA (1) | chế độ: 1 = CBC, 2 = CTR (1) | độ dài khóa AES (1)
 *   loại 1: số vòng PBKDF2 (4) | salt (16)        loại 2: độ dài khóa bọc (2) | khóa bọc bằng RSA-OAEP
 *   IV (16) | bản mã | thẻ HMAC-SHA256 (32)
 * Phần được mã hóa = độ dài tên file (2) | tên file (UTF-8) | nội dung file — nên tên file cũng được giấu.
 * Mã hóa rồi mới tính HMAC (encrypt-then-MAC): sai mật khẩu hay file bị sửa đều bị phát hiện trước khi giải mã.
 */
(function (root) {
  'use strict';
  const req = (n) => (typeof require !== 'undefined' ? require(n) : null);
  const U = root.CryptoUtils || req('./utils.js');
  const Modes = root.Modes || req('./modes.js');
  const KDF = root.KDF || req('./kdf.js');
  const RSA = root.RSA || req('./rsa.js');
  const OAEP = root.OAEP || req('./oaep.js');

  const MAGIC = U.utf8Encode('N01ENC');
  const VERSION = 1;
  const MODES = { CBC: 1, CTR: 2 };
  const MODE_NAME = { 1: 'CBC', 2: 'CTR' };
  const DEFAULT_ITERATIONS = 100000;

  function u16(n) { return Uint8Array.of(n >>> 8, n & 0xff); }
  function u32(n) { return Uint8Array.of(n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff); }
  function readU16(b, o) { return (b[o] << 8) | b[o + 1]; }
  function readU32(b, o) { return ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3]; }

  /** Từ 32 byte bí mật chung, tách ra khóa AES và khóa HMAC độc lập nhau. */
  function deriveKeys(master, keyLen) {
    const mac = KDF.hmacFactory(master);
    return {
      encKey: mac(U.utf8Encode('N01|enc')).subarray(0, keyLen),
      macKey: mac(U.utf8Encode('N01|mac')),
    };
  }

  function packPayload(name, data) {
    const nameBytes = U.utf8Encode(name || 'file');
    if (nameBytes.length > 65535) throw new Error('Tên file quá dài.');
    return U.concatBytes(u16(nameBytes.length), nameBytes, data);
  }

  function unpackPayload(p) {
    const n = readU16(p, 0);
    return { name: U.utf8Decode(p.subarray(2, 2 + n)), data: p.slice(2 + n) };
  }

  async function encryptPayload(header, payload, keys, mode, onProgress) {
    const iv = U.randomBytes(16);
    const ct = mode === MODES.CTR
      ? await Modes.ctrCryptAsync(payload, keys.encKey, iv, onProgress)
      : await Modes.cbcEncryptAsync(payload, keys.encKey, iv, onProgress);
    const tag = KDF.hmacFactory(keys.macKey)(header, iv, ct);
    return { file: U.concatBytes(header, iv, ct, tag), iv, tag };
  }

  /** Đọc phần đầu file .enc, chưa cần khóa (để giao diện hiển thị thông tin). */
  function parseHeader(file) {
    if (file.length < 6 + 4 + 16 + 32 || !U.bytesEqual(file.subarray(0, 6), MAGIC)) {
      throw new Error('Đây không phải file .enc do ứng dụng này tạo ra.');
    }
    const version = file[6], type = file[7], mode = file[8], keyLen = file[9];
    if (version !== VERSION) throw new Error(`Phiên bản file ${version} không được hỗ trợ.`);
    if (!MODE_NAME[mode] || ![16, 24, 32].includes(keyLen)) throw new Error('Phần đầu file không hợp lệ.');
    let o = 10;
    const info = { type: type === 1 ? 'password' : 'rsa', mode: MODE_NAME[mode], modeCode: mode, keyLen };
    if (type === 1) {
      info.iterations = readU32(file, o); o += 4;
      info.salt = file.slice(o, o + 16); o += 16;
    } else if (type === 2) {
      const wl = readU16(file, o); o += 2;
      info.wrappedKey = file.slice(o, o + wl); o += wl;
    } else {
      throw new Error('Loại file không hợp lệ.');
    }
    info.headerLen = o;
    info.iv = file.slice(o, o + 16);
    info.ciphertext = file.subarray(o + 16, file.length - 32);
    info.tag = file.slice(file.length - 32);
    if (info.ciphertext.length === 0 && mode === MODES.CBC) throw new Error('File bị cắt ngắn.');
    return info;
  }

  async function verifyAndDecrypt(file, info, master, onProgress) {
    const keys = deriveKeys(master, info.keyLen);
    const expected = KDF.hmacFactory(keys.macKey)(file.subarray(0, info.headerLen), info.iv, info.ciphertext);
    if (!KDF.constantTimeEqual(expected, info.tag)) {
      throw new Error('Thẻ HMAC không khớp: sai mật khẩu/khóa, hoặc file đã bị sửa. Không giải mã.');
    }
    const payload = info.modeCode === MODES.CTR
      ? await Modes.ctrCryptAsync(info.ciphertext, keys.encKey, info.iv, onProgress)
      : await Modes.cbcDecryptAsync(info.ciphertext, keys.encKey, info.iv, onProgress);
    return unpackPayload(payload);
  }

  // ------------------------------------------------------------- 1) Mật khẩu
  async function encryptWithPassword(data, name, password, opts = {}) {
    if (!password) throw new Error('Hãy nhập mật khẩu.');
    const mode = MODES[opts.mode || 'CBC'];
    const keyLen = opts.keyLen || 32;
    const iterations = opts.iterations || DEFAULT_ITERATIONS;
    const salt = U.randomBytes(16);
    const t0 = Date.now();
    const master = KDF.pbkdf2(U.utf8Encode(password), salt, iterations, 32);
    const kdfMs = Date.now() - t0;
    const header = U.concatBytes(MAGIC, Uint8Array.of(VERSION, 1, mode, keyLen), u32(iterations), salt);
    const res = await encryptPayload(header, packPayload(name, data), deriveKeys(master, keyLen), mode, opts.onProgress);
    return Object.assign(res, { salt, iterations, kdfMs, headerLen: header.length });
  }

  async function decryptWithPassword(file, password, opts = {}) {
    const info = parseHeader(file);
    if (info.type !== 'password') throw new Error('File này được mã hóa bằng khóa RSA, hãy dùng chức năng "Gửi file bằng khóa công khai".');
    const t0 = Date.now();
    const master = KDF.pbkdf2(U.utf8Encode(password), info.salt, info.iterations, 32);
    info.kdfMs = Date.now() - t0;
    return Object.assign(await verifyAndDecrypt(file, info, master, opts.onProgress), { info });
  }

  // ------------------------------------------------------------- 2) Khóa công khai RSA
  async function encryptForRecipient(data, name, publicKey, opts = {}) {
    if (OAEP.maxMessageBytes(publicKey) < 32) throw new Error('Khóa RSA quá ngắn để bọc khóa 32 byte, hãy dùng khóa từ 1024 bit.');
    const mode = MODES[opts.mode || 'CBC'];
    const keyLen = opts.keyLen || 32;
    const master = U.randomBytes(32);                         // khóa phiên ngẫu nhiên
    const wrapped = await OAEP.encrypt(master, publicKey);    // chỉ người giữ khóa riêng mở được
    const header = U.concatBytes(MAGIC, Uint8Array.of(VERSION, 2, mode, keyLen), u16(wrapped.length), wrapped);
    const res = await encryptPayload(header, packPayload(name, data), deriveKeys(master, keyLen), mode, opts.onProgress);
    return Object.assign(res, { wrapped, headerLen: header.length });
  }

  async function decryptWithPrivateKey(file, privateKey, opts = {}) {
    const info = parseHeader(file);
    if (info.type !== 'rsa') throw new Error('File này được mã hóa bằng mật khẩu, hãy dùng chức năng "Mã hóa file bằng mật khẩu".');
    if (!privateKey.d) throw new Error('Cần khóa riêng để giải mã.');
    let master;
    try {
      master = await OAEP.decrypt(info.wrappedKey, privateKey);
    } catch (e) {
      throw new Error('Không mở được khóa phiên: file không gửi cho khóa riêng này, hoặc đã bị sửa.');
    }
    return Object.assign(await verifyAndDecrypt(file, info, master, opts.onProgress), { info });
  }

  // ------------------------------------------------------------- 3) Lưu / nạp khóa RSA
  const hex = (n) => n.toString(16);

  function exportPublicKey(key) {
    return JSON.stringify({ format: 'N01-RSA-PUBLIC', bits: key.bits, n: hex(key.n), e: hex(key.e) }, null, 2);
  }

  function exportPrivateKey(key) {
    return JSON.stringify({
      format: 'N01-RSA-PRIVATE', bits: key.bits, n: hex(key.n), e: hex(key.e), d: hex(key.d),
      p: hex(key.p), q: hex(key.q), dP: hex(key.dP), dQ: hex(key.dQ), qInv: hex(key.qInv),
    }, null, 2);
  }

  function importKey(text) {
    let o;
    try { o = JSON.parse(text); } catch (e) { throw new Error('File khóa không phải JSON hợp lệ.'); }
    const big = (h, name) => {
      if (typeof h !== 'string' || !/^[0-9a-f]+$/i.test(h)) throw new Error(`Trường ${name} trong file khóa không hợp lệ.`);
      return BigInt('0x' + h);
    };
    if (o.format === 'N01-RSA-PUBLIC') {
      const n = big(o.n, 'n'), e = big(o.e, 'e');
      return { n, e, bits: U.bitLength(n), isPrivate: false };
    }
    if (o.format === 'N01-RSA-PRIVATE') {
      const k = {};
      for (const f of ['n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv']) k[f] = big(o[f], f);
      if (k.p * k.q !== k.n) throw new Error('File khóa hỏng: p·q ≠ n.');
      const test = 0x4e3031n % k.n;                                          // thử mã hóa – giải mã một số
      if (RSA.decryptCRT(RSA.encryptInt(test, k), k) !== test) throw new Error('File khóa hỏng: e và d không khớp nhau.');
      k.phi = (k.p - 1n) * (k.q - 1n);
      k.bits = U.bitLength(k.n);
      k.isPrivate = true;
      return k;
    }
    throw new Error('Không nhận ra định dạng file khóa.');
  }

  function fingerprint(key) {
    // dấu vân tay: 8 byte đầu SHA-256 của n, giúp hai người đối chiếu đúng khóa
    const h = (root.SHA256 || req('./sha256.js')).hash(U.bigIntToBytes(key.n));
    return U.bytesToHex(h.subarray(0, 8)).match(/.{4}/g).join(':');
  }

  const api = {
    encryptWithPassword, decryptWithPassword, encryptForRecipient, decryptWithPrivateKey,
    parseHeader, exportPublicKey, exportPrivateKey, importKey, fingerprint, DEFAULT_ITERATIONS,
  };
  root.FileCrypt = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
