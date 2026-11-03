/* global QUnit, CryptoUtils, AES, Modes, RSA, OAEP, Hybrid, WebCryptoLib, SHA256, KDF, FileCrypt */
/**
 * tests.js — Kiểm thử bằng dữ liệu chuẩn:
 *   NIST FIPS 197-upd1 Phụ lục A.1, B, C.1–C.3 (4 vector khối + mở rộng khóa)
 *   NIST SP 800-38A Phụ lục F: ECB, CBC, CTR × khóa 128/192/256 × 4 khối = 36 vector
 *   RSA: ví dụ số, toàn miền thông điệp, CRT, Miller–Rabin, OAEP giải mã chéo với Web Crypto.
 *   SHA-256 (FIPS 180-4), HMAC (RFC 4231), PBKDF2 (RFC 7914 §11), định dạng file .enc.
 */
(function () {
  'use strict';
  const U = CryptoUtils;
  const hex = U.hexToBytes;
  const toHex = U.bytesToHex;

  // ======================================================================= AES
  QUnit.module('AES – số học GF(2⁸) và S-box');

  QUnit.test('Phép nhân GF(2⁸) theo ví dụ FIPS 197', (assert) => {
    assert.strictEqual(AES.gfMul(0x57, 0x83), 0xc1, '{57} • {83} = {C1}');
    assert.strictEqual(AES.gfMul(0x57, 0x13), 0xfe, '{57} • {13} = {FE}');
    assert.strictEqual(AES.xtime(0x57), 0xae, 'xtime({57}) = {AE}');
    assert.strictEqual(AES.gfMul(0x95, AES.gfInverse(0x95)), 1, '{95} • {95}⁻¹ = 1');
  });

  QUnit.test('S-box tự tính khớp giá trị chuẩn', (assert) => {
    assert.strictEqual(AES.SBOX[0x00], 0x63, 'S({00}) = {63}');
    assert.strictEqual(AES.SBOX[0x53], 0xed, 'S({53}) = {ED}');
    assert.strictEqual(AES.SBOX[0x95], 0x2a, 'S({95}) = {2A} (ví dụ bài giảng)');
    assert.strictEqual(new Set(AES.SBOX).size, 256, 'S-box là hoán vị của 256 giá trị');
    let ok = true;
    for (let x = 0; x < 256; x++) if (AES.INV_SBOX[AES.SBOX[x]] !== x) ok = false;
    assert.ok(ok, 'InvSubBytes(SubBytes(x)) = x với mọi x');
  });

  QUnit.module('AES – NIST FIPS 197-upd1');
  const KEY128 = '2b7e151628aed2a6abf7158809cf4f3c';

  QUnit.test('Phụ lục A.1: mở rộng khóa AES-128', (assert) => {
    const { words, roundKeys, Nr } = AES.expandKey(hex(KEY128));
    assert.strictEqual(Nr, 10);
    assert.strictEqual(words.length, 44, '44 word');
    assert.strictEqual(toHex(words[4]), 'a0fafe17', 'w4 = a0fafe17');
    assert.strictEqual(toHex(roundKeys[1]), 'a0fafe1788542cb123a339392a6c7605', 'K1');
    assert.strictEqual(toHex(roundKeys[10]), 'd014f9a8c9ee2589e13f0cc8b6630ca6', 'K10');
  });

  QUnit.test('Phụ lục B: mã hóa và trạng thái trung gian', (assert) => {
    const rk = AES.expandKey(hex(KEY128)).roundKeys;
    const trace = [];
    const ct = AES.encryptBlock(hex('3243f6a8885a308d313198a2e0370734'), rk, trace);
    assert.strictEqual(toHex(ct), '3925841d02dc09fbdc118597196a0b32', 'bản mã');
    const state = (r, step) => toHex(trace.find((t) => t.round === r && t.step === step).state);
    assert.strictEqual(state(0, 'AddRoundKey'), '193de3bea0f4e22b9ac68d2ae9f84808', 'đầu vòng 1');
    assert.strictEqual(state(1, 'SubBytes'), 'd42711aee0bf98f1b8b45de51e415230', 'vòng 1 SubBytes');
    assert.strictEqual(state(1, 'ShiftRows'), 'd4bf5d30e0b452aeb84111f11e2798e5', 'vòng 1 ShiftRows');
    assert.strictEqual(state(1, 'MixColumns'), '046681e5e0cb199a48f8d37a2806264c', 'vòng 1 MixColumns');
    assert.notOk(trace.some((t) => t.round === 10 && t.step === 'MixColumns'), 'vòng 10 không có MixColumns');
    assert.strictEqual(toHex(AES.decryptBlock(ct, rk)), '3243f6a8885a308d313198a2e0370734', 'giải mã');
  });

  const C_VECTORS = [
    ['C.1 AES-128', '000102030405060708090a0b0c0d0e0f', '69c4e0d86a7b0430d8cdb78070b4c55a'],
    ['C.2 AES-192', '000102030405060708090a0b0c0d0e0f1011121314151617', 'dda97ca4864cdfe06eaf70a0ec0d7191'],
    ['C.3 AES-256', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '8ea2b7ca516745bfeafc49904b496089'],
  ];
  QUnit.test('Phụ lục C: AES-128/192/256', (assert) => {
    const pt = '00112233445566778899aabbccddeeff';
    for (const [name, key, ct] of C_VECTORS) {
      const rk = AES.expandKey(hex(key)).roundKeys;
      assert.strictEqual(toHex(AES.encryptBlock(hex(pt), rk)), ct, `${name} mã hóa`);
      assert.strictEqual(toHex(AES.decryptBlock(hex(ct), rk)), pt, `${name} giải mã`);
    }
  });

  QUnit.test('Từ chối khóa và khối sai độ dài', (assert) => {
    assert.throws(() => AES.expandKey(new Uint8Array(15)), /16, 24 hoặc 32/);
    assert.throws(() => AES.encryptBlock(new Uint8Array(15), AES.expandKey(new Uint8Array(16)).roundKeys), /16 byte/);
  });

  // ======================================================== SP 800-38A
  QUnit.module('Chế độ hoạt động – NIST SP 800-38A Phụ lục F');
  const PLAIN = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710';
  const IV = '000102030405060708090a0b0c0d0e0f';
  const CTR0 = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
  const SP = {
    128: { key: KEY128,
      ECB: '3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4',
      CBC: '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7',
      CTR: '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee' },
    192: { key: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
      ECB: 'bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e',
      CBC: '4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd',
      CTR: '1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050' },
    256: { key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
      ECB: 'f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7',
      CBC: 'f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b',
      CTR: '601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6' },
  };

  for (const bits of [128, 192, 256]) {
    const v = SP[bits];
    QUnit.test(`AES-${bits}: ECB, CBC, CTR (12 vector)`, (assert) => {
      const key = hex(v.key), pt = hex(PLAIN);
      assert.strictEqual(toHex(Modes.ecbEncrypt(pt, key, { pad: false })), v.ECB, 'ECB mã hóa');
      assert.strictEqual(toHex(Modes.ecbDecrypt(hex(v.ECB), key, { pad: false })), PLAIN, 'ECB giải mã');
      assert.strictEqual(toHex(Modes.cbcEncrypt(pt, key, hex(IV), { pad: false })), v.CBC, 'CBC mã hóa');
      assert.strictEqual(toHex(Modes.cbcDecrypt(hex(v.CBC), key, hex(IV), { pad: false })), PLAIN, 'CBC giải mã');
      assert.strictEqual(toHex(Modes.ctrCrypt(pt, key, hex(CTR0))), v.CTR, 'CTR mã hóa');
      assert.strictEqual(toHex(Modes.ctrCrypt(hex(v.CTR), key, hex(CTR0))), PLAIN, 'CTR giải mã');
    });
  }

  QUnit.test('Padding PKCS#7 – ví dụ “Xin chào”', (assert) => {
    const data = U.utf8Encode('Xin chào');
    assert.strictEqual(data.length, 9, '“à” chiếm 2 byte UTF-8');
    const padded = Modes.pkcs7Pad(data);
    assert.strictEqual(toHex(padded), '58696e206368c3a06f07070707070707', '+ 7 byte giá trị 07');
    assert.strictEqual(U.utf8Decode(Modes.pkcs7Unpad(padded)), 'Xin chào');
    assert.strictEqual(Modes.pkcs7Pad(new Uint8Array(16)).length, 32, 'đủ khối vẫn thêm 1 khối padding');
    assert.throws(() => Modes.pkcs7Unpad(new Uint8Array(16)), /Padding/, 'từ chối padding sai');
  });

  QUnit.test('Văn bản tiếng Việt: CBC và CTR khứ hồi với mọi độ dài khóa', (assert) => {
    const text = 'An toàn thông tin – Nhóm 01 mã hóa “tiếng Việt có dấu” 🔐';
    for (const n of [16, 24, 32]) {
      const key = U.randomBytes(n), iv = U.randomBytes(16);
      assert.strictEqual(U.utf8Decode(Modes.cbcDecrypt(Modes.cbcEncrypt(U.utf8Encode(text), key, iv), key, iv)), text, `CBC ${n * 8} bit`);
      assert.strictEqual(U.utf8Decode(Modes.ctrCrypt(Modes.ctrCrypt(U.utf8Encode(text), key, iv), key, iv)), text, `CTR ${n * 8} bit`);
    }
  });

  QUnit.test('ECB lộ cấu trúc: hai khối giống nhau cho bản mã giống nhau', (assert) => {
    const key = U.randomBytes(16);
    const ct = Modes.ecbEncrypt(new Uint8Array(32), key, { pad: false });
    assert.ok(U.bytesEqual(ct.subarray(0, 16), ct.subarray(16, 32)), 'ECB: C1 = C2');
    const cbc = Modes.cbcEncrypt(new Uint8Array(32), key, U.randomBytes(16), { pad: false });
    assert.notOk(U.bytesEqual(cbc.subarray(0, 16), cbc.subarray(16, 32)), 'CBC: C1 ≠ C2');
  });

  // ======================================================================= RSA
  QUnit.module('RSA – toán học');

  QUnit.test('Ví dụ số p = 61, q = 53, e = 17', (assert) => {
    const k = RSA.keyFromPrimes(61n, 53n, 17n);
    assert.strictEqual(k.n, 3233n, 'n = 3233');
    assert.strictEqual(k.phi, 3120n, 'φ(n) = 3120');
    assert.strictEqual(k.d, 2753n, 'd = 2753');
    assert.strictEqual(RSA.encryptInt(65n, k), 2790n, '65^17 mod 3233 = 2790');
    assert.strictEqual(RSA.decryptInt(2790n, k), 65n, '2790^2753 mod 3233 = 65');
    const info = {};
    assert.strictEqual(RSA.decryptCRT(2790n, k, info), 65n, 'giải mã CRT = 65');
    assert.deepEqual([k.dP, k.dQ, k.qInv, info.m1, info.m2, info.h], [53n, 49n, 38n, 4n, 12n, 1n], 'dP, dQ, qInv, m1, m2, h');
  });

  QUnit.test('Euclid mở rộng cho d = −367 mod 3120', (assert) => {
    const { g, x, y } = RSA.extGcd(17n, 3120n);
    assert.strictEqual(g, 1n);
    assert.strictEqual(17n * x + 3120n * y, 1n, 'Bézout: 17x + 3120y = 1');
    assert.strictEqual(RSA.mod(x, 3120n), 2753n);
  });

  QUnit.test('Bình phương – nhân khớp phép nhân lặp', (assert) => {
    for (let i = 0; i < 50; i++) {
      const b = BigInt(1 + Math.floor(Math.random() * 1000)), e = BigInt(Math.floor(Math.random() * 60)), m = BigInt(2 + Math.floor(Math.random() * 5000));
      let naive = 1n;
      for (let j = 0n; j < e; j++) naive = (naive * b) % m;
      assert.strictEqual(RSA.modPow(b, e, m), naive, `${b}^${e} mod ${m}`);
    }
    const trace = [];
    RSA.modPow(65n, 17n, 3233n, trace);
    assert.deepEqual(trace.map((t) => t.base), [65n, 992n, 1232n, 1547n, 789n], 'các cơ số 65, 65², 65⁴, 65⁸, 65¹⁶');
  });

  QUnit.test('Mọi thông điệp 0 ≤ m < 3233 đều giải mã đúng (kể cả m không nguyên tố cùng nhau với n)', (assert) => {
    const k = RSA.keyFromPrimes(61n, 53n, 17n);
    let bad = 0;
    for (let m = 0n; m < k.n; m++) {
      const c = RSA.encryptInt(m, k);
      if (RSA.decryptInt(c, k) !== m || RSA.decryptCRT(c, k) !== m) bad++;
    }
    assert.strictEqual(bad, 0, '3233/3233 thông điệp');
  });

  QUnit.test('Miller–Rabin', (assert) => {
    for (const p of [2n, 3n, 104729n, 2147483647n, (1n << 61n) - 1n, (1n << 127n) - 1n]) assert.ok(RSA.isProbablePrime(p), `${p} là số nguyên tố`);
    for (const c of [1n, 221n, 561n, 41041n, 825265n, 3215031751n, ((1n << 61n) - 1n) * ((1n << 31n) - 1n)]) assert.notOk(RSA.isProbablePrime(c), `${c} là hợp số`);
  });

  QUnit.test('Từ chối tham số sai', (assert) => {
    assert.throws(() => RSA.keyFromPrimes(61n, 61n, 17n), /khác nhau/);
    assert.throws(() => RSA.keyFromPrimes(60n, 53n, 17n), /nguyên tố/);
    assert.throws(() => RSA.keyFromPrimes(61n, 53n, 12n), /gcd/);
    const k = RSA.keyFromPrimes(61n, 53n, 17n);
    assert.throws(() => RSA.encryptInt(3233n, k), /0 ≤ m < n/);
  });

  QUnit.test('Sinh khóa 512 bit: cấu trúc khóa đúng', (assert) => {
    const k = RSA.generateKeyPair(512);
    assert.strictEqual(k.bits, 512, 'n dài đúng 512 bit');
    assert.strictEqual((k.e * k.d) % k.phi, 1n, 'e·d ≡ 1 (mod φ)');
    assert.strictEqual((k.q * k.qInv) % k.p, 1n, 'q·qInv ≡ 1 (mod p)');
    for (let i = 0; i < 5; i++) {
      const m = U.randomBigIntRange(0n, k.n - 1n);
      const c = RSA.encryptInt(m, k);
      assert.strictEqual(RSA.decryptCRT(c, k), RSA.decryptInt(c, k), 'CRT = giải mã thường');
    }
  });

  // ============================================================ OAEP + Web Crypto
  QUnit.module('RSA-OAEP, mã hóa lai và đối chứng Web Crypto');
  let KEY1024 = null;
  const key1024 = () => (KEY1024 = KEY1024 || RSA.generateKeyPair(1024));

  QUnit.test('OAEP khứ hồi và văn bản nhiều khối', async (assert) => {
    const k = key1024();
    const msg = U.utf8Encode('Xin chào thầy');
    const ct = await OAEP.encrypt(msg, k);
    assert.strictEqual(ct.length, 128, 'bản mã đúng k = 128 byte');
    assert.strictEqual(U.utf8Decode(await OAEP.decrypt(ct, k)), 'Xin chào thầy');
    const ct2 = await OAEP.encrypt(msg, k);
    assert.notOk(U.bytesEqual(ct, ct2), 'OAEP ngẫu nhiên: cùng bản rõ cho bản mã khác nhau');
    const long = 'Mã hóa văn bản dài bằng RSA-OAEP. '.repeat(12);
    const res = await OAEP.encryptText(long, k);
    assert.ok(res.blocks > 1, `chia ${res.blocks} khối`);
    assert.strictEqual(await OAEP.decryptText(res.cipher, k), long);
    const tampered = Uint8Array.from(ct); tampered[5] ^= 1;
    await assert.rejects(OAEP.decrypt(tampered, k), /OAEP/, 'phát hiện bản mã bị sửa');
  });

  QUnit.test('Mã hóa lai RSA-OAEP + AES-256-CBC', async (assert) => {
    const k = key1024();
    const text = 'Gói tin lai: RSA bọc khóa phiên, AES mã hóa dữ liệu.';
    const { packet } = await Hybrid.encrypt(text, k);
    assert.strictEqual((await Hybrid.decrypt(packet, k)).text, text);
  });

  QUnit.test('Web Crypto: AES-CBC và AES-CTR trùng từng byte với code tay', async (assert) => {
    // Chrome/Edge không hỗ trợ AES-192 trong Web Crypto; AES-192 đã được đối chiếu bằng NIST ở trên
    for (const n of [16, 32]) {
      const key = U.randomBytes(n), iv = U.randomBytes(16), data = U.utf8Encode('Đối chứng với thư viện chuẩn W3C Web Crypto API – ' + n);
      assert.strictEqual(toHex(Modes.cbcEncrypt(data, key, iv)), toHex(await WebCryptoLib.aesCbcEncrypt(data, key, iv)), `CBC ${n * 8} bit`);
      assert.strictEqual(toHex(Modes.ctrCrypt(data, key, iv)), toHex(await WebCryptoLib.aesCtr(data, key, iv)), `CTR ${n * 8} bit`);
    }
  });

  QUnit.test('Web Crypto: RSA-OAEP giải mã chéo hai chiều', async (assert) => {
    const k = key1024();
    const msg = U.utf8Encode('Giải mã chéo');
    const ours = await OAEP.encrypt(msg, k);
    assert.strictEqual(U.utf8Decode(await WebCryptoLib.rsaOaepDecrypt(ours, k)), 'Giải mã chéo', 'Web Crypto giải mã bản mã của nhóm');
    const theirs = await WebCryptoLib.rsaOaepEncrypt(msg, k);
    assert.strictEqual(U.utf8Decode(await OAEP.decrypt(theirs, k)), 'Giải mã chéo', 'nhóm giải mã bản mã của Web Crypto');
  });

  // ================================================== SHA-256, HMAC, PBKDF2
  QUnit.module('SHA-256, HMAC, PBKDF2 tự cài đặt');

  QUnit.test('SHA-256 – ví dụ của FIPS 180-4', (assert) => {
    const h = (s) => toHex(SHA256.hash(U.utf8Encode(s)));
    assert.strictEqual(h('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', '"abc"');
    assert.strictEqual(h(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'chuỗi rỗng');
    assert.strictEqual(h('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1', '448 bit (2 khối)');
    assert.strictEqual(toHex(SHA256.hash(new Uint8Array(1000000).fill(0x61))), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0', 'một triệu chữ a');
    const parts = new SHA256.Hasher().update(U.utf8Encode('ab')).update(U.utf8Encode('c')).digest();
    assert.strictEqual(toHex(parts), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'nạp nhiều lần = nạp một lần');
  });

  QUnit.test('HMAC-SHA256 – RFC 4231', (assert) => {
    assert.strictEqual(toHex(KDF.hmac(new Uint8Array(20).fill(0x0b), U.utf8Encode('Hi There'))), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7', 'test case 1');
    assert.strictEqual(toHex(KDF.hmac(U.utf8Encode('Jefe'), U.utf8Encode('what do ya want for nothing?'))), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843', 'test case 2');
    assert.strictEqual(toHex(KDF.hmac(new Uint8Array(131).fill(0xaa), U.utf8Encode('Test Using Larger Than Block-Size Key - Hash Key First'))), '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54', 'test case 6 (khóa dài hơn 1 khối)');
  });

  QUnit.test('PBKDF2-HMAC-SHA256 – vector chuẩn', (assert) => {
    const P = U.utf8Encode('password'), S = U.utf8Encode('salt');
    assert.strictEqual(toHex(KDF.pbkdf2(P, S, 1, 32)), '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b', 'c = 1');
    assert.strictEqual(toHex(KDF.pbkdf2(P, S, 2, 32)), 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43', 'c = 2');
    assert.strictEqual(toHex(KDF.pbkdf2(P, S, 4096, 32)), 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a', 'c = 4096');
    assert.strictEqual(toHex(KDF.pbkdf2(U.utf8Encode('passwordPASSWORDpassword'), U.utf8Encode('saltSALTsaltSALTsaltSALTsaltSALTsalt'), 4096, 40)),
      '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9', 'dkLen = 40 (2 khối đầu ra)');
  });

  // ================================================== Ứng dụng: file .enc
  QUnit.module('Ứng dụng: mã hóa file');
  const sample = () => U.concatBytes(U.utf8Encode('Báo cáo Nhóm 01 – nội dung nhị phân: '), U.randomBytes(5000));

  QUnit.test('Mật khẩu: khứ hồi CBC và CTR, giữ đúng tên file', async (assert) => {
    for (const mode of ['CBC', 'CTR']) {
      const data = sample();
      const enc = await FileCrypt.encryptWithPassword(data, 'báo cáo.pdf', 'Mật khẩu đủ dài!', { mode, iterations: 1000 });
      const out = await FileCrypt.decryptWithPassword(enc.file, 'Mật khẩu đủ dài!');
      assert.ok(U.bytesEqual(out.data, data), `${mode}: nội dung khớp`);
      assert.strictEqual(out.name, 'báo cáo.pdf', `${mode}: tên file khớp`);
      assert.strictEqual(out.info.mode, mode);
    }
  });

  QUnit.test('Mật khẩu: sai mật khẩu hoặc file bị sửa đều bị HMAC phát hiện', async (assert) => {
    const enc = await FileCrypt.encryptWithPassword(sample(), 'a.bin', 'dung', { iterations: 1000 });
    await assert.rejects(FileCrypt.decryptWithPassword(enc.file, 'sai'), /HMAC/, 'sai mật khẩu');
    const bad = Uint8Array.from(enc.file); bad[bad.length - 100] ^= 1;
    await assert.rejects(FileCrypt.decryptWithPassword(bad, 'dung'), /HMAC/, 'sửa 1 bit bản mã');
    assert.throws(() => FileCrypt.parseHeader(U.utf8Encode('không phải file enc của ứng dụng này, chỉ là chữ thường')), /không phải file/, 'file lạ');
  });

  QUnit.test('Khóa công khai: gửi file cho người nhận, lưu và nạp khóa', async (assert) => {
    const k = key1024();
    const pubOnly = FileCrypt.importKey(FileCrypt.exportPublicKey(k));
    const priv = FileCrypt.importKey(FileCrypt.exportPrivateKey(k));
    assert.notOk(pubOnly.isPrivate, 'file khóa công khai không chứa d');
    assert.strictEqual(pubOnly.n, k.n, 'nạp lại đúng n');
    const data = sample();
    const enc = await FileCrypt.encryptForRecipient(data, 'hop-dong.docx', pubOnly);
    const out = await FileCrypt.decryptWithPrivateKey(enc.file, priv);
    assert.ok(U.bytesEqual(out.data, data), 'người nhận giải mã đúng');
    assert.strictEqual(out.name, 'hop-dong.docx');
    const other = RSA.generateKeyPair(1024);
    await assert.rejects(FileCrypt.decryptWithPrivateKey(enc.file, other), /khóa phiên/, 'khóa riêng khác không mở được');
    assert.throws(() => FileCrypt.importKey('{"format":"N01-RSA-PRIVATE","n":"zz"}'), /không hợp lệ/, 'từ chối file khóa hỏng');
  });
})();
