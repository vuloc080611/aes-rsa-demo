/**
 * sha256.js — Hàm băm SHA-256 tự cài đặt theo NIST FIPS 180-4.
 * Dùng cho OAEP, HMAC và PBKDF2, để toàn bộ ứng dụng không phụ thuộc thư viện mật mã.
 *
 * Cách dùng:
 *   SHA256.hash(bytes)                    -> Uint8Array(32)
 *   const h = new SHA256.Hasher(); h.update(a); h.update(b); h.digest()
 */
(function (root) {
  'use strict';

  // 64 hằng số K: 32 bit đầu phần thập phân căn bậc ba của 64 số nguyên tố đầu tiên
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  // Giá trị băm khởi tạo: 32 bit đầu phần thập phân căn bậc hai của 8 số nguyên tố đầu tiên
  const H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  class Hasher {
    constructor() {
      this.h = new Uint32Array(H0);
      this.buf = new Uint8Array(64);   // khối 512 bit đang gom
      this.bufLen = 0;
      this.total = 0;                  // tổng số byte đã nạp
      this.w = new Uint32Array(64);
    }

    /** Hàm nén: xử lý một khối 64 byte. */
    compress(block, off) {
      const w = this.w, h = this.h;
      for (let i = 0; i < 16; i++) {
        const j = off + i * 4;
        w[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3];
      }
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    update(data) {
      let i = 0;
      this.total += data.length;
      if (this.bufLen > 0) {
        const n = Math.min(64 - this.bufLen, data.length);
        this.buf.set(data.subarray(0, n), this.bufLen);
        this.bufLen += n;
        i = n;
        if (this.bufLen === 64) { this.compress(this.buf, 0); this.bufLen = 0; }
      }
      for (; i + 64 <= data.length; i += 64) this.compress(data, i);
      if (i < data.length) {
        this.buf.set(data.subarray(i), 0);
        this.bufLen = data.length - i;
      }
      return this;
    }

    /** Padding: thêm bit 1, các bit 0, rồi độ dài thông điệp 64 bit (big-endian). */
    digest() {
      const bits = this.total * 8;
      const pad = new Uint8Array(((this.bufLen < 56 ? 56 : 120) - this.bufLen) + 8);
      pad[0] = 0x80;
      const hi = Math.floor(bits / 0x100000000), lo = bits >>> 0;
      const L = pad.length;
      pad[L - 8] = hi >>> 24; pad[L - 7] = hi >>> 16; pad[L - 6] = hi >>> 8; pad[L - 5] = hi;
      pad[L - 4] = lo >>> 24; pad[L - 3] = lo >>> 16; pad[L - 2] = lo >>> 8; pad[L - 1] = lo;
      const saveTotal = this.total;
      this.update(pad);
      this.total = saveTotal;
      const out = new Uint8Array(32);
      for (let i = 0; i < 8; i++) {
        out[i * 4] = this.h[i] >>> 24; out[i * 4 + 1] = this.h[i] >>> 16;
        out[i * 4 + 2] = this.h[i] >>> 8; out[i * 4 + 3] = this.h[i];
      }
      return out;
    }

    /** Sao chép trạng thái (để HMAC tính sẵn phần khóa, tăng tốc PBKDF2). */
    clone() {
      const c = new Hasher();
      c.h.set(this.h);
      c.buf.set(this.buf);
      c.bufLen = this.bufLen;
      c.total = this.total;
      return c;
    }
  }

  function hash(data) {
    return new Hasher().update(data).digest();
  }

  const api = { Hasher, hash, BLOCK: 64, SIZE: 32 };
  root.SHA256 = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
