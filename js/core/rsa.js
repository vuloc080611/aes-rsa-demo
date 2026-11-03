/**
 * rsa.js — RSA tự cài đặt bằng BigInt.
 * BigInt chỉ có + - * / % và phép dịch bit: lũy thừa modulo, nghịch đảo modulo
 * và kiểm tra nguyên tố đều phải tự viết.
 * Tham chiếu: Rivest–Shamir–Adleman (1978), RFC 8017 (PKCS #1 v2.2), FIPS 186-5.
 */
(function (root) {
  'use strict';
  const U = root.CryptoUtils || (typeof require !== 'undefined' && require('./utils.js'));

  function mod(a, m) {
    const r = a % m;
    return r < 0n ? r + m : r;
  }

  /** Euclid mở rộng: trả về { g, x, y } với a*x + b*y = g = gcd(a, b). Có ghi bước nếu cần. */
  function extGcd(a, b, steps) {
    let [oldR, r] = [a, b];
    let [oldX, x] = [1n, 0n];
    let [oldY, y] = [0n, 1n];
    while (r !== 0n) {
      const q = oldR / r;
      if (steps) steps.push({ a: oldR, b: r, q, rem: oldR - q * r });
      [oldR, r] = [r, oldR - q * r];
      [oldX, x] = [x, oldX - q * x];
      [oldY, y] = [y, oldY - q * y];
    }
    return { g: oldR, x: oldX, y: oldY };
  }

  function gcd(a, b) { return extGcd(a, b).g; }

  function modInverse(a, m, steps) {
    // Euclid mở rộng trên (m, a): m*x + a*y = g, nên a*y ≡ g (mod m)
    const { g, y } = extGcd(m, mod(a, m), steps);
    if (g !== 1n) throw new Error(`Không tồn tại nghịch đảo: gcd(${a}, ${m}) = ${g} ≠ 1.`);
    return mod(y, m);
  }

  /**
   * Lũy thừa modulo bằng bình phương – nhân, đọc bit số mũ từ phải sang trái.
   * trace (tùy chọn) ghi: bit đang xét, cơ số hiện tại, kết quả trước/sau.
   */
  function modPow(base, exp, m, trace) {
    if (m === 1n) return 0n;
    if (exp < 0n) throw new Error('Số mũ phải không âm.');
    let result = 1n;
    base = mod(base, m);
    let i = 0;
    while (exp > 0n) {
      const bit = exp & 1n;
      const before = result;
      if (bit === 1n) result = (result * base) % m;          // bit = 1: nhân
      if (trace) trace.push({ i, bit: Number(bit), base, before, after: result });
      base = (base * base) % m;                               // bình phương
      exp >>= 1n;                                             // sang bit kế tiếp
      i++;
    }
    return result;
  }

  // Các số nguyên tố nhỏ để lọc nhanh trước khi chạy Miller–Rabin
  const SMALL_PRIMES = (() => {
    const out = [];
    for (let n = 2; out.length < 300; n++) {
      if (out.every((p) => n % p !== 0)) out.push(n);
    }
    return out.map(BigInt);
  })();

  /**
   * Miller–Rabin: n - 1 = 2^s * d (d lẻ). Mỗi vòng chọn a ngẫu nhiên trong [2, n-2].
   * Hợp số lọt qua 1 vòng với xác suất ≤ 1/4, nên t vòng cho sai số ≤ 4^-t.
   */
  function isProbablePrime(n, rounds = 40, onRound) {
    if (n < 2n) return false;
    for (const p of SMALL_PRIMES) {
      if (n === p) return true;
      if (n % p === 0n) return false;
    }
    let d = n - 1n, s = 0;
    while ((d & 1n) === 0n) { d >>= 1n; s++; }
    for (let i = 0; i < rounds; i++) {
      const a = U.randomBigIntRange(2n, n - 2n);
      let x = modPow(a, d, n);
      let pass = x === 1n || x === n - 1n;
      for (let r = 1; r < s && !pass; r++) {
        x = (x * x) % n;
        if (x === n - 1n) pass = true;
      }
      if (onRound) onRound({ round: i + 1, a, pass });
      if (!pass) return false;                                // chắc chắn là hợp số
    }
    return true;                                              // nguyên tố với xác suất rất cao
  }

  /** Số nguyên tố ngẫu nhiên đúng `bits` bit; có 2 bit cao = 1 để p*q đủ độ dài. */
  function generatePrime(bits, onProgress) {
    let candidates = 0;
    for (;;) {
      let n = U.randomBigIntBits(bits) | 1n;
      n |= 1n << BigInt(bits - 2);
      candidates++;
      if (isProbablePrime(n, 1)) {                            // 1 vòng lọc nhanh
        const log = [];
        if (isProbablePrime(n, 40, (r) => log.push(r))) {
          if (onProgress) onProgress({ type: 'prime', bits, candidates, prime: n, rounds: log.length });
          return { prime: n, candidates, rounds: log.length };
        }
      }
      if (onProgress && candidates % 25 === 0) onProgress({ type: 'search', bits, candidates });
    }
  }

  /** Dựng bộ khóa từ p, q, e cho trước (dùng cho ví dụ số nhỏ và cho sinh khóa). */
  function keyFromPrimes(p, q, e = 65537n) {
    if (p === q) throw new Error('p và q phải là hai số nguyên tố khác nhau.');
    if (!isProbablePrime(p) || !isProbablePrime(q)) throw new Error('p và q phải là số nguyên tố.');
    if (p < q) [p, q] = [q, p];                               // quy ước p > q để qInv = q^-1 mod p
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    if (e <= 1n || e >= phi) throw new Error('Cần chọn 1 < e < φ(n).');
    if (gcd(e, phi) !== 1n) throw new Error(`gcd(e, φ(n)) = ${gcd(e, phi)} ≠ 1, hãy chọn e khác.`);
    const euclid = [];
    const d = modInverse(e, phi, euclid);
    return {
      n, e, d, p, q, phi,
      dP: d % (p - 1n), dQ: d % (q - 1n), qInv: modInverse(q, p),
      bits: U.bitLength(n), euclid,
    };
  }

  function generateKeyPair(bits = 2048, e = 65537n, onProgress) {
    if (bits < 64 || bits % 2) throw new Error('Độ dài khóa phải là số chẵn ≥ 64 bit.');
    for (;;) {
      const p = generatePrime(bits / 2, onProgress).prime;
      const q = generatePrime(bits / 2, onProgress).prime;
      if (p === q) continue;
      const phi = (p - 1n) * (q - 1n);
      if (gcd(e, phi) !== 1n) continue;
      const key = keyFromPrimes(p, q, e);
      if (key.bits === bits) return key;
    }
  }

  function encryptInt(m, key, trace) {
    if (m < 0n || m >= key.n) throw new Error(`Bản rõ phải thỏa 0 ≤ m < n.`);
    return modPow(m, key.e, key.n, trace);
  }

  function decryptInt(c, key, trace) {
    if (c < 0n || c >= key.n) throw new Error(`Bản mã phải thỏa 0 ≤ c < n.`);
    return modPow(c, key.d, key.n, trace);
  }

  /** Giải mã theo định lý số dư Trung Hoa (RFC 8017 §5.1.2, cách 2b). */
  function decryptCRT(c, key, info) {
    if (c < 0n || c >= key.n) throw new Error(`Bản mã phải thỏa 0 ≤ c < n.`);
    const m1 = modPow(c, key.dP, key.p);
    const m2 = modPow(c, key.dQ, key.q);
    const h = mod(key.qInv * (m1 - m2), key.p);
    const m = m2 + h * key.q;
    if (info) Object.assign(info, { m1, m2, h, m });
    return m;
  }

  const api = { mod, extGcd, gcd, modInverse, modPow, isProbablePrime, generatePrime, keyFromPrimes, generateKeyPair, encryptInt, decryptInt, decryptCRT, SMALL_PRIMES };
  root.RSA = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
