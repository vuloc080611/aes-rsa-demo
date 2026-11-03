/* global $, CryptoUtils, AES, Modes, RSA, OAEP, Hybrid, WebCryptoLib */
/**
 * app.js — Giao diện (jQuery + Bootstrap). File này KHÔNG chứa thuật toán mật mã:
 * mọi phép tính gọi sang js/core/ (code tay) hoặc js/lib/webcrypto.js (đối chứng).
 */
$(function () {
  'use strict';
  const U = CryptoUtils;
  const state = { rsaKey: null, aesLast: null };

  //  tiện ích
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function setStatus(sel, type, html) {
    $(sel).removeClass('ok err info').addClass(type || '').html(html || '');
  }
  function fail(sel, err) {
    setStatus(sel, 'err', esc(err && err.message ? err.message : err));
  }
  function parseBig(v, name) {
    const s = String(v).trim();
    if (!/^\d+$/.test(s)) throw new Error(`${name} phải là số nguyên không âm.`);
    return BigInt(s);
  }
  function short(n, max = 48) { return U.formatBigInt(n, max); }
  function shortB64(b64, max = 90) { return b64.length > max ? `${b64.slice(0, max)}… (${b64.length} ký tự)` : b64; }
  function hexGroups(bytes, size = 4) {
    const h = U.bytesToHex(bytes);
    return h.match(new RegExp(`.{1,${size * 2}}`, 'g')).join(' ');
  }
  const ms = (x) => (x < 1 ? x.toFixed(3) : x < 10 ? x.toFixed(2) : x.toFixed(1)) + ' ms';
  const nextFrame = () => new Promise((r) => setTimeout(r, 30));

  // Chuyển tab con (segmented control) bằng Bootstrap tab
  $('.seg-btn').on('shown.bs.tab', function () {
    $(this).addClass('active').siblings().removeClass('active');
  });

  //  RSA: ví dụ số nhỏ
  function smallKey() {
    const p = parseBig($('#rs-p').val(), 'p');
    const q = parseBig($('#rs-q').val(), 'q');
    const e = parseBig($('#rs-e').val(), 'e');
    if (p > 10n ** 12n || q > 10n ** 12n) throw new Error('Phần số nhỏ giới hạn p, q ≤ 10¹² để bảng từng bước dễ đọc. Dùng tab "Khóa thật" cho khóa lớn.');
    return RSA.keyFromPrimes(p, q, e);
  }

  function renderSmallKey(k) {
    $('#rs-key').html(`
      <dt>n = p·q</dt><dd class="big">${k.n}</dd>
      <dt>φ(n) = (p−1)(q−1)</dt><dd>${k.phi}</dd>
      <dt>d = e⁻¹ mod φ(n)</dt><dd class="big">${k.d}</dd>
      <dt>Khóa công khai</dt><dd>(n, e) = (${k.n}, ${k.e})</dd>
      <dt>Khóa riêng</dt><dd>(n, d) = (${k.n}, ${k.d})</dd>`);
  }

  function euclidTable(k) {
    const rows = k.euclid.map((s, i) => `<tr><td>${i + 1}</td><td>${s.a} = ${s.q} × ${s.b} + ${s.rem}</td></tr>`).join('');
    return `<h3>1. Tìm d bằng Euclid mở rộng</h3>
      <p class="note">Chia liên tiếp cho đến khi số dư bằng 0. Truy ngược các phép chia cho ra e·d ≡ 1 (mod φ(n)).</p>
      <div class="table-wrap"><table class="table table-sm table-steps"><thead><tr><th>Bước</th><th>Phép chia</th></tr></thead><tbody>${rows}</tbody></table></div>
      <p class="mt-2"><span class="formula">${k.e} × ${k.d} mod ${k.phi} = ${(k.e * k.d) % k.phi}</span></p>`;
  }

  function powTable(title, base, exp, mod, trace, result) {
    const bits = exp.toString(2);
    const limit = 64;
    const rows = trace.slice(0, limit).map((t) => `<tr class="${t.bit ? 'hit' : ''}"><td>${t.i}</td><td>${t.bit}</td><td>${base}^${2n ** BigInt(t.i)} ≡ ${t.base}</td><td>${t.before}</td><td>${t.after}</td></tr>`).join('');
    const more = trace.length > limit ? `<p class="note">Chỉ hiện ${limit}/${trace.length} bước đầu.</p>` : '';
    const nMul = trace.filter((t) => t.bit).length;
    return `<h3>${title}</h3>
      <p class="note">Số mũ ${exp} = ${bits}₂. Đọc bit từ phải sang trái: bit 1 thì nhân kết quả với cơ số, sau mỗi bước bình phương cơ số.
        Tổng cộng ${trace.length - 1} lần bình phương và ${nMul} lần nhân, thay vì ${exp > 1000n ? 'hàng nghìn' : exp - 1n} lần nhân liên tiếp.</p>
      <div class="table-wrap"><table class="table table-sm table-steps"><thead><tr><th>Bit thứ</th><th>Bit</th><th>Cơ số (mod ${mod})</th><th>Kết quả trước</th><th>Kết quả sau</th></tr></thead><tbody>${rows}</tbody></table></div>${more}
      <p class="mt-2"><span class="formula">${base}^${exp} mod ${mod} = ${result}</span></p>`;
  }

  function rsSmall(mode) {
    try {
      const k = smallKey();
      renderSmallKey(k);
      let html = euclidTable(k);
      if (mode === 'enc') {
        const m = parseBig($('#rs-m').val(), 'm');
        const trace = [];
        const c = RSA.encryptInt(m, k, trace);
        $('#rs-c').val(c.toString());
        html += powTable(`2. Mã hóa: c = m<sup>e</sup> mod n`, m, k.e, k.n, trace, c);
        setStatus('#rs-status', 'ok', `Mã hóa: ${m}<sup>${k.e}</sup> mod ${k.n} = <b>${c}</b>`);
      } else {
        const c = parseBig($('#rs-c').val(), 'c');
        const trace = [];
        const m = RSA.decryptInt(c, k, trace);
        const info = {};
        RSA.decryptCRT(c, k, info);
        $('#rs-m').val(m.toString());
        html += powTable(`2. Giải mã: m = c<sup>d</sup> mod n`, c, k.d, k.n, trace, m);
        html += `<h3>3. Cách nhanh hơn: định lý số dư Trung Hoa (RFC 8017 §5.1.2)</h3>
          <dl class="kv">
            <dt>dP = d mod (p−1)</dt><dd>${k.dP}</dd><dt>dQ = d mod (q−1)</dt><dd>${k.dQ}</dd><dt>qInv = q⁻¹ mod p</dt><dd>${k.qInv}</dd>
            <dt>m₁ = c<sup>dP</sup> mod p</dt><dd>${info.m1}</dd><dt>m₂ = c<sup>dQ</sup> mod q</dt><dd>${info.m2}</dd>
            <dt>h = qInv·(m₁ − m₂) mod p</dt><dd>${info.h}</dd><dt>m = m₂ + h·q</dt><dd class="big">${info.m}</dd>
          </dl><p class="note mt-2">Hai lũy thừa tính trên p và q, mỗi số chỉ dài bằng nửa n. Về lý thuyết nhanh hơn khoảng 4 lần; số đo thực tế trên máy này xem ở tab Kiểm thử và hiệu năng.</p>`;
        setStatus('#rs-status', 'ok', `Giải mã: ${c}<sup>${k.d}</sup> mod ${k.n} = <b>${m}</b>`);
      }
      $('#rs-detail').html(html);
    } catch (err) {
      fail('#rs-status', err);
    }
  }
  $('#rs-encrypt').on('click', () => rsSmall('enc'));
  $('#rs-decrypt').on('click', () => rsSmall('dec'));
  $('#rs-reset').on('click', () => {
    $('#rs-p').val('61'); $('#rs-q').val('53'); $('#rs-e').val('17'); $('#rs-m').val('65'); $('#rs-c').val('');
    rsSmall('enc');
  });

  //  RSA: khóa thật
  function generateKey(bits, onProgress) {
    return new Promise((resolve, reject) => {
      let worker = null;
      try {
        worker = new Worker('js/worker/rsa-keygen.worker.js');
      } catch (e) {
        worker = null;
      }
      const fallback = () => {
        // Mở bằng file:// một số trình duyệt chặn Worker: sinh khóa ngay trên luồng chính
        onProgress({ type: 'note', text: 'Trình duyệt chặn Web Worker khi mở bằng file://, sinh khóa trên luồng chính (trang có thể dừng vài giây).' });
        setTimeout(() => {
          try {
            const t0 = performance.now();
            const key = RSA.generateKeyPair(bits, 65537n, onProgress);
            resolve({ key, ms: performance.now() - t0 });
          } catch (err) { reject(err); }
        }, 50);
      };
      if (!worker) return fallback();
      worker.onmessage = (ev) => {
        const msg = ev.data;
        if (msg.type === 'progress') onProgress(msg.progress);
        else if (msg.type === 'done') { worker.terminate(); resolve({ key: msg.key, ms: msg.ms }); }
        else if (msg.type === 'error') { worker.terminate(); reject(new Error(msg.message)); }
      };
      worker.onerror = (e) => { e.preventDefault(); worker.terminate(); fallback(); };
      worker.postMessage({ bits });
    });
  }

  function renderBigKey(k, sel) {
    $(sel).html(`
      <dt>Độ dài n</dt><dd class="big">${k.bits} bit</dd>
      <dt>e</dt><dd>${k.e}</dd>
      <dt>n</dt><dd>${short(k.n)}</dd>
      <dt>d</dt><dd>${short(k.d)}</dd>
      <dt>p</dt><dd>${short(k.p)}</dd>
      <dt>q</dt><dd>${short(k.q)}</dd>`);
  }

  async function runKeygen(bits, logSel, statusSel) {
    const $log = $('<div class="log"></div>');
    $(logSel).empty().append(`<h3>Tìm số nguyên tố p, q (mỗi số ${bits / 2} bit)</h3>
      <p class="note">Sinh số lẻ ngẫu nhiên, lọc bằng các số nguyên tố nhỏ rồi chạy Miller–Rabin 40 vòng. Theo định lý số nguyên tố, trung bình cần thử khoảng ${Math.round((bits / 2) * Math.LN2 / 2)} số lẻ cho mỗi số.</p>`).append($log);
    const line = (cls, text) => { $log.append(`<div class="${cls}">${esc(text)}</div>`); $log.scrollTop($log[0].scrollHeight); };
    let found = 0;
    setStatus(statusSel, 'info', `Đang sinh khóa ${bits} bit…`);
    const { key, ms: took } = await generateKey(bits, (p) => {
      if (p.type === 'search') line('', `  đã thử ${p.candidates} ứng viên…`);
      else if (p.type === 'note') line('hi', p.text);
      else if (p.type === 'prime') {
        found++;
        line('ok', `${found === 1 ? 'p' : found === 2 ? 'q' : 'số dự phòng'}: tìm thấy sau ${p.candidates} ứng viên, qua ${p.rounds} vòng Miller–Rabin`);
        line('', `  ${short(p.prime, 60)}`);
      }
    });
    line('hi', `n = p·q dài ${key.bits} bit, e = 65537, d = e⁻¹ mod φ(n). Thời gian: ${ms(took)}`);
    state.rsaKey = key;
    refreshKeyUsers();
    setStatus(statusSel, 'ok', `Đã sinh khóa ${key.bits} bit trong ${ms(took)}.`);
    return key;
  }

  function refreshKeyUsers() {
    const k = state.rsaKey;
    $('#rr-encrypt, #rr-decrypt, #hy-encrypt, #hy-decrypt').prop('disabled', !k);
    if (k) {
      renderBigKey(k, '#rr-key');
      setStatus('#hy-key-status', 'ok', `Đang dùng khóa RSA ${k.bits} bit (dùng chung với tab RSA).`);
    } else {
      setStatus('#hy-key-status', 'info', 'Chưa có khóa RSA. Sinh khóa ở đây hoặc ở tab RSA.');
    }
  }

  $('#rr-gen').on('click', async function () {
    const $b = $(this).prop('disabled', true);
    try {
      await runKeygen(Number($('#rr-bits').val()), '#rr-gen-log', '#rr-gen-status');
      $('#rr-oaep').empty();
    } catch (err) {
      fail('#rr-gen-status', err);
    } finally { $b.prop('disabled', false); }
  });

  $('#rr-encrypt').on('click', async () => {
    try {
      const k = state.rsaKey;
      const t0 = performance.now();
      const res = await OAEP.encryptText($('#rr-plain').val(), k);
      const took = performance.now() - t0;
      const b64 = U.bytesToBase64(res.cipher);
      $('#rr-cipher').val(b64);
      setStatus('#rr-status', 'ok', `Đã mã hóa thành ${res.blocks} khối OAEP, mỗi khối ${res.blockBytes} byte (${ms(took)}).`);
      let cmp = '';
      try {
        const first = res.cipher.subarray(0, res.blockBytes);
        const plainFirst = await WebCryptoLib.rsaOaepDecrypt(first, k);
        const ours = U.utf8Encode($('#rr-plain').val()).subarray(0, res.maxPerBlock);
        cmp = U.bytesEqual(plainFirst, ours)
          ? '<p class="compare ok mt-2">Web Crypto giải mã được khối đầu tiên do code tay tạo ra: định dạng OAEP đúng chuẩn RFC 8017.</p>'
          : '<p class="compare mt-2">Web Crypto giải mã ra nội dung khác. Cần kiểm tra lại.</p>';
      } catch (e) {
        cmp = `<p class="compare na mt-2">Không đối chứng được với Web Crypto: ${esc(e.message)}${k.bits < 1024 ? ' (nhiều trình duyệt không nhận khóa dưới 1024 bit).' : ''}</p>`;
      }
      $('#rr-oaep').html(`<h3>RSAES-OAEP với SHA-256</h3>
        <p class="note">Mỗi khối: EM = 0x00 ‖ maskedSeed ‖ maskedDB, trong đó DB = Hash(nhãn) ‖ 0…0 ‖ 0x01 ‖ thông điệp và seed là 32 byte ngẫu nhiên.
        Vì có seed ngẫu nhiên, mã hóa cùng một câu hai lần sẽ cho hai bản mã khác nhau.</p>
        <dl class="kv"><dt>Độ dài khóa k</dt><dd>${res.blockBytes} byte</dd><dt>Tối đa mỗi khối</dt><dd>k − 2·32 − 2 = ${res.maxPerBlock} byte</dd>
        <dt>Bản rõ (UTF-8)</dt><dd>${U.utf8Encode($('#rr-plain').val()).length} byte</dd><dt>Số khối</dt><dd>${res.blocks}</dd><dt>Bản mã</dt><dd>${shortB64(b64)}</dd></dl>${cmp}`);
    } catch (err) { fail('#rr-status', err); }
  });

  $('#rr-decrypt').on('click', async () => {
    try {
      const k = state.rsaKey;
      const cipher = U.base64ToBytes($('#rr-cipher').val());
      const useCRT = $('#rr-crt').is(':checked');
      const t0 = performance.now();
      const text = await decryptTextWith(cipher, k, useCRT);
      const took = performance.now() - t0;
      $('#rr-plain').val(text);
      setStatus('#rr-status', 'ok', `Giải mã thành công ${useCRT ? 'bằng CRT' : 'bằng cᵈ mod n'} trong ${ms(took)}. Bản rõ đã được đưa vào ô phía trên.`);
    } catch (err) { fail('#rr-status', err); }
  });

  async function decryptTextWith(cipher, k, useCRT) {
    const kb = OAEP.keyBytes(k);
    if (cipher.length === 0 || cipher.length % kb !== 0) throw new Error(`Bản mã phải là bội của ${kb} byte với khóa này.`);
    const parts = [];
    for (let i = 0; i < cipher.length; i += kb) parts.push(await OAEP.decrypt(cipher.subarray(i, i + kb), k, useCRT));
    return U.utf8Decode(U.concatBytes(...parts));
  }

  // Xuất cho các phần sau dùng chung
  window.__app = { state, esc, setStatus, fail, ms, nextFrame, runKeygen, refreshKeyUsers, hexGroups, shortB64, short };
  rsSmall('enc');
  refreshKeyUsers();
});
