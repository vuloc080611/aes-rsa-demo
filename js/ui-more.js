/* global $, CryptoUtils, RSA, OAEP, Hybrid, Modes, WebCryptoLib */
/** ui-more.js — Tab Mã hóa lai, tab Kiểm thử và đo hiệu năng. */
$(function () {
  'use strict';
  const U = CryptoUtils;
  const app = window.__app;
  const { state, setStatus, fail, ms, nextFrame, shortB64 } = app;

  // mã hóa lai
  const flow = (k, html) => $(`#hy-flow .flow-val[data-k="${k}"]`).html(html);

  $('#hy-gen').on('click', async function () {
    const $b = $(this).prop('disabled', true);
    try {
      $('#rr-bits').val('2048');
      await app.runKeygen(2048, '#rr-gen-log', '#hy-key-status');
      $('#rr-oaep').empty();
      app.refreshKeyUsers();
    } catch (err) { fail('#hy-key-status', err); } finally { $b.prop('disabled', false); }
  });

  $('#hy-encrypt').on('click', async () => {
    try {
      const { packet, sessionKey } = await Hybrid.encrypt($('#hy-plain').val(), state.rsaKey);
      $('#hy-packet').val(JSON.stringify(packet, null, 2));
      flow('k', `K = ${U.bytesToHex(sessionKey)}`);
      flow('data', `IV = ${packet.iv}<br>bản mã = ${shortB64(packet.ciphertext)}`);
      flow('wrap', `RSA-OAEP(K) = ${shortB64(packet.wrappedKey)}`);
      flow('open', '');
      setStatus('#hy-status', 'ok', 'Đã đóng gói. Có thể sửa thử một ký tự trong gói rồi bấm Mở gói để xem hệ thống phát hiện.');
    } catch (err) { fail('#hy-status', err); }
  });

  $('#hy-decrypt').on('click', async () => {
    try {
      let packet;
      try { packet = JSON.parse($('#hy-packet').val()); } catch (e) { throw new Error('Gói tin không phải JSON hợp lệ.'); }
      const { text, sessionKey } = await Hybrid.decrypt(packet, state.rsaKey);
      flow('open', `K mở được = ${U.bytesToHex(sessionKey)}<br>nội dung: ${app.esc(text)}`);
      setStatus('#hy-status', 'ok', 'Mở gói thành công: khóa riêng RSA mở được K, AES giải mã đúng nội dung.');
    } catch (err) { fail('#hy-status', err); }
  });

  //  kiểm thử
  $('#qt-run').on('click', () => $('#qt-frame').attr('src', `tests/test.html?t=${Date.now()}`));
  $('button[data-bs-target="#tab-tests"]').one('shown.bs.tab', () => $('#qt-run').trigger('click'));

  //  hiệu năng
  $('#bm-run').on('click', async function () {
    const $b = $(this).prop('disabled', true);
    const html = [];
    try {
      setStatus('#bm-status', 'info', 'Đang đo AES-CBC với 64 KB dữ liệu…');
      await nextFrame();
      const key = U.randomBytes(16), iv = U.randomBytes(16), data = U.randomBytes(64 * 1024);
      const tHand = await WebCryptoLib.timeIt(() => Modes.cbcEncrypt(data, key, iv), 5);
      const tLib = await WebCryptoLib.timeIt(() => WebCryptoLib.aesCbcEncrypt(data, key, iv), 5);
      html.push(app.barRows('AES-128-CBC, mã hóa 64 KB (ms)', [
        { label: 'Code tay', value: tHand, color: '#2ee6d6', text: ms(tHand) },
        { label: 'Web Crypto', value: tLib, color: '#8f83ff', text: ms(tLib) },
      ], 'ms'));

      let k = state.rsaKey;
      if (!k || k.bits < 1024) {
        setStatus('#bm-status', 'info', 'Chưa có khóa RSA từ 1024 bit, đang sinh khóa 2048 bit để đo…');
        await nextFrame();
        k = RSA.generateKeyPair(2048);
        state.rsaKey = k;
        app.refreshKeyUsers();
      }
      setStatus('#bm-status', 'info', `Đang đo giải mã RSA ${k.bits} bit…`);
      await nextFrame();
      const c = RSA.encryptInt(U.randomBigIntRange(2n, k.n - 1n), k);
      const tPlain = await WebCryptoLib.timeIt(() => RSA.decryptInt(c, k), 10);
      const tCrt = await WebCryptoLib.timeIt(() => RSA.decryptCRT(c, k), 10);
      const block = await OAEP.encrypt(U.utf8Encode('đo tốc độ'), k);
      let tWeb = null;
      try { tWeb = await WebCryptoLib.timeIt(() => WebCryptoLib.rsaOaepDecrypt(block, k), 10); } catch (e) { tWeb = null; }
      const rows = [
        { label: 'Code tay, cᵈ mod n', value: tPlain, color: '#ffb547', text: ms(tPlain) },
        { label: 'Code tay, CRT', value: tCrt, color: '#e89a2d', text: `${ms(tCrt)} (nhanh ×${(tPlain / tCrt).toFixed(1)})` },
      ];
      if (tWeb !== null) rows.push({ label: 'Web Crypto', value: tWeb, color: '#8f83ff', text: ms(tWeb) });
      html.push(app.barRows(`Giải mã RSA ${k.bits} bit, một khối (ms)`, rows, 'ms'));
      $('#bm-chart').html(html.join('') + '<p class="note mt-2">Web Crypto nhanh hơn vì được viết bằng mã máy tối ưu. Phần code tay ưu tiên dễ đọc và dễ kiểm chứng. Lần giải mã Web Crypto đã bao gồm cả bước nhập khóa.</p>');
      setStatus('#bm-status', 'ok', 'Đã đo xong. Kết quả phụ thuộc máy đang chạy.');
    } catch (err) { fail('#bm-status', err); } finally { $b.prop('disabled', false); }
  });
});
