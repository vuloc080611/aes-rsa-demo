/* global $, CryptoUtils, FileCrypt */
/** ui-app.js — Tab Ứng dụng: chỉ gọi FileCrypt (code tay), không chứa thuật toán. */
$(function () {
  'use strict';
  const U = CryptoUtils;
  const app = window.__app;
  const { state, esc, setStatus, fail, ms, nextFrame } = app;
  const MAX_MB = 50;

  //  tiện ích
  function download(data, name, type) {
    const blob = new Blob([data], { type: type || 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  async function readFile(sel) {
    const f = $(sel)[0].files[0];
    if (!f) throw new Error('Hãy chọn một file.');
    if (f.size > MAX_MB * 1024 * 1024) throw new Error(`File lớn hơn ${MAX_MB} MB. Bản demo xử lý trên trình duyệt nên giới hạn kích thước.`);
    return { name: f.name, data: new Uint8Array(await f.arrayBuffer()) };
  }

  const size = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB');

  function progress(sel) {
    const $p = $(sel).removeClass('d-none');
    const bar = $p.find('.progress-bar')[0];
    bar.style.width = '0%';
    return {
      set: (x) => { bar.style.width = Math.round(x * 100) + '%'; },
      done: () => setTimeout(() => $p.addClass('d-none'), 600),
    };
  }

  function busy($btns, on) { $btns.prop('disabled', on); }

  /** Vẽ cấu trúc file .enc và bảng các bước. */
  function showDetail(kind, op, fileBytes, info, extra) {
    const isPw = info.type === 'password';
    const hdrFixed = 10;
    const parts = isPw
      ? [['Đầu file', hdrFixed, '#15213a', 'Đầu'], ['Số vòng PBKDF2', 4, '#5b6779', 'Lặp'], ['Salt', 16, '#4450b0', 'Salt']]
      : [['Đầu file', hdrFixed, '#15213a', 'Đầu'], ['Khóa phiên bọc bằng RSA-OAEP', 2 + info.wrappedKey.length, '#a8690f', 'Khóa bọc RSA']];
    parts.push(['IV', 16, '#4450b0', 'IV'], [`Bản mã AES-${info.keyLen * 8}-${info.mode}`, info.ciphertext.length, '#0b7f7d', `Bản mã AES-${info.keyLen * 8}-${info.mode}`], ['Thẻ HMAC', 32, '#b5452e', 'HMAC']);
    const total = fileBytes.length;
    const map = parts.map(([n, b, c, s2]) => `<span style="flex:${Math.max(b / total, 0.06)};background:${c}" title="${esc(n)}: ${b} byte">${esc(s2)}</span>`).join('');
    const rows = parts.map(([n, b, c]) => `<tr><td><span class="dot" style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${c};margin-right:7px;vertical-align:middle"></span>${esc(n)}</td><td>${size(b)}</td></tr>`).join('');
    const steps = isPw ? [
      `Sinh salt ngẫu nhiên 16 byte: <span class="mono">${U.bytesToHex(info.salt)}</span>`,
      `PBKDF2-HMAC-SHA256 lặp ${info.iterations.toLocaleString('vi-VN')} vòng biến mật khẩu thành 32 byte bí mật (${ms(extra.kdfMs || info.kdfMs || 0)}). Lặp nhiều vòng để kẻ tấn công dò mật khẩu rất chậm.`,
      `Từ 32 byte bí mật, HMAC tách ra khóa AES-${info.keyLen * 8} và khóa HMAC riêng.`,
    ] : [
      'Sinh khóa phiên ngẫu nhiên 32 byte.',
      `Bọc khóa phiên bằng RSA-OAEP với khóa công khai người nhận (${info.wrappedKey.length} byte). Chỉ khóa riêng tương ứng mở được.`,
      `Từ khóa phiên, HMAC tách ra khóa AES-${info.keyLen * 8} và khóa HMAC.`,
    ];
    steps.push(
      `AES-${info.keyLen * 8} chế độ ${info.mode} với IV ngẫu nhiên <span class="mono">${U.bytesToHex(info.iv)}</span> mã hóa tên file và nội dung${info.mode === 'CBC' ? ', có padding PKCS#7' : ''}.`,
      `HMAC-SHA256 trên toàn bộ phần đầu, IV và bản mã: <span class="mono">${U.bytesToHex(info.tag).slice(0, 32)}…</span>. ${op === 'dec' ? 'Khi giải mã, thẻ được kiểm tra trước, khớp mới giải mã.' : 'Sai mật khẩu hay sửa 1 bit đều làm thẻ không khớp.'}`,
    );
    $('#ap-detail').html(`
      <p class="note">${esc(kind)}: file .enc dài ${size(total)}${extra.plainSize !== undefined ? `, file gốc ${size(extra.plainSize)}` : ''}. Toàn bộ thuật toán tự cài đặt trong js/core/.</p>
      <div class="enc-map mb-3">${map}</div>
      <div class="row g-4">
        <div class="col-lg-4"><table class="table table-sm table-steps"><thead><tr><th>Phần</th><th>Kích thước</th></tr></thead><tbody>${rows}</tbody></table></div>
        <div class="col-lg-8"><ol class="mb-0">${steps.map((s) => `<li class="mb-2">${s}</li>`).join('')}</ol></div>
      </div>`);
  }

  // 1) mật khẩu
  $('#ap-show').on('click', function () {
    const $i = $('#ap-pass');
    const show = $i.attr('type') === 'password';
    $i.attr('type', show ? 'text' : 'password');
    $(this).text(show ? 'Ẩn' : 'Hiện');
  });

  $('#ap-enc').on('click', async () => {
    const $b = $('#ap-enc, #ap-dec');
    try {
      const { name, data } = await readFile('#ap-file');
      const pw = $('#ap-pass').val();
      if (pw.length < 8) throw new Error('Mật khẩu cần ít nhất 8 ký tự.');
      busy($b, true);
      setStatus('#ap-status', 'info', 'Đang tạo khóa từ mật khẩu (PBKDF2)…');
      await nextFrame();
      const p = progress('#ap-prog');
      const t0 = performance.now();
      const res = await FileCrypt.encryptWithPassword(data, name, pw, {
        mode: $('#ap-mode').val(), keyLen: Number($('#ap-size').val()),
        onProgress: (x) => { p.set(x); setStatus('#ap-status', 'info', `Đang mã hóa… ${Math.round(x * 100)}%`); },
      });
      p.done();
      download(res.file, name + '.enc');
      setStatus('#ap-status', 'ok', `Đã mã hóa <b>${esc(name)}</b> (${size(data.length)}) trong ${ms(performance.now() - t0)} và tải về <b>${esc(name)}.enc</b>.`);
      showDetail('Mã hóa bằng mật khẩu', 'enc', res.file, FileCrypt.parseHeader(res.file), { kdfMs: res.kdfMs, plainSize: data.length });
    } catch (err) { fail('#ap-status', err); } finally { busy($b, false); }
  });

  $('#ap-dec').on('click', async () => {
    const $b = $('#ap-enc, #ap-dec');
    try {
      const { data } = await readFile('#ap-file');
      busy($b, true);
      setStatus('#ap-status', 'info', 'Đang kiểm tra mật khẩu (PBKDF2 + HMAC)…');
      await nextFrame();
      const p = progress('#ap-prog');
      const t0 = performance.now();
      const out = await FileCrypt.decryptWithPassword(data, $('#ap-pass').val(), { onProgress: (x) => p.set(x) });
      p.done();
      download(out.data, out.name);
      setStatus('#ap-status', 'ok', `Thẻ HMAC khớp. Đã giải mã và tải về <b>${esc(out.name)}</b> (${size(out.data.length)}) trong ${ms(performance.now() - t0)}.`);
      showDetail('Giải mã bằng mật khẩu', 'dec', data, out.info, { plainSize: out.data.length });
    } catch (err) { fail('#ap-status', err); $('#ap-prog').addClass('d-none'); } finally { busy($b, false); }
  });

  // 2) khóa RSA
  function refreshAppKey() {
    const k = state.appKey;
    $('#ak-pub, #ar-enc').prop('disabled', !k);
    $('#ak-priv, #ar-dec').prop('disabled', !(k && k.d));
    if (!k) { setStatus('#ak-status', 'info', 'Chưa có khóa. Sinh cặp khóa mới, hoặc nạp file khóa công khai của người nhận.'); return; }
    setStatus('#ak-status', 'ok', `${k.d ? 'Cặp khóa (công khai + riêng)' : 'Khóa công khai'} ${k.bits} bit. Dấu vân tay: <span class="mono">${FileCrypt.fingerprint(k)}</span>${k.d ? '' : '. Chỉ mã hóa được, không giải mã được.'}`);
  }

  $('#ak-gen').on('click', async function () {
    const $b = $(this).prop('disabled', true);
    try {
      const key = await app.runKeygen(2048, '#ap-detail', '#ak-status');
      state.appKey = Object.assign({ isPrivate: true }, key);
      refreshAppKey();
    } catch (err) { fail('#ak-status', err); } finally { $b.prop('disabled', false); }
  });

  $('#ak-pub').on('click', () => download(FileCrypt.exportPublicKey(state.appKey), `khoa-cong-khai-${state.appKey.bits}.json`, 'application/json'));
  $('#ak-priv').on('click', () => {
    if (!confirm('Khóa riêng phải giữ bí mật tuyệt đối, không gửi cho ai. Vẫn tải về?')) return;
    download(FileCrypt.exportPrivateKey(state.appKey), `khoa-rieng-${state.appKey.bits}.json`, 'application/json');
  });

  $('#ak-load').on('change', async function () {
    const f = this.files[0];
    if (!f) return;
    try {
      const key = FileCrypt.importKey(await f.text());
      state.appKey = key;
      if (key.d) { state.rsaKey = key; app.refreshKeyUsers(); }
      refreshAppKey();
    } catch (err) { fail('#ak-status', err); }
    this.value = '';
  });

  $('#ar-enc').on('click', async () => {
    const $b = $('#ar-enc, #ar-dec');
    try {
      const { name, data } = await readFile('#ar-file');
      busy($b, true);
      const p = progress('#ar-prog');
      const t0 = performance.now();
      const res = await FileCrypt.encryptForRecipient(data, name, state.appKey, { onProgress: (x) => p.set(x) });
      p.done();
      download(res.file, name + '.enc');
      setStatus('#ar-status', 'ok', `Đã mã hóa <b>${esc(name)}</b> cho người giữ khóa <span class="mono">${FileCrypt.fingerprint(state.appKey)}</span> (${app.ms(performance.now() - t0)}). Gửi file .enc này qua email, Zalo… đều an toàn.`);
      showDetail('Mã hóa cho người nhận (RSA + AES)', 'enc', res.file, FileCrypt.parseHeader(res.file), { plainSize: data.length });
    } catch (err) { fail('#ar-status', err); } finally { busy($b, false); refreshAppKey(); }
  });

  $('#ar-dec').on('click', async () => {
    const $b = $('#ar-enc, #ar-dec');
    try {
      const { data } = await readFile('#ar-file');
      busy($b, true);
      const p = progress('#ar-prog');
      const t0 = performance.now();
      const out = await FileCrypt.decryptWithPrivateKey(data, state.appKey, { onProgress: (x) => p.set(x) });
      p.done();
      download(out.data, out.name);
      setStatus('#ar-status', 'ok', `Khóa riêng mở được khóa phiên, thẻ HMAC khớp. Đã tải về <b>${esc(out.name)}</b> (${size(out.data.length)}, ${app.ms(performance.now() - t0)}).`);
      showDetail('Giải mã bằng khóa riêng', 'dec', data, out.info, { plainSize: out.data.length });
    } catch (err) { fail('#ar-status', err); $('#ar-prog').addClass('d-none'); } finally { busy($b, false); refreshAppKey(); }
  });

  refreshAppKey();
});
