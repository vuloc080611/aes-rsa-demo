/* global $, CryptoUtils, AES, Modes */
/** ui-visual.js — Thí nghiệm avalanche và ảnh mã hóa ECB/CBC, kèm hàm vẽ biểu đồ cột SVG. */
$(function () {
  'use strict';
  const U = CryptoUtils;
  const { setStatus, fail, nextFrame } = window.__app;

  /**
   * Biểu đồ cột dọc SVG đơn giản.
   * opts: { labels, values, color, max, refLine, refLabel, unit, title, valueFmt }
   */
  function columnChart(opts) {
    const W = 640, H = 300, L = 44, R = 12, T = 34, B = 40;
    const n = opts.values.length;
    const max = opts.max || Math.max(...opts.values) * 1.15;
    const cw = (W - L - R) / n;
    const y = (v) => T + (H - T - B) * (1 - v / max);
    const fmt = opts.valueFmt || ((v) => v.toFixed(1));
    let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${opts.title}">`;
    s += `<text x="${L}" y="20" font-size="14" font-weight="700" fill="#e9f2ff">${opts.title}</text>`;
    for (let g = 0; g <= 4; g++) {
      const v = (max / 4) * g, yy = y(v);
      s += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}" stroke="rgba(154,184,220,.24)"/>`;
      s += `<text x="${L - 6}" y="${yy + 4}" font-size="11" text-anchor="end" fill="#b5c5d9">${Math.round(v)}</text>`;
    }
    opts.values.forEach((v, i) => {
      const x = L + i * cw + cw * 0.18, w = cw * 0.64;
      s += `<rect x="${x}" y="${y(v)}" width="${w}" height="${y(0) - y(v)}" rx="3" fill="${opts.color}"><title>${opts.labels[i]}: ${fmt(v)}</title></rect>`;
      s += `<text x="${x + w / 2}" y="${y(v) - 5}" font-size="11" font-weight="600" text-anchor="middle" fill="#e1ebf8">${fmt(v)}</text>`;
      s += `<text x="${x + w / 2}" y="${H - B + 16}" font-size="11" text-anchor="middle" fill="#b5c5d9">${opts.labels[i]}</text>`;
    });
    if (opts.refLine !== undefined) {
      const yy = y(opts.refLine);
      s += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}" stroke="#ff7b86" stroke-dasharray="6 4" stroke-width="1.5"/>`;
      s += `<text x="${L + 6}" y="${yy - 8}" font-size="12" font-weight="700" fill="#ff9ca5">${opts.refLabel}</text>`;
    }
    if (opts.xTitle) s += `<text x="${(W + L) / 2}" y="${H - 6}" font-size="12" text-anchor="middle" fill="#c2d0e1">${opts.xTitle}</text>`;
    return s + '</svg>';
  }

  /** Biểu đồ thanh ngang để so sánh vài giá trị (dùng ở tab hiệu năng). */
  function barRows(title, rows, unit) {
    const W = 520, rowH = 40, L = 175, R = 120, T = 34;
    const H = T + rows.length * rowH + 8;
    const max = Math.max(...rows.map((r) => r.value)) || 1;
    let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${title}"><text x="0" y="20" font-size="15" font-weight="700" fill="#e9f2ff">${title}</text>`;
    rows.forEach((r, i) => {
      const yy = T + i * rowH;
      const w = Math.max(2, (W - L - R) * (r.value / max));
      s += `<text x="${L - 8}" y="${yy + 23}" font-size="14" text-anchor="end" fill="#c7d5e6">${r.label}</text>`;
      s += `<rect x="${L}" y="${yy + 7}" width="${w}" height="24" rx="4" fill="${r.color}"/>`;
      s += `<text x="${L + w + 6}" y="${yy + 23}" font-size="14" font-weight="600" fill="#dce7f5">${r.text || r.value.toFixed(2) + ' ' + unit}</text>`;
    });
    return s + '</svg>';
  }
  window.__app.columnChart = columnChart;
  window.__app.barRows = barRows;

  // avalanche
  $('#av-run').on('click', async function () {
    const $b = $(this).prop('disabled', true).text('Đang chạy…');
    await nextFrame();
    try {
      const size = Number($('#av-size').val());
      const what = $('#av-what').val();
      const trials = Number($('#av-n').val());
      let sums = null;
      for (let t = 0; t < trials; t++) {
        const key = U.randomBytes(size), pt = U.randomBytes(16);
        const key2 = Uint8Array.from(key), pt2 = Uint8Array.from(pt);
        if (what === 'plain') { const bit = Math.floor(Math.random() * 128); pt2[bit >> 3] ^= 1 << (bit & 7); }
        else { const bit = Math.floor(Math.random() * size * 8); key2[bit >> 3] ^= 1 << (bit & 7); }
        const tr1 = [], tr2 = [];
        AES.encryptBlock(pt, AES.expandKey(key).roundKeys, tr1);
        AES.encryptBlock(pt2, AES.expandKey(key2).roundKeys, tr2);
        const a = tr1.filter((s) => s.step === 'AddRoundKey'), b = tr2.filter((s) => s.step === 'AddRoundKey');
        if (!sums) sums = new Array(a.length).fill(0);
        a.forEach((s, i) => { sums[i] += U.countDiffBits(s.state, b[i].state); });
        if (t % 100 === 99) await nextFrame();
      }
      const avg = sums.map((s) => s / trials);
      $('#av-chart').html(columnChart({
        title: `Số bit State khác nhau sau mỗi vòng (trung bình ${trials} lần, đổi 1 bit ${what === 'plain' ? 'bản rõ' : 'khóa'})`,
        labels: avg.map((_, i) => String(i)), values: avg, color: '#2ee6d6', max: 80, refLine: 64, refLabel: '64 bit = 50%', xTitle: `Vòng AES-${size * 8}`,
      }) + `<p class="note mt-2">Sau vòng 1 chỉ khoảng ${avg[1].toFixed(0)} bit khác. Từ vòng 2 trở đi đạt khoảng ${avg[2].toFixed(0)}/128 bit: một bit đầu vào đã ảnh hưởng đến toàn khối.</p>`);
    } catch (err) {
      $('#av-chart').html(`<p class="status err">${err.message}</p>`);
    } finally { $b.prop('disabled', false).text('Chạy thí nghiệm'); }
  });

  // ECB vs CBC
  function drawDefault(ctx) {
    ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, 200, 200);
    ctx.fillStyle = '#0b1a33'; ctx.beginPath(); ctx.arc(100, 100, 84, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = '#c2841a'; ctx.fillRect(58, 92, 84, 64);
    ctx.strokeStyle = '#c2841a'; ctx.lineWidth = 14; ctx.beginPath(); ctx.arc(100, 88, 28, Math.PI, 0); ctx.lineTo(128, 96); ctx.moveTo(72, 88); ctx.lineTo(72, 96); ctx.stroke();
    ctx.fillStyle = '#0b1a33'; ctx.beginPath(); ctx.arc(100, 116, 9, 0, Math.PI * 2); ctx.fill(); ctx.fillRect(96, 118, 8, 22);
  }
  const src = document.getElementById('img-src').getContext('2d', { willReadFrequently: true });
  drawDefault(src);

  function encryptCanvas(mode) {
    const img = src.getImageData(0, 0, 200, 200);
    const rgb = new Uint8Array(200 * 200 * 3);
    for (let i = 0, j = 0; i < img.data.length; i += 4) { rgb[j++] = img.data[i]; rgb[j++] = img.data[i + 1]; rgb[j++] = img.data[i + 2]; }
    const padded = new Uint8Array(Math.ceil(rgb.length / 16) * 16); padded.set(rgb);
    const key = encryptCanvas.key || (encryptCanvas.key = U.randomBytes(16));
    const out = mode === 'ECB' ? Modes.ecbEncrypt(padded, key, { pad: false }) : Modes.cbcEncrypt(padded, key, U.randomBytes(16), { pad: false });
    const res = new ImageData(200, 200);
    for (let i = 0, j = 0; i < res.data.length; i += 4) { res.data[i] = out[j++]; res.data[i + 1] = out[j++]; res.data[i + 2] = out[j++]; res.data[i + 3] = 255; }
    return res;
  }

  $('#img-run').on('click', async function () {
    const $b = $(this).prop('disabled', true).text('Đang mã hóa…');
    await nextFrame();
    try {
      encryptCanvas.key = U.randomBytes(16);
      document.getElementById('img-ecb').getContext('2d').putImageData(encryptCanvas('ECB'), 0, 0);
      document.getElementById('img-cbc').getContext('2d').putImageData(encryptCanvas('CBC'), 0, 0);
    } finally { $b.prop('disabled', false).text('Mã hóa ảnh'); }
  });

  $('#img-file').on('change', function () {
    const file = this.files[0];
    if (!file) return;
    const im = new Image();
    im.onload = () => {
      const s = Math.min(im.width, im.height);
      src.fillStyle = '#fff'; src.fillRect(0, 0, 200, 200);
      src.drawImage(im, (im.width - s) / 2, (im.height - s) / 2, s, s, 0, 0, 200, 200);
      URL.revokeObjectURL(im.src);
      $('#img-run').trigger('click');
    };
    im.src = URL.createObjectURL(file);
  });
});
