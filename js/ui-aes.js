/* global $, CryptoUtils, AES, Modes, WebCryptoLib */
/** ui-aes.js — Tab AES: mã hóa/giải mã văn bản và xem State 4×4 qua từng bước. */
$(function () {
  'use strict';
  const U = CryptoUtils;
  const { esc, setStatus, fail, hexGroups } = window.__app;

  const NIST_KEY = '2b7e151628aed2a6abf7158809cf4f3c';
  // Vector chuẩn để gắn nhãn "khớp NIST" ở chế độ một khối
  const KNOWN = [
    { key: NIST_KEY, pt: '3243f6a8885a308d313198a2e0370734', ct: '3925841d02dc09fbdc118597196a0b32', src: 'FIPS 197 Phụ lục B' },
    { key: '000102030405060708090a0b0c0d0e0f', pt: '00112233445566778899aabbccddeeff', ct: '69c4e0d86a7b0430d8cdb78070b4c55a', src: 'FIPS 197 Phụ lục C.1' },
    { key: '000102030405060708090a0b0c0d0e0f1011121314151617', pt: '00112233445566778899aabbccddeeff', ct: 'dda97ca4864cdfe06eaf70a0ec0d7191', src: 'FIPS 197 Phụ lục C.2' },
    { key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', pt: '00112233445566778899aabbccddeeff', ct: '8ea2b7ca516745bfeafc49904b496089', src: 'FIPS 197 Phụ lục C.3' },
  ];

  const DESC = {
    Input: 'Khối 16 byte nạp vào State theo cột: byte 0–3 thành cột 0, byte 4–7 thành cột 1…',
    AddRoundKey: 'XOR từng byte của State với khóa vòng. Đây là bước duy nhất trộn khóa vào dữ liệu.',
    SubBytes: 'Thay mỗi byte qua S-box (nghịch đảo trong GF(2⁸) rồi biến đổi affine). Thành phần phi tuyến, tạo tính gây lẫn.',
    ShiftRows: 'Dịch vòng trái hàng r đi r byte. Các byte của một cột được rải sang các cột khác.',
    MixColumns: 'Nhân mỗi cột với ma trận [02 03 01 01] trong GF(2⁸). Mỗi byte ra phụ thuộc cả 4 byte của cột.',
    InvShiftRows: 'Dịch vòng phải hàng r đi r byte, đảo lại ShiftRows.',
    InvSubBytes: 'Tra S-box ngược để đưa từng byte về giá trị trước SubBytes.',
    InvMixColumns: 'Nhân mỗi cột với ma trận [0E 0B 0D 09], đảo lại MixColumns.',
  };

  function keyBytes() {
    const size = Number($('#ae-size').val());
    const raw = $('#ae-key').val().trim();
    const key = U.hexToBytes(raw);
    if (key.length !== size) throw new Error(`Khóa AES-${size * 8} cần đúng ${size * 2} ký tự hex, hiện có ${raw.replace(/\s+/g, '').length}.`);
    return key;
  }

  function updateLabels() {
    const mode = $('#ae-mode').val();
    const size = Number($('#ae-size').val());
    $('#ae-key-help').text(`${size * 2} ký tự hex = ${size} byte = ${size * 8} bit. AES-${size * 8} có ${{ 16: 10, 24: 12, 32: 14 }[size]} vòng.`);
    if (mode === 'BLOCK') {
      $('#ae-plain-label').text('Khối bản rõ (32 ký tự hex, không padding)');
      $('#ae-cipher-label').text('Khối bản mã (hex)');
    } else {
      $('#ae-plain-label').text('Bản rõ');
      $('#ae-cipher-label').text(mode === 'ECB' ? 'Bản mã (Base64)' : 'Bản mã (Base64 của IV ‖ bản mã)');
    }
  }

  $('#ae-size').on('change', () => {
    const size = Number($('#ae-size').val());
    const cur = $('#ae-key').val().replace(/\s+/g, '');
    if (cur.length !== size * 2) $('#ae-key').val(U.bytesToHex(U.randomBytes(size)));
    updateLabels();
  });
  $('#ae-mode').on('change', () => {
    if ($('#ae-mode').val() === 'BLOCK' && !/^[0-9a-f\s]{32,}$/i.test($('#ae-plain').val())) $('#ae-plain').val('3243f6a8885a308d313198a2e0370734');
    if ($('#ae-mode').val() !== 'BLOCK' && /^[0-9a-f]{32}$/i.test($('#ae-plain').val().trim())) $('#ae-plain').val('Xin chào thầy và các bạn!');
    $('#ae-cipher').val('');
    updateLabels();
  });
  $('#ae-randkey').on('click', () => $('#ae-key').val(U.bytesToHex(U.randomBytes(Number($('#ae-size').val())))));
  $('#ae-nist').on('click', () => {
    $('#ae-size').val('16'); $('#ae-mode').val('BLOCK');
    $('#ae-key').val(NIST_KEY); $('#ae-plain').val('3243f6a8885a308d313198a2e0370734');
    updateLabels();
    encrypt();
  });

  //  mã hóa
  async function encrypt() {
    $('#ae-compare').empty();
    try {
      const key = keyBytes();
      const mode = $('#ae-mode').val();
      const { roundKeys, steps } = AES.expandKey(key);
      const trace = [];
      let firstNote = '';
      if (mode === 'BLOCK') {
        const block = U.hexToBytes($('#ae-plain').val());
        if (block.length !== 16) throw new Error('Chế độ một khối cần đúng 32 ký tự hex (16 byte).');
        const ct = AES.encryptBlock(block, roundKeys, trace);
        $('#ae-cipher').val(U.bytesToHex(ct));
        const hit = KNOWN.find((v) => v.key === U.bytesToHex(key) && v.pt === U.bytesToHex(block));
        setStatus('#ae-status', 'ok', `Bản mã: <span class="mono">${U.bytesToHex(ct)}</span>`);
        $('#ae-compare').attr('class', `compare mt-2 ${hit ? 'ok' : 'na'}`).html(hit
          ? (hit.ct === U.bytesToHex(ct) ? `Khớp đúng bản mã chuẩn trong ${hit.src}.` : `Không khớp ${hit.src}.`)
          : 'Đầu vào tùy chọn: chưa có bản mã chuẩn để đối chiếu.');
        firstNote = 'Khối đầu vào chính là khối bản rõ.';
      } else {
        const data = U.utf8Encode($('#ae-plain').val());
        const iv = U.randomBytes(16);
        let ct, firstBlock;
        if (mode === 'CBC') {
          ct = Modes.cbcEncrypt(data, key, iv);
          firstBlock = U.xorBytes(Modes.pkcs7Pad(data).subarray(0, 16), iv);
          firstNote = 'Khối đưa vào AES là P₁ ⊕ IV (CBC).';
        } else if (mode === 'CTR') {
          ct = Modes.ctrCrypt(data, key, iv);
          firstBlock = iv;
          firstNote = 'Ở CTR, AES mã hóa bộ đếm (giá trị khởi tạo là IV) để sinh dòng khóa, rồi XOR với bản rõ.';
        } else {
          ct = Modes.ecbEncrypt(data, key);
          firstBlock = Modes.pkcs7Pad(data).subarray(0, 16);
          firstNote = 'ECB mã hóa từng khối độc lập, khối đầu vào là P₁.';
        }
        AES.encryptBlock(firstBlock, roundKeys, trace);
        const out = mode === 'ECB' ? ct : U.concatBytes(iv, ct);
        $('#ae-cipher').val(U.bytesToBase64(out));
        setStatus('#ae-status', 'ok', `Đã mã hóa ${data.length} byte thành ${ct.length} byte bản mã (${ct.length / 16 | 0}${ct.length % 16 ? '+' : ''} khối)${mode === 'ECB' ? '' : ', IV ngẫu nhiên được ghép ở đầu'}.`);
        await compareWithLibrary(mode, data, key, iv, ct);
      }
      renderStepper(trace, roundKeys, steps, 'enc', firstNote, key.length);
    } catch (err) { fail('#ae-status', err); }
  }

  async function compareWithLibrary(mode, data, key, iv, ct) {
    const $c = $('#ae-compare');
    if (mode === 'ECB') {
      $c.attr('class', 'compare na mt-2').text('Web Crypto không hỗ trợ ECB vì chế độ này không an toàn. ECB được đối chiếu bằng dữ liệu NIST trong tab Kiểm thử.');
      return;
    }
    if (key.length === 24) {
      $c.attr('class', 'compare na mt-2').text('Web Crypto trên Chrome, Edge không hỗ trợ khóa 192 bit. AES-192 được đối chiếu bằng dữ liệu NIST (FIPS 197 C.2, SP 800-38A) trong tab Kiểm thử.');
      return;
    }
    try {
      const lib = mode === 'CBC' ? await WebCryptoLib.aesCbcEncrypt(data, key, iv) : await WebCryptoLib.aesCtr(data, key, iv);
      const same = U.bytesEqual(lib, ct);
      $c.attr('class', `compare mt-2 ${same ? 'ok' : ''}`).text(same
        ? `Web Crypto (thư viện chuẩn của trình duyệt) cho ra bản mã giống từng byte với cùng khóa và IV.`
        : 'Bản mã khác với Web Crypto. Cần kiểm tra lại.');
    } catch (e) {
      $c.attr('class', 'compare na mt-2').text(`Không gọi được Web Crypto: ${e.message}`);
    }
  }

  //  giải mã
  function decrypt() {
    $('#ae-compare').empty();
    try {
      const key = keyBytes();
      const mode = $('#ae-mode').val();
      const { roundKeys, steps } = AES.expandKey(key);
      const trace = [];
      let note = '';
      if (mode === 'BLOCK') {
        const block = U.hexToBytes($('#ae-cipher').val());
        if (block.length !== 16) throw new Error('Chế độ một khối cần bản mã đúng 32 ký tự hex.');
        const pt = AES.decryptBlock(block, roundKeys, trace);
        $('#ae-plain').val(U.bytesToHex(pt));
        setStatus('#ae-status', 'ok', `Giải mã ra khối: <span class="mono">${U.bytesToHex(pt)}</span>`);
        note = 'Giải mã đi ngược: khóa vòng dùng từ cuối về đầu.';
        renderStepper(trace, roundKeys, steps, 'dec', note, key.length);
        return;
      }
      const raw = U.base64ToBytes($('#ae-cipher').val());
      let plain;
      if (mode === 'ECB') {
        plain = Modes.ecbDecrypt(raw, key);
        AES.decryptBlock(raw.subarray(0, 16), roundKeys, trace);
        note = 'Khối đầu tiên của bản mã được giải mã độc lập.';
      } else {
        if (raw.length < 17) throw new Error('Bản mã quá ngắn: cần 16 byte IV và ít nhất 1 byte dữ liệu.');
        const iv = raw.subarray(0, 16), ct = raw.subarray(16);
        if (mode === 'CBC') {
          plain = Modes.cbcDecrypt(ct, key, iv);
          AES.decryptBlock(ct.subarray(0, 16), roundKeys, trace);
          note = 'Khối đầu được giải mã bằng AES ngược, sau đó XOR với IV để ra P₁.';
        } else {
          plain = Modes.ctrCrypt(ct, key, iv);
          AES.encryptBlock(iv, roundKeys, trace);
          note = 'CTR giải mã bằng chính phép mã hóa bộ đếm, nên ở đây vẫn là AES chiều thuận.';
        }
      }
      let text;
      try { text = U.utf8Decode(plain); } catch (e) { throw new Error('Giải mã ra dữ liệu không phải văn bản UTF-8 hợp lệ. Thường do sai khóa hoặc sai chế độ.'); }
      $('#ae-plain').val(text);
      setStatus('#ae-status', 'ok', `Giải mã thành công ${plain.length} byte. Bản rõ đã được đưa vào ô phía trên.`);
      renderStepper(trace, roundKeys, steps, mode === 'CTR' ? 'enc' : 'dec', note, key.length);
    } catch (err) { fail('#ae-status', err); }
  }

  $('#ae-encrypt').on('click', encrypt);
  $('#ae-decrypt').on('click', decrypt);

  //  State stepper
  function cellStyle(v) {
    // thang màu xanh ngọc: byte càng lớn càng đậm
    const t = v / 255;
    const mix = (a, b) => Math.round(a + (b - a) * t);
    const bg = `rgb(${mix(230, 10)}, ${mix(244, 95)}, ${mix(243, 94)})`;
    return `background:${bg};color:${v > 135 ? '#fff' : '#12304a'}`;
  }

  function gridHtml(bytes, prev) {
    let html = '';
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) {
        const i = r + 4 * c;
        const changed = prev && prev[i] !== bytes[i];
        html += `<div class="cell${changed ? ' changed' : ''}" style="${cellStyle(bytes[i])}" title="hàng ${r}, cột ${c}">${bytes[i].toString(16).padStart(2, '0')}</div>`;
      }
    }
    return html;
  }

  function renderStepper(trace, roundKeys, steps, dir, note, keyLen) {
    const Nr = roundKeys.length - 1;
    const g = steps.find((s) => s.kind === 'g');
    const keyRows = roundKeys.map((k, i) => `<div class="rk" data-rk="${i}">K${String(i).padStart(2, '0')} ${hexGroups(k)}</div>`).join('');
    const $d = $('#ae-detail').html(`
      <p class="note">${esc(note)} AES-${keyLen * 8}: ${Nr} vòng, ${roundKeys.length} khóa vòng. Ô có viền đậm là byte vừa thay đổi.</p>
      <div class="stepper">
        <div><div class="state-grid" id="ae-grid"></div>
          <div class="legend-scale"><span>00</span><span class="bar"></span><span>ff</span></div></div>
        <div>
          <div class="step-head" id="ae-step-head"></div>
          <p class="step-desc" id="ae-step-desc"></p>
          <div class="mono small-mono" id="ae-step-hex"></div>
        </div>
      </div>
      <div class="step-controls">
        <button class="btn btn-outline-accent btn-sm" id="ae-prev" aria-label="Bước trước">‹</button>
        <input type="range" id="ae-range" min="0" max="${trace.length - 1}" value="0" aria-label="Chọn bước">
        <button class="btn btn-outline-accent btn-sm" id="ae-next" aria-label="Bước sau">›</button>
        <button class="btn btn-accent btn-sm" id="ae-play">Chạy</button>
      </div>
      <h3>Khóa vòng (Key Expansion)</h3>
      <p class="note">Ví dụ word w${g.i}: RotWord(${hexGroups(g.prev)}) = ${hexGroups(g.rot)}, SubWord → ${hexGroups(g.sub)}, XOR Rcon ${g.rcon.toString(16).padStart(2, '0')} → ${hexGroups(g.afterRcon)}, XOR w${g.i - keyLen / 4} → <b>${hexGroups(g.result)}</b>.</p>
      <div class="round-keys">${keyRows}</div>`);

    let timer = null;
    function show(i) {
      const t = trace[i];
      const prev = i > 0 ? trace[i - 1].state : null;
      $('#ae-grid').html(gridHtml(t.state, prev));
      const roundLabel = t.step === 'Input' ? 'Đầu vào' : `Vòng ${t.round}`;
      $('#ae-step-head').text(t.step === 'Input' ? 'Đầu vào: khối 16 byte' : `${roundLabel}: ${t.step}${t.round === Nr && t.step === 'ShiftRows' && dir === 'enc' ? ' (vòng cuối bỏ MixColumns)' : ''}`);
      $('#ae-step-desc').text(DESC[t.step]);
      $('#ae-step-hex').text(hexGroups(t.state));
      $('#ae-range').val(i);
      $d.find('.rk').removeClass('on');
      if (t.step === 'AddRoundKey') $d.find(`.rk[data-rk="${t.round}"]`).addClass('on');
    }
    show(0);
    $('#ae-range').on('input', function () { show(Number(this.value)); });
    $('#ae-prev').on('click', () => show(Math.max(0, Number($('#ae-range').val()) - 1)));
    $('#ae-next').on('click', () => show(Math.min(trace.length - 1, Number($('#ae-range').val()) + 1)));
    $('#ae-play').on('click', function () {
      if (timer) { clearInterval(timer); timer = null; $(this).text('Chạy'); return; }
      $(this).text('Dừng');
      let i = Number($('#ae-range').val());
      if (i >= trace.length - 1) i = -1;
      timer = setInterval(() => {
        i++;
        show(i);
        if (i >= trace.length - 1) { clearInterval(timer); timer = null; $('#ae-play').text('Chạy'); }
      }, 650);
    });
  }

  // khởi tạo
  $('#ae-key').val(NIST_KEY);
  updateLabels();
});
