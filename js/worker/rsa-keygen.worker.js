/**
 * rsa-keygen.worker.js — Sinh khóa RSA trong luồng nền để giao diện không bị đứng.
 * Nhận { bits }, gửi về các thông báo tiến độ và cuối cùng là khóa.
 */
/* global importScripts, RSA */
importScripts('../core/utils.js', '../core/rsa.js');

self.onmessage = (event) => {
  const { bits } = event.data;
  const t0 = performance.now();
  try {
    const key = RSA.generateKeyPair(bits, 65537n, (p) => self.postMessage({ type: 'progress', progress: p }));
    const { euclid, ...rest } = key;
    self.postMessage({ type: 'done', key: rest, ms: performance.now() - t0 });
  } catch (err) {
    self.postMessage({ type: 'error', message: err.message });
  }
};
