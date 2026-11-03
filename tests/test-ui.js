/* global QUnit */
(function () {
  'use strict';

  var tests = 0;
  var assertions = 0;
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var testsMetric = document.getElementById('metric-tests');
  var assertionsMetric = document.getElementById('metric-assertions');
  var failedMetric = document.getElementById('metric-failed');
  var runtimeMetric = document.getElementById('metric-runtime');
  var state = document.querySelector('.test-run-state');
  var stateTitle = document.getElementById('run-state-title');
  var stateCopy = document.getElementById('run-state-copy');

  function setText(element, value) {
    if (element) element.textContent = String(value);
  }

  function animateNumber(element, value) {
    if (!element || reducedMotion || value < 2) {
      setText(element, value);
      return;
    }

    var started = performance.now();
    var duration = 520;
    function tick(now) {
      var progress = Math.min((now - started) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      setText(element, Math.round(value * eased));
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  QUnit.begin(function () {
    if (stateTitle) stateTitle.textContent = 'ĐANG KIỂM THỬ';
    if (stateCopy) stateCopy.textContent = 'Đang chạy vector chuẩn NIST và RFC...';
    setText(testsMetric, 0);
    setText(assertionsMetric, 0);
    setText(failedMetric, 0);
    setText(runtimeMetric, '...');
  });

  QUnit.testDone(function (details) {
    tests += 1;
    assertions += details.total || 0;
    setText(testsMetric, tests);
    setText(assertionsMetric, assertions);
    setText(failedMetric, details.failed ? Number(failedMetric.textContent || 0) + details.failed : failedMetric.textContent || 0);
  });

  QUnit.done(function (details) {
    animateNumber(testsMetric, tests);
    animateNumber(assertionsMetric, details.total || assertions);
    animateNumber(failedMetric, details.failed || 0);
    animateNumber(runtimeMetric, details.runtime || 0);

    if (!state) return;
    state.classList.remove('is-pass', 'is-fail');
    if (details.failed > 0) {
      state.classList.add('is-fail');
      if (stateTitle) stateTitle.textContent = 'PHÁT HIỆN LỖI';
      if (stateCopy) stateCopy.textContent = details.failed + ' assertion chưa đạt — mở test để xem chi tiết.';
    } else {
      state.classList.add('is-pass');
      if (stateTitle) stateTitle.textContent = 'TẤT CẢ ĐÃ ĐẠT';
      if (stateCopy) stateCopy.textContent = (details.total || assertions) + ' assertion được xác minh thành công.';
    }
  });
}());
