/* global $ */
/** ui-shell.js — Khung giao diện: vùng kéo thả file, cuộn lên đầu khi đổi trang. Không chứa thuật toán. */
$(function () {
  'use strict';
  const size = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB');

  $('.drop').each(function () {
    const $drop = $(this);
    const input = $drop.find('.drop-input')[0];
    const $name = $drop.find('.drop-file');
    const empty = $name.text();
    const show = () => {
      const f = input.files[0];
      $drop.toggleClass('has-file', !!f);
      $name.text(f ? `${f.name} (${size(f.size)})` : empty);
    };
    $(input).on('change', show);
    $drop.on('dragover dragenter', (e) => { e.preventDefault(); $drop.addClass('is-over'); });
    $drop.on('dragleave dragend drop', () => $drop.removeClass('is-over'));
    $drop.on('drop', (e) => {
      e.preventDefault();
      const files = e.originalEvent.dataTransfer.files;
      if (files.length) { input.files = files; show(); }
    });
  });

  // Đổi trang: đưa nội dung về đầu để người xem thấy tiêu đề trang mới
  $('.side-nav .nav-link').on('shown.bs.tab', () => window.scrollTo({ top: 0, behavior: 'auto' }));
});
