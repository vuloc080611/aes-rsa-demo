/* Visual effects only. This file does not read or modify cryptographic state. */
(function () {
  'use strict';

  var root = document.documentElement;
  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  var finePointer = window.matchMedia('(hover: hover) and (pointer: fine)');
  var currentView = document.querySelector('[data-current-view]');
  var cursorGlow = document.querySelector('.cursor-glow');
  var revealObserver = null;

  root.classList.add('js-effects');

  var viewNames = {
    '#tab-app': 'file-encryption',
    '#tab-rsa': 'rsa-workbench',
    '#tab-aes': 'aes-workbench',
    '#tab-visual': 'visual-analysis',
    '#tab-hybrid': 'hybrid-cipher',
    '#tab-tests': 'verification-suite'
  };

  function setCurrentView(target) {
    if (currentView && viewNames[target]) currentView.textContent = viewNames[target];
  }

  function replayPaneTransition(pane) {
    if (!pane || reduceMotion.matches) return;
    pane.classList.remove('ui-entering');
    void pane.offsetWidth;
    pane.classList.add('ui-entering');
    window.setTimeout(function () {
      pane.classList.remove('ui-entering');
    }, 850);
  }

  function revealElement(element, index) {
    if (element.dataset.fxReveal === 'ready') return;
    element.dataset.fxReveal = 'ready';
    element.classList.add('reveal-ready');
    element.style.setProperty('--reveal-delay', Math.min(index * 55, 275) + 'ms');
    if (reduceMotion.matches || !revealObserver) element.classList.add('reveal-visible');
    else revealObserver.observe(element);
  }

  function setupReveal() {
    if ('IntersectionObserver' in window && !reduceMotion.matches) {
      revealObserver = new IntersectionObserver(function (entries, observer) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.classList.add('reveal-visible');
          observer.unobserve(entry.target);
        });
      }, { rootMargin: '0px 0px -7% 0px', threshold: 0.08 });
    }

    document.querySelectorAll('.tab-pane').forEach(function (pane) {
      pane.querySelectorAll('.panel, .seg, .enc-map, .flow, .img-row').forEach(function (element, index) {
        revealElement(element, index);
      });
    });
  }

  function revealActivePane(pane) {
    if (!pane) return;
    pane.querySelectorAll('.reveal-ready').forEach(function (element) {
      if (reduceMotion.matches || !revealObserver) element.classList.add('reveal-visible');
      else revealObserver.observe(element);
    });
  }

  function setupTabs() {
    document.querySelectorAll('[data-bs-toggle="tab"]').forEach(function (trigger) {
      trigger.addEventListener('shown.bs.tab', function (event) {
        var target = event.target.getAttribute('data-bs-target');
        var pane = target ? document.querySelector(target) : null;
        setCurrentView(target);
        replayPaneTransition(pane);
        revealActivePane(pane);
      });
    });

    var activeTrigger = document.querySelector('.side-nav .nav-link.active');
    var activeTarget = activeTrigger && activeTrigger.getAttribute('data-bs-target');
    setCurrentView(activeTarget);
    var activePane = document.querySelector('.tab-pane.show.active');
    replayPaneTransition(activePane);
    revealActivePane(activePane);
  }

  function setupPanelSpotlights() {
    if (!finePointer.matches || reduceMotion.matches) return;
    document.querySelectorAll('.panel').forEach(function (panel) {
      panel.addEventListener('pointermove', function (event) {
        var rect = panel.getBoundingClientRect();
        var x = ((event.clientX - rect.left) / rect.width) * 100;
        var y = ((event.clientY - rect.top) / rect.height) * 100;
        panel.style.setProperty('--mx', x.toFixed(1) + '%');
        panel.style.setProperty('--my', y.toFixed(1) + '%');
      }, { passive: true });

      panel.addEventListener('pointerleave', function () {
        panel.style.setProperty('--mx', '50%');
        panel.style.setProperty('--my', '0%');
      }, { passive: true });
    });
  }

  function setupCursorGlow() {
    if (!cursorGlow || !finePointer.matches || reduceMotion.matches) return;
    var queued = false;
    var x = window.innerWidth * 0.7;
    var y = window.innerHeight * 0.2;

    window.addEventListener('pointermove', function (event) {
      x = event.clientX;
      y = event.clientY;
      if (queued) return;
      queued = true;
      window.requestAnimationFrame(function () {
        cursorGlow.style.setProperty('--pointer-x', x + 'px');
        cursorGlow.style.setProperty('--pointer-y', y + 'px');
        queued = false;
      });
    }, { passive: true });
  }

  function setupRipples() {
    document.addEventListener('click', function (event) {
      var button = event.target.closest('.btn');
      if (!button || button.disabled || reduceMotion.matches) return;
      var rect = button.getBoundingClientRect();
      var ripple = document.createElement('span');
      ripple.className = 'ui-ripple';
      ripple.style.left = (event.clientX - rect.left) + 'px';
      ripple.style.top = (event.clientY - rect.top) + 'px';
      button.appendChild(ripple);
      ripple.addEventListener('animationend', function () { ripple.remove(); }, { once: true });
    });
  }

  function setupLattice() {
    var canvas = document.getElementById('crypto-lattice');
    if (!canvas || reduceMotion.matches) return;
    var context = canvas.getContext('2d');
    if (!context) return;

    var nodes = [];
    var width = 0;
    var height = 0;
    var frame = 0;
    var active = !document.hidden;
    var dpr = Math.min(window.devicePixelRatio || 1, 1.5);

    function makeNode() {
      var angle = Math.random() * Math.PI * 2;
      var speed = 0.08 + Math.random() * 0.2;
      return {
        x: Math.random() * width,
        y: Math.random() * height,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        r: 0.7 + Math.random() * 1.35,
        color: Math.random() > 0.68 ? '155,140,255' : '46,230,214'
      };
    }

    function resize() {
      width = window.innerWidth;
      height = window.innerHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      canvas.style.width = width + 'px';
      canvas.style.height = height + 'px';
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      var count = Math.max(24, Math.min(58, Math.round((width * height) / 28000)));
      nodes = Array.from({ length: count }, makeNode);
    }

    function draw() {
      if (!active) return;
      context.clearRect(0, 0, width, height);

      for (var i = 0; i < nodes.length; i += 1) {
        var node = nodes[i];
        node.x += node.vx;
        node.y += node.vy;
        if (node.x < -10) node.x = width + 10;
        if (node.x > width + 10) node.x = -10;
        if (node.y < -10) node.y = height + 10;
        if (node.y > height + 10) node.y = -10;

        context.beginPath();
        context.arc(node.x, node.y, node.r, 0, Math.PI * 2);
        context.fillStyle = 'rgba(' + node.color + ',.52)';
        context.shadowColor = 'rgba(' + node.color + ',.62)';
        context.shadowBlur = 8;
        context.fill();
        context.shadowBlur = 0;

        for (var j = i + 1; j < nodes.length; j += 1) {
          var other = nodes[j];
          var dx = node.x - other.x;
          var dy = node.y - other.y;
          var distance = Math.sqrt(dx * dx + dy * dy);
          if (distance > 132) continue;
          var opacity = (1 - distance / 132) * 0.12;
          context.beginPath();
          context.moveTo(node.x, node.y);
          context.lineTo(other.x, other.y);
          context.strokeStyle = 'rgba(91,208,222,' + opacity.toFixed(3) + ')';
          context.lineWidth = 0.6;
          context.stroke();
        }
      }

      frame = window.requestAnimationFrame(draw);
    }

    var resizeQueued = false;
    window.addEventListener('resize', function () {
      if (resizeQueued) return;
      resizeQueued = true;
      window.requestAnimationFrame(function () {
        resize();
        resizeQueued = false;
      });
    }, { passive: true });

    document.addEventListener('visibilitychange', function () {
      active = !document.hidden;
      if (!active) {
        window.cancelAnimationFrame(frame);
        frame = 0;
      } else if (!frame) {
        draw();
      }
    });

    reduceMotion.addEventListener('change', function (event) {
      if (!event.matches) return;
      active = false;
      window.cancelAnimationFrame(frame);
      context.clearRect(0, 0, width, height);
      canvas.hidden = true;
    });

    resize();
    draw();
  }

  setupReveal();
  setupTabs();
  setupPanelSpotlights();
  setupCursorGlow();
  setupRipples();
  setupLattice();
}());
