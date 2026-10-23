(function () {
  'use strict';

  var STATS_URL = 'api/omk/index.php?action=stats';
  var devicesEl = document.getElementById('omk-devices');
  var metaEl = document.getElementById('omk-meta');
  var timer = null;

  function fmt(n) {
    if (!isFinite(n)) return '0';
    return n.toLocaleString('zh-CN');
  }

  function refresh() {
    fetch(STATS_URL, { cache: 'no-store', referrerPolicy: 'no-referrer' })
      .then(function (res) {
        if (!res.ok) throw new Error('stats ' + res.status);
        return res.json();
      })
      .then(function (data) {
        var devices = parseInt(data.devices, 10);
        if (!isFinite(devices) || devices < 0) devices = 0;
        devicesEl.textContent = fmt(devices);
        var keybox = parseInt(data.keybox_distinct, 10) || 0;
        metaEl.textContent = 'PIF 指纹已下发 ' + fmt(parseInt(data.pif, 10) || 0) +
          ' 次 · 在线 Keybox ' + fmt(keybox) +
          ' 种 · 统计于 ' + (data.updated_at || '');
      })
      .catch(function () {
        devicesEl.textContent = '…';
        metaEl.textContent = '统计暂不可用';
      });
  }

  refresh();
  timer = setInterval(refresh, 3000);
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) refresh();
  });
  window.addEventListener('focus', refresh);
})();