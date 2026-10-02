/* Additive level-up. Leaves existing chat functions in place. */
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }
  function toast(t) { if (typeof showToast === 'function') showToast(t); }

  function statusEl() {
    var el = $('ym-level-status');
    if (!el) {
      el = document.createElement('div');
      el.id = 'ym-level-status';
      el.innerHTML = '<span class="dot"></span><span class="tx">確認中</span>';
      document.body.appendChild(el);
    }
    return el;
  }
  function paintStatus() {
    var el = statusEl();
    var tx = el.querySelector('.tx');
    var online = navigator.onLine;
    var peerState = '未接続';
    try {
      if (typeof peer !== 'undefined' && peer && peer.open) peerState = 'P2P接続';
      else if (typeof peer !== 'undefined' && peer) peerState = 'P2P接続中';
    } catch (e) {}
    el.className = online ? (peerState === 'P2P接続' ? 'ok' : 'warn') : 'bad';
    tx.textContent = (online ? 'オンライン' : 'オフライン') + ' / ' + peerState;
  }

  function draftKey() {
    var id = (typeof activeUserId !== 'undefined' && activeUserId) ? String(activeUserId) : 'none';
    var room = (typeof activeChatId !== 'undefined' && activeChatId) ? String(activeChatId) : id;
    return 'YM_DRAFT_' + room;
  }
  function bindDraft() {
    var input = $('chat-input');
    if (!input || input.dataset.ymLevelDraft === '1') return;
    input.dataset.ymLevelDraft = '1';
    try { if (!input.value) input.value = localStorage.getItem(draftKey()) || ''; } catch (e) {}
    input.addEventListener('input', function () {
      input.style.height = 'auto';
      input.style.height = Math.min(96, input.scrollHeight) + 'px';
      try { localStorage.setItem(draftKey(), input.value.slice(0, 4000)); } catch (e) {}
    });
    var send = $('btn-chat-send');
    if (send) send.addEventListener('click', function () {
      setTimeout(function () { try { localStorage.removeItem(draftKey()); } catch (e) {} }, 50);
    });
  }

  function onePanel() {
    var plus = $('btn-composer-plus');
    var stamp = $('btn-chat-stamp');
    if (plus && !plus.dataset.ymLevel) {
      plus.dataset.ymLevel = '1';
      plus.addEventListener('click', function () {
        var sk = document.querySelector('.stamp-keyboard-container.active');
        if (sk) sk.classList.remove('active');
      });
    }
    if (stamp && !stamp.dataset.ymLevel) {
      stamp.dataset.ymLevel = '1';
      stamp.addEventListener('click', function () {
        var extra = $('composer-extra-tools');
        if (extra) extra.classList.remove('active');
      });
    }
  }

  function emptyHint() {
    var list = document.querySelector('.friend-list');
    if (!list || list.querySelector('.ym-empty-hint')) return;
    if (list.children.length > 0) return;
    var hint = document.createElement('div');
    hint.className = 'ym-empty-hint';
    hint.textContent = 'まだトークがありません。友だちを追加すると、ここに並びます。';
    list.appendChild(hint);
  }

  function badge() {
    try {
      if (!navigator.setAppBadge) return;
      var n = document.querySelectorAll('.unread-badge').length;
      if (n) navigator.setAppBadge(n); else navigator.clearAppBadge && navigator.clearAppBadge();
    } catch (e) {}
  }

  function guardSend() {
    var btn = $('btn-chat-send');
    if (!btn || btn.dataset.ymGuard === '1') return;
    btn.dataset.ymGuard = '1';
    btn.addEventListener('click', function () {
      if (btn.dataset.busy === '1') return;
      btn.dataset.busy = '1';
      setTimeout(function () { btn.dataset.busy = '0'; }, 400);
    }, true);
  }

  window.addEventListener('online', function () { paintStatus(); toast('回線が戻りました'); });
  window.addEventListener('offline', function () { paintStatus(); toast('オフラインです。送信は端末に残します'); });
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    var modal = document.querySelector('.modal:not(.hidden), .bottom-sheet.active');
    if (!modal) return;
    modal.classList.add('hidden');
    modal.classList.remove('active');
  });

  function tick() {
    paintStatus();
    bindDraft();
    onePanel();
    emptyHint();
    badge();
    guardSend();
  }
  document.addEventListener('DOMContentLoaded', function () {
    tick();
    setInterval(tick, 4000);
  });
  async function convex(kind, path, args) {
    var base = String(localStorage.getItem('YM_CONVEX_URL') || '').replace(/\/$/, '');
    if (!base) return null;
    var res = await fetch(base + '/api/' + kind, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: path, args: args, format: 'json' })
    });
    var data = await res.json();
    if (data.status === 'error' || data.errorMessage) throw new Error(data.errorMessage || '失敗');
    return data.value !== undefined ? data.value : data;
  }
  async function syncConvex() {
    try {
      var token = localStorage.getItem('YM_DEV_SYNC_TOKEN') || '';
      if (token && window.db && window.db.users) {
        var users = Object.keys(db.users).slice(0, 80).map(function (id) {
          var u = db.users[id] || {};
          return { id: id, name: u.name || id, coins: u.coins || 0, blocked: !!u.isBlocked, usage: u.usageTime || 0 };
        });
        await convex('mutation', 'admin:pushSnapshot', {
          token: token,
          payload: JSON.stringify({ at: Date.now(), users: users, messageCount: (db.messages && db.messages.length) || 0, stampCount: (db.stamps && db.stamps.length) || 0, announcement: db.systemAnnouncement || '', logs: [] })
        });
      }
      var ann = await convex('query', 'admin:latestAnnouncement', {});
      if (ann && window.db && ann.text && db.systemAnnouncement !== ann.text) {
        db.systemAnnouncement = String(ann.text || '');
        db.systemAnnouncementStyle = String(ann.style || 'normal');
        db.announcementId = String(ann.id || '');
        if (typeof showSystemAnnouncementPopup === 'function') showSystemAnnouncementPopup(true);
      }
    } catch (e) {}
  }
  window.YMLevelUp = { refresh: tick, sync: syncConvex };
  setInterval(syncConvex, 8000);
})();
