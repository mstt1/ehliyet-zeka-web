/* Ehliyet Zeka — e-posta doğrulama + şifre yenileme (03 Eki 2026)
   Tasarım: ana repo docs/plans/auth_epostalar_tasarim.md

   Güvenlik notları:
   - Yalnız Supabase URL + publishable (herkese açık) anahtar burada; gizli anahtar YOK.
   - Oturum yalnız bellekte (persistSession:false) ve iş bitince signOut — tarayıcıda iz kalmaz.
   - Jeton URL'den okunur okunmaz adres çubuğundan silinir; jeton, şifre, e-posta
     ASLA loglanmaz / gönderilmez (console.* kullanılmıyor, analytics yok).
   - Jeton (tek kullanımlık) sayfa açılınca DEĞİL, kullanıcı düğmeye basınca tüketilir:
     e-posta önizleyici/bağlantı tarayıcı botları jetonu yakamaz. */
(function () {
  'use strict';

  var SUPABASE_URL = 'https://bmsihszdvurhlfxledkr.supabase.co';
  var SUPABASE_KEY = 'sb_publishable_b_Ff_JSY4NVUsYdrM1Y3_Q_0BsXSMAd';
  var MIN_PASSWORD = 6; // uygulamadaki kayıt kuralıyla aynı (register_screen.dart); Dashboard'da teyit edilecek
  var MAX_PASSWORD = 72; // Supabase/bcrypt sınırı

  var MSG = {
    missing: 'Bağlantı eksik veya bozuk. Lütfen e-postadaki bağlantıyı yeniden aç ya da uygulamadan yeni bir bağlantı iste.',
    expired: 'Bağlantı geçersiz veya süresi dolmuş. Uygulamadan yeni bir bağlantı iste.',
    network: 'Sunucuya ulaşılamadı. İnternet bağlantını kontrol edip tekrar dene.',
    generic: 'İşlem tamamlanamadı. Lütfen biraz sonra tekrar dene.',
    samePassword: 'Yeni şifre eskisiyle aynı olamaz. Farklı bir şifre seç.',
    weakPassword: 'Bu şifre çok zayıf. Daha uzun veya daha karmaşık bir şifre seç.',
    verifyDone: 'E-postan doğrulandı, uygulamaya dönüp giriş yap.',
    resetDone: 'Şifren güncellendi, uygulamada yeni şifrenle giriş yap.',
    short: 'Şifre en az ' + MIN_PASSWORD + ' karakter olmalı.',
    mismatch: 'İki şifre aynı değil.'
  };

  function $(id) { return document.getElementById(id); }

  // Jetonu oku ve adres çubuğundan hemen sil.
  function takeParams() {
    var q = new URLSearchParams(window.location.search);
    var out = { tokenHash: q.get('token_hash'), type: q.get('type') };
    try { window.history.replaceState(null, '', window.location.pathname); } catch (e) { /* yoksay */ }
    return out;
  }

  function makeClient() {
    if (!window.supabase || !window.supabase.createClient) return null;
    return window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
    });
  }

  function show(id, text) {
    var el = $(id);
    if (!el) return;
    if (typeof text === 'string') el.textContent = text;
    el.hidden = false;
  }
  function hide(id) { var el = $(id); if (el) el.hidden = true; }

  function setBusy(btn, busy, label) {
    btn.disabled = busy;
    btn.textContent = busy ? 'Lütfen bekle…' : label;
  }

  // Hata → Türkçe mesaj. Ham hata metni kullanıcıya/loga gitmez.
  function mapError(err, phase) {
    if (!err) return MSG.generic;
    var code = err.code || '';
    var name = err.name || '';
    var status = err.status;
    if (name === 'AuthRetryableFetchError' || status === 0 || status === undefined && /fetch|network/i.test(String(err.message || ''))) {
      return MSG.network;
    }
    if (code === 'same_password') return MSG.samePassword;
    if (code === 'weak_password') return MSG.weakPassword;
    if (phase === 'verify') {
      if (code === 'otp_expired' || code === 'otp_disabled' || status === 400 || status === 401 || status === 403 || status === 422) {
        return MSG.expired;
      }
    }
    return MSG.generic;
  }

  function finish(client, doneText) {
    // Oturumu hemen kapat: tarayıcıda/bellekte açık oturum kalmasın.
    var p = client && client.auth ? client.auth.signOut({ scope: 'local' }) : null;
    var after = function () {
      hide('form');
      hide('error');
      show('done', doneText);
    };
    if (p && p.then) { p.then(after, after); } else { after(); }
  }

  // ── E-posta doğrulama ─────────────────────────────────────────
  function initVerify() {
    var params = takeParams();
    var btn = $('verify-btn');
    var type = params.type === 'signup' ? 'signup' : 'email'; // şablon type=email gönderir; eski 'signup' da kabul
    if (!params.tokenHash || (params.type && params.type !== 'email' && params.type !== 'signup')) {
      hide('form'); show('error', MSG.missing); return;
    }
    var client = makeClient();
    if (!client) { hide('form'); show('error', MSG.generic); return; }
    btn.addEventListener('click', function () {
      hide('error');
      setBusy(btn, true, 'E-postamı doğrula');
      client.auth.verifyOtp({ token_hash: params.tokenHash, type: type }).then(function (res) {
        if (res.error) {
          setBusy(btn, false, 'E-postamı doğrula');
          show('error', mapError(res.error, 'verify'));
          return;
        }
        finish(client, MSG.verifyDone);
      }, function (err) {
        setBusy(btn, false, 'E-postamı doğrula');
        show('error', mapError(err, 'verify'));
      });
    });
  }

  // ── Şifre yenileme ────────────────────────────────────────────
  function initReset() {
    var params = takeParams();
    var form = $('reset-form');
    var btn = $('reset-btn');
    if (!params.tokenHash || (params.type && params.type !== 'recovery')) {
      hide('form'); show('error', MSG.missing); return;
    }
    var client = makeClient();
    if (!client) { hide('form'); show('error', MSG.generic); return; }
    var verified = false; // verifyOtp bir kez başarılıysa tekrar denemede yeniden tüketme

    var toggle = $('toggle-pw');
    if (toggle) {
      toggle.addEventListener('click', function () {
        var shown = $('pw1').type === 'text';
        $('pw1').type = shown ? 'password' : 'text';
        $('pw2').type = shown ? 'password' : 'text';
        toggle.setAttribute('aria-pressed', shown ? 'false' : 'true');
        toggle.textContent = shown ? 'Şifreyi göster' : 'Şifreyi gizle';
      });
    }

    function updatePassword(pw) {
      return client.auth.updateUser({ password: pw }).then(function (res) {
        if (res.error) { throw res.error; }
        finish(client, MSG.resetDone);
      });
    }

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      hide('error');
      var pw1 = $('pw1').value;
      var pw2 = $('pw2').value;
      if (pw1.length < MIN_PASSWORD) { show('error', MSG.short); return; }
      if (pw1.length > MAX_PASSWORD) { show('error', 'Şifre en fazla ' + MAX_PASSWORD + ' karakter olabilir.'); return; }
      if (pw1 !== pw2) { show('error', MSG.mismatch); return; }
      setBusy(btn, true, 'Şifreyi güncelle');
      var chain = verified
        ? Promise.resolve()
        : client.auth.verifyOtp({ token_hash: params.tokenHash, type: 'recovery' }).then(function (res) {
            if (res.error) { var e = res.error; e._phase = 'verify'; throw e; }
            verified = true;
          });
      chain.then(function () { return updatePassword(pw1); }).catch(function (err) {
        setBusy(btn, false, 'Şifreyi güncelle');
        show('error', mapError(err, err && err._phase === 'verify' ? 'verify' : 'update'));
      });
    });
  }

  var page = document.body.getAttribute('data-page');
  if (page === 'verify') initVerify();
  else if (page === 'reset') initReset();
})();
