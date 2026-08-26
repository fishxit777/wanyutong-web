(function () {
  'use strict';

  var root = document.documentElement;
  var card = document.getElementById('digital-card');
  var flipButton = document.getElementById('flip-button');
  var themeButton = document.getElementById('theme-button');
  var saveButton = document.getElementById('save-button');
  var shareButton = document.getElementById('share-button');
  var status = document.getElementById('action-status');
  var currentLang = 'zh';

  function textFor(zh, en) {
    return currentLang === 'en' ? en : zh;
  }

  function announce(zh, en) {
    if (!status) return;
    status.textContent = textFor(zh, en);
    window.setTimeout(function () {
      if (status.textContent === textFor(zh, en)) status.textContent = '';
    }, 4200);
  }

  function setLanguage(lang) {
    currentLang = lang === 'en' ? 'en' : 'zh';
    root.lang = currentLang === 'en' ? 'en' : 'zh-Hant';
    document.querySelectorAll('[data-zh][data-en]').forEach(function (element) {
      element.textContent = element.getAttribute(currentLang === 'en' ? 'data-en' : 'data-zh');
    });

    var zhButton = document.getElementById('lang-zh');
    var enButton = document.getElementById('lang-en');
    if (zhButton && enButton) {
      zhButton.classList.toggle('active', currentLang === 'zh');
      enButton.classList.toggle('active', currentLang === 'en');
      zhButton.setAttribute('aria-pressed', String(currentLang === 'zh'));
      enButton.setAttribute('aria-pressed', String(currentLang === 'en'));
    }

    document.title = textFor('萬語通數位名片｜WanyuTong', 'WanyuTong Digital Card');
    updateCardLabel();
    updateThemeButton();
    try { localStorage.setItem('wyt-lang', currentLang); } catch (error) {}
  }

  function updateCardLabel() {
    if (!card) return;
    var isBack = card.classList.contains('is-flipped');
    card.setAttribute('aria-label', textFor(isBack ? '萬語通數位名片背面' : '萬語通數位名片正面', isBack ? 'Back of WanyuTong digital card' : 'Front of WanyuTong digital card'));
  }

  function setTheme(theme) {
    var isLight = theme === 'light';
    root.classList.toggle('light', isLight);
    root.classList.toggle('dark', !isLight);
    try { localStorage.setItem('wyt-theme', isLight ? 'light' : 'dark'); } catch (error) {}
    updateThemeButton();
  }

  function updateThemeButton() {
    if (!themeButton) return;
    var isLight = root.classList.contains('light');
    var label = textFor('切換日夜模式', 'Switch light or dark mode');
    themeButton.querySelector('span').textContent = isLight ? '☀' : '☾';
    themeButton.setAttribute('aria-label', label);
    themeButton.setAttribute('title', label);
  }

  function flipCard() {
    if (!card) return;
    var isBack = card.classList.toggle('is-flipped');
    if (flipButton) flipButton.setAttribute('aria-pressed', String(isBack));
    updateCardLabel();
    announce(isBack ? '已翻到名片背面' : '已翻到名片正面', isBack ? 'Showing the back of the card' : 'Showing the front of the card');
  }

  function saveContact() {
    var lines = [
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:萬語通團隊',
      'ORG:萬語通 WanyuTong',
      'TITLE:LINE 多國翻譯與工作管理',
      'EMAIL;TYPE=INTERNET:wanyutong29@gmail.com',
      'URL:https://wanyutong.tw/',
      'NOTE:官方 LINE @969wpxno｜LINE 群組多國翻譯與工作管理',
      'END:VCARD'
    ];
    var blob = new Blob([lines.join('\r\n')], { type: 'text/vcard;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = 'WanyuTong-Team.vcf';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    announce('已建立萬語通聯絡人檔案', 'WanyuTong contact file created');
  }

  function fallbackShare(url) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(url).then(function () {
        announce('名片網址已複製', 'Card link copied');
      });
    }
    var field = document.createElement('textarea');
    field.value = url;
    field.setAttribute('readonly', '');
    field.style.position = 'fixed';
    field.style.opacity = '0';
    document.body.appendChild(field);
    field.select();
    document.execCommand('copy');
    field.remove();
    announce('名片網址已複製', 'Card link copied');
    return Promise.resolve();
  }

  function shareCard() {
    var url = 'https://wanyutong.tw/card.html';
    var data = {
      title: textFor('萬語通數位名片', 'WanyuTong Digital Card'),
      text: textFor('萬語通｜LINE 多國翻譯與工作管理', 'WanyuTong | LINE multilingual translation and work management'),
      url: url
    };
    if (navigator.share) {
      navigator.share(data).then(function () {
        announce('名片已分享', 'Card shared');
      }).catch(function (error) {
        if (error && error.name !== 'AbortError') fallbackShare(url);
      });
      return;
    }
    fallbackShare(url);
  }

  document.querySelectorAll('[data-lang]').forEach(function (button) {
    button.addEventListener('click', function () { setLanguage(button.getAttribute('data-lang')); });
  });
  if (themeButton) themeButton.addEventListener('click', function () { setTheme(root.classList.contains('light') ? 'dark' : 'light'); });
  if (flipButton) flipButton.addEventListener('click', flipCard);
  if (card) card.addEventListener('keydown', function (event) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      flipCard();
    }
  });
  if (saveButton) saveButton.addEventListener('click', saveContact);
  if (shareButton) shareButton.addEventListener('click', shareCard);

  var savedLang = 'zh';
  var savedTheme = root.classList.contains('light') ? 'light' : 'dark';
  try {
    savedLang = localStorage.getItem('wyt-lang') === 'en' ? 'en' : 'zh';
    savedTheme = localStorage.getItem('wyt-theme') === 'light' ? 'light' : 'dark';
  } catch (error) {}
  setTheme(savedTheme);
  setLanguage(savedLang);

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('./sw.js').catch(function () {});
    });
  }
})();
