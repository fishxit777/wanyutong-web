(function () {
  'use strict';

  var root = document.documentElement;
  var card = document.getElementById('digital-card');
  var flipButton = document.getElementById('flip-button');
  var themeButton = document.getElementById('theme-button');
  var saveButton = document.getElementById('save-button');
  var shareButton = document.getElementById('share-button');
  var status = document.getElementById('action-status');
  var staticLocale = root.getAttribute('data-wyt-static-locale');
  var currentLang = staticLocale || 'zh';
  // Only transient card actions use this copy. The page itself is localized at build time.
  var cardMessages = {
    'zh-Hans': {
      'Back of WanyuTong digital card': '万语通数字名片背面',
      'Front of WanyuTong digital card': '万语通数字名片正面',
      'Switch light or dark mode': '切换日夜模式',
      'Showing the back of the card': '已翻到名片背面',
      'Showing the front of the card': '已翻到名片正面',
      'WanyuTong contact file created': '已创建万语通联系人文件',
      'Card link copied': '名片链接已复制',
      'WanyuTong Digital Card': '万语通数字名片',
      'WanyuTong | LINE multilingual translation and work management': '万语通｜LINE 多语言翻译与工作管理',
      'Card shared': '名片已分享'
    },
    ja: {
      'Back of WanyuTong digital card': 'WanyuTong のデジタル名刺の裏面',
      'Front of WanyuTong digital card': 'WanyuTong のデジタル名刺の表面',
      'Switch light or dark mode': 'ライトモードとダークモードを切り替える',
      'Showing the back of the card': '名刺の裏面を表示しました',
      'Showing the front of the card': '名刺の表面を表示しました',
      'WanyuTong contact file created': 'WanyuTong の連絡先ファイルを作成しました',
      'Card link copied': '名刺のリンクをコピーしました',
      'WanyuTong Digital Card': 'WanyuTong デジタル名刺',
      'WanyuTong | LINE multilingual translation and work management': 'WanyuTong｜LINE の多言語翻訳と業務管理',
      'Card shared': '名刺を共有しました'
    },
    ko: {
      'Back of WanyuTong digital card': 'WanyuTong 디지털 명함 뒷면',
      'Front of WanyuTong digital card': 'WanyuTong 디지털 명함 앞면',
      'Switch light or dark mode': '라이트 모드와 다크 모드 전환',
      'Showing the back of the card': '명함 뒷면을 표시했습니다',
      'Showing the front of the card': '명함 앞면을 표시했습니다',
      'WanyuTong contact file created': 'WanyuTong 연락처 파일을 만들었습니다',
      'Card link copied': '명함 링크를 복사했습니다',
      'WanyuTong Digital Card': 'WanyuTong 디지털 명함',
      'WanyuTong | LINE multilingual translation and work management': 'WanyuTong | LINE 다국어 번역 및 업무 관리',
      'Card shared': '명함을 공유했습니다'
    },
    id: {
      'Back of WanyuTong digital card': 'Bagian belakang kartu nama digital WanyuTong',
      'Front of WanyuTong digital card': 'Bagian depan kartu nama digital WanyuTong',
      'Switch light or dark mode': 'Beralih antara mode terang dan gelap',
      'Showing the back of the card': 'Bagian belakang kartu ditampilkan',
      'Showing the front of the card': 'Bagian depan kartu ditampilkan',
      'WanyuTong contact file created': 'File kontak WanyuTong telah dibuat',
      'Card link copied': 'Tautan kartu telah disalin',
      'WanyuTong Digital Card': 'Kartu Nama Digital WanyuTong',
      'WanyuTong | LINE multilingual translation and work management': 'WanyuTong | Penerjemahan multibahasa dan pengelolaan pekerjaan di LINE',
      'Card shared': 'Kartu nama telah dibagikan'
    }
  };

  function textFor(zh, en) {
    if (currentLang === 'zh') return zh;
    var messages = cardMessages[currentLang];
    return messages && messages[en] ? messages[en] : en;
  }

  function announce(zh, en) {
    if (!status) return;
    status.textContent = textFor(zh, en);
    window.setTimeout(function () {
      if (status.textContent === textFor(zh, en)) status.textContent = '';
    }, 4200);
  }

  function setLanguage(lang) {
    if (staticLocale) return;
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
    var localePaths = { en: 'en/', ja: 'ja/', ko: 'ko/', id: 'id/', 'zh-Hans': 'zh-cn/' };
    var localizedFolder = localePaths[staticLocale] || '';
    var url = 'https://wanyutong.tw/' + localizedFolder + 'card.html';
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
  if (staticLocale) updateCardLabel();
  else setLanguage(savedLang);

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register(staticLocale ? '/sw.js' : './sw.js').catch(function () {});
    });
  }
})();
