import os
import deepl
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
from flask import Flask, request, abort, jsonify, redirect, make_response
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import (
    MessageEvent, TextMessage, ImageMessage, AudioMessage,
    TextSendMessage, MemberJoinedEvent, JoinEvent
)
import anthropic
import base64
import threading
import time
from collections import defaultdict
from competitor_monitor import run_competitor_monitor, init_competitor_db
import schedule
import openai
import hashlib
import urllib.parse
import uuid
import logging
import requests
import re
import hmac
import secrets

# ===== PostgreSQL 連線 =====
DATABASE_URL = os.environ.get('DATABASE_URL', '')

def get_db():
    """取得 PostgreSQL 連線，自動處理 SSL"""
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    conn.autocommit = False
    return conn

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.json.ensure_ascii = False
app.json.sort_keys = False

# ===== 安全防護 =====
@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    resp.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    if request.path.startswith('/admin'):
        resp.headers['Cache-Control'] = 'no-store, no-cache, max-age=0, must-revalidate'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        resp.headers['Referrer-Policy'] = 'no-referrer'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers.setdefault('Content-Security-Policy', "frame-ancestors 'none'")
    return resp

# 錯誤訊息遮蔽：統一回傳 500，不洩漏內部資訊
@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': '伺服器內部錯誤，請稍後再試'}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': '找不到此路徑'}), 404

# 後台 IP 白名單（允許所有 IP 存取；如需限制，在 ADMIN_ALLOWED_IPS 環境變數填入逗號分隔的 IP）
# 範例：ADMIN_ALLOWED_IPS=1.2.3.4,5.6.7.8（空白代表不限制）
ADMIN_ALLOWED_IPS_RAW = os.environ.get('ADMIN_ALLOWED_IPS', '').strip()
ADMIN_ALLOWED_IPS = [ip.strip() for ip in ADMIN_ALLOWED_IPS_RAW.split(',') if ip.strip()]

def check_admin_ip():
    """檢查請求 IP 是否在白名單，白名單為空則全部放行"""
    if not ADMIN_ALLOWED_IPS:
        return True
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    return client_ip in ADMIN_ALLOWED_IPS

# API Rate Limiting（防暴力攻擊）：每個 IP 每分鐘最多 60 次 API 請求
api_request_times = defaultdict(list)
API_RATE_LIMIT = 60
API_RATE_WINDOW = 60

# ===== 爬蟲 / 異常偵測防護 =====
# 管理員 LINE ID（收異常通知）
ADMIN_LINE_ID = 'Uf0cb8b35a0ac041d4b427cb1f727772e'

# 封鎖名單：{ip: unblock_timestamp}
blocked_ips = {}
BLOCK_DURATION = 3600  # 封鎖1小時

# 異常偵測參數
CRAWLER_LIMIT = 30      # 同一 IP 1分鐘內超過30次 → 視為爬蟲
CRAWLER_WINDOW = 60
crawler_request_times = defaultdict(list)
crawler_notified = {}   # {ip: last_notify_time}，避免重複通知

def get_client_ip():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip:
        ip = ip.split(',')[0].strip()
    return ip or 'unknown'


def log_admin_action(action, target='', detail=''):
    try:
        conn = get_db()
        c = conn.cursor()
        tw_now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute('''INSERT INTO admin_audit_logs (action, target, detail, ip, created_at)
                     VALUES (%s, %s, %s, %s, %s)''',
                  (str(action)[:80], str(target)[:160], str(detail)[:800], get_client_ip()[:80], tw_now))
        conn.commit()
        conn.close()
    except Exception as e:
        print('[admin_audit] error:', e)

PATH_DESCRIPTIONS = {
    '/track/pixel':  '網站瀏覽追蹤像素\n→ 對方可能在掃描你的流量系統',
    '/track':        '網站瀏覽追蹤\n→ 對方可能在干擾流量統計',
    '/webhook':      'LINE Bot 訊息接收入口\n→ 對方可能在騷擾或測試 Bot 漏洞',
    '/admin':        '後台管理入口\n→ 對方可能在暴力破解後台',
    '/ecpay/notify': 'ECPay 付款回調入口\n→ 對方可能在偽造付款通知，請立即檢查',
    '/ecpay/return': 'ECPay 付款結果入口\n→ 對方可能在偽造付款結果，請立即檢查',
    '/pay':          '付款頁面\n→ 對方可能在掃描付款流程',
}

def notify_admin_crawler(ip, count, path):
    """推播爬蟲通知給管理員 LINE"""
    now = time.time()
    last = crawler_notified.get(ip, 0)
    if now - last < 300:
        return
    crawler_notified[ip] = now
    tw_now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    path_desc = '未知入口\n→ 對方可能在掃描系統漏洞'
    for key, desc in PATH_DESCRIPTIONS.items():
        if str(path).startswith(key):
            path_desc = desc
            break
    msg = (
        '🚨 異常爬蟲偵測\n'
        '時間：' + tw_now + '\n'
        'IP：' + ip + '\n'
        '1分鐘請求數：' + str(count) + '\n'
        '攻擊入口：' + str(path) + '\n'
        '說明：' + path_desc + '\n\n'
        '已自動封鎖1小時\n\n'
        '─────────────────\n'
        '📋 你的所有入口：\n'
        '/track/pixel → 流量追蹤像素\n'
        '/track → 流量追蹤(POST)\n'
        '/webhook → LINE Bot\n'
        '/admin → 後台管理\n'
        '/ecpay/notify → 付款回調\n'
        '/ecpay/return → 付款結果\n'
        '/pay → 付款頁面\n'
        '─────────────────'
    )
    try:
        line_bot_api.push_message(ADMIN_LINE_ID, TextSendMessage(text=msg))
    except Exception as e:
        print('[notify_admin_crawler] err:', e)

def check_crawler(path='/'):
    """
    偵測異常爬蟲，回傳 True=正常，False=異常已封鎖
    同時也做原有的 API rate limit 邏輯
    """
    ip = get_client_ip()
    now = time.time()

    # 已封鎖中
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            return False
        else:
            del blocked_ips[ip]  # 解封

    # 計算請求頻率
    times = crawler_request_times[ip]
    times = [t for t in times if now - t < CRAWLER_WINDOW]
    times.append(now)
    crawler_request_times[ip] = times

    if len(times) > CRAWLER_LIMIT:
        blocked_ips[ip] = now + BLOCK_DURATION
        threading.Thread(
            target=notify_admin_crawler,
            args=(ip, len(times), path),
            daemon=True
        ).start()
        return False

    return True

def check_api_rate_limit():
    """API 層級 rate limit，回傳 True=通過，False=超速"""
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    now = time.time()
    times = api_request_times[client_ip]
    times = [t for t in times if now - t < API_RATE_WINDOW]
    times.append(now)
    api_request_times[client_ip] = times
    return len(times) <= API_RATE_LIMIT

line_bot_api = LineBotApi(os.environ.get('LINE_CHANNEL_ACCESS_TOKEN'))
handler = WebhookHandler(os.environ.get('LINE_CHANNEL_SECRET'))
translator = deepl.Translator(os.environ.get('DEEPL_API_KEY'))
claude = anthropic.Anthropic(api_key=os.environ.get('ANTHROPIC_API_KEY'))
openai_client = openai.OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))

# ECPay 設定（等合約拿到後填入 Render 環境變數）
ECPAY_MERCHANT_ID = os.environ.get('ECPAY_MERCHANT_ID', '')
ECPAY_HASH_KEY    = os.environ.get('ECPAY_HASH_KEY', '')
ECPAY_HASH_IV     = os.environ.get('ECPAY_HASH_IV', '')
ECPAY_PAYMENT_URL = 'https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5'
BOT_BASE_URL      = os.environ.get('BOT_BASE_URL', 'https://one1stars-line-bot.onrender.com')

user_message_times = defaultdict(list)
RATE_LIMIT_COUNT = 10
RATE_LIMIT_SECONDS = 60

# 每日免費翻譯次數（個人版 & 群組版共用）
FREE_DAILY_LIMIT = 15

# 多語翻譯待機：記住下一則要翻的語言清單
# key = user_id 或 group_id, value = [(lang_code, lang_name), ...]
multilang_pending = {}

IMAGE_OCR_PROMPT = """請識別這張圖片中的主要文字內容，只回傳文字，不要加任何說明。

規則：
1. 如果是表格或比較圖，請保留欄位與列，使用「欄位 | 欄位 | 欄位」格式。
2. 如果是網頁截圖，忽略導覽列、按鈕、語言切換、頁尾與重複選單，只保留主要內容。
3. 保留有意義的標題、段落、條列與數字。
4. 不要自行翻譯，不要補充圖片中沒有的內容。
5. 如果圖片中沒有可辨識文字，回傳「圖片中沒有文字」。
"""

IMAGE_REPLY_MAX_CHARS = 2600
IMAGE_ORIGINAL_PREVIEW_CHARS = 420

def clean_image_ocr_text(text):
    """Normalize OCR text before language detection and display."""
    if not text:
        return ''
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    lines = []
    seen = set()
    nav_keywords = [
        'blog', 'faq', 'pricing', 'terms', 'try free', 'free trial',
        'home', 'why us', 'en', '繁中', '免費體驗', '部落格', '常見問題',
        '為何選我', '引擎差異', '競品比較', '收費方式', '如何開始'
    ]
    for raw_line in text.split('\n'):
        line = re.sub(r'[ \t]+', ' ', raw_line).strip()
        if not line:
            continue
        lower = line.lower()
        keyword_hits = sum(1 for keyword in nav_keywords if keyword in lower)
        # Common website navigation bars add noise to OCR screenshots.
        if keyword_hits >= 5 and len(line) < 180:
            continue
        dedupe_key = lower
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        lines.append(line)
    return '\n'.join(lines).strip()

def text_looks_like_table(text):
    if not text:
        return False
    lines = [line for line in text.split('\n') if line.strip()]
    pipe_rows = sum(1 for line in lines if line.count('|') >= 2)
    if pipe_rows >= 2:
        return True
    table_words = ['feature', 'monthly fee', 'free quota', 'translation engine',
                   '功能', '月費', '免費額度', '翻譯引擎', 'wanyutong',
                   'echonora', 't2go', 'ligo']
    lower = text.lower()
    hits = sum(1 for word in table_words if word in lower)
    return hits >= 4

def limit_text(text, max_chars):
    text = (text or '').strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "\n…（原文較長，已摘要顯示）"

def split_line_text(text, max_chars=IMAGE_REPLY_MAX_CHARS):
    """Split long LINE text into safe chunks while preserving paragraphs."""
    text = (text or '').strip()
    if len(text) <= max_chars:
        return [text]
    chunks = []
    current = ''
    for para in text.split('\n\n'):
        addition = para if not current else '\n\n' + para
        if len(current) + len(addition) <= max_chars:
            current += addition
            continue
        if current:
            chunks.append(current)
        while len(para) > max_chars:
            chunks.append(para[:max_chars].rstrip())
            para = para[max_chars:].lstrip()
        current = para
    if current:
        chunks.append(current)
    return chunks[:5]

def build_image_translation_reply(extracted_text, translated_text, direction):
    source_text = clean_image_ocr_text(extracted_text)
    translated_text = (translated_text or '').strip()
    section_title = "📊 表格整理" if text_looks_like_table(source_text) or text_looks_like_table(translated_text) else "📝 翻譯內容"
    original_preview = limit_text(source_text, IMAGE_ORIGINAL_PREVIEW_CHARS)
    parts = [
        "📷 圖片翻譯完成",
        "語言：" + direction,
        "━━━━━━━━━━━━━━",
        section_title,
        translated_text,
        "━━━━━━━━━━━━━━",
        "🧾 原文摘要",
        original_preview,
        "━━━━━━━━━━━━━━",
        "重要文件、工安、醫療、法律或金額內容，請再人工確認。"
    ]
    return '\n'.join(part for part in parts if part).strip()

def reply_text_chunks(reply_token, text):
    messages = [TextSendMessage(text=chunk) for chunk in split_line_text(text)]
    line_bot_api.reply_message(reply_token, messages if len(messages) > 1 else messages[0])


# ===== ECPay 付款工具 =====
# 方案定義：(plan_key, days, amount, label)
ECPAY_PLANS = {
    'personal_trial':   ('trial',   7,   49,   '萬語通個人版7日體驗'),
    'personal_monthly': ('monthly', 30,  199,  '萬語通個人版月付'),
    'personal_yearly':  ('yearly',  365, 1590, '萬語通個人版年付'),
    'group_trial':      ('basic',   7,   49,   '萬語通群組版7日體驗'),
    'group_basic':      ('basic',   30,  199,  '萬語通群組版體驗版'),
    'group_pro':        ('pro',     30,  499,  '萬語通群組版商務版'),
}

PLAN_AMOUNTS = {
    'trial': 49,
    'monthly': 199,
    'yearly': 1590,
    'basic': 199,
    'pro': 499,
}

REFERRAL_REWARD_RULES = {
    # plan_key: (referrer_days, referred_days)
    'personal_trial': (3, 3),
    'personal_monthly': (14, 7),
    'personal_yearly': (90, 30),
}

REFERRAL_GROUP_BLOCK_TEXT = (
    "🎁 推薦碼功能僅限個人版使用\n\n"
    "為避免群組內多人共用、歸屬不清或獎勵爭議，"
    "推薦碼目前只支援「個人推薦個人」。\n\n"
    "正確流程：\n"
    "1. 推薦人在個人版傳 @推薦，取得自己的推薦碼\n"
    "2. 推薦人把推薦碼給新朋友\n"
    "3. 新朋友加入萬語通後，付款前傳 @使用推薦碼 XXXXX\n"
    "4. 首次付款成功後，雙方自動獲得翻譯天數\n\n"
    "要查看天數是否增加，請在個人版傳 @到期。"
)

REFERRAL_GROUP_USE_BLOCK_TEXT = (
    "⚠️ 群組版目前不支援使用推薦碼\n\n"
    "推薦優惠僅限個人對個人：\n"
    "1. 推薦人在個人版傳 @推薦，取得自己的推薦碼\n"
    "2. 推薦人把推薦碼給新朋友\n"
    "3. 新朋友加入萬語通後，付款前傳 @使用推薦碼 XXXXX\n"
    "4. 首次付款成功後，雙方自動獲得翻譯天數\n\n"
    "要查看天數是否增加，請在個人版傳 @到期。"
)

PLAN_ALIASES = {
    'trial': 'trial',
    '7': 'trial',
    '7日': 'trial',
    '7天': 'trial',
    '體驗7日': 'trial',
    '7日體驗': 'trial',
    'monthly': 'monthly',
    'month': 'monthly',
    '月付': 'monthly',
    '月付方案': 'monthly',
    '199': 'monthly',
    'yearly': 'yearly',
    'year': 'yearly',
    '年付': 'yearly',
    '年付方案': 'yearly',
    '1590': 'yearly',
    'basic': 'basic',
    '體驗版': 'basic',
    '群組體驗': 'basic',
    'group_basic': 'basic',
    'pro': 'pro',
    '商務版': 'pro',
    '群組商務': 'pro',
    '499': 'pro',
}


def normalize_plan_key(plan, owner_type='user', amount=None):
    raw = str(plan or '').strip().lower()
    raw = raw.replace(' ', '').replace('／', '/')
    normalized = PLAN_ALIASES.get(raw)
    if normalized:
        return normalized
    if amount is not None:
        try:
            amt = int(amount)
            if amt == 49:
                return 'trial'
            if amt == 1590:
                return 'yearly'
            if amt == 499:
                return 'pro'
            if amt == 199:
                return 'basic' if owner_type == 'group' else 'monthly'
        except:
            pass
    return raw


def parse_admin_int(value, default=0, field_name='數字'):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(field_name + '格式錯誤')


def validate_admin_plan(plan, owner_type='user'):
    plan = normalize_plan_key(plan, owner_type)
    allowed = ('trial', 'monthly', 'yearly') if owner_type == 'user' else ('trial', 'basic', 'pro')
    if plan not in allowed:
        raise ValueError('不支援的方案：' + str(plan))
    return plan


def validate_admin_days(days):
    days = parse_admin_int(days, 30, '天數')
    if days < 1 or days > 3650:
        raise ValueError('天數必須介於 1 到 3650')
    return days


def validate_admin_amount(amount):
    amount = parse_admin_int(amount, 0, '金額')
    if amount < 0:
        raise ValueError('金額不可小於 0')
    if amount > 1000000:
        raise ValueError('金額過大，請確認')
    return amount


def validate_admin_date(value):
    value = str(value or '').strip()
    try:
        datetime.strptime(value, '%Y-%m-%d')
    except ValueError:
        raise ValueError('日期格式必須是 YYYY-MM-DD')
    return value


def ecpay_generate_check_mac(params):
    # 依 ECPay 規範產生 CheckMacValue
    sorted_params = sorted(params.items(), key=lambda x: x[0].lower())
    raw = 'HashKey=' + ECPAY_HASH_KEY + '&'
    raw += '&'.join([k + '=' + str(v) for k, v in sorted_params])
    raw += '&HashIV=' + ECPAY_HASH_IV
    encoded = urllib.parse.quote_plus(raw).lower()
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest().upper()


def ecpay_create_order(owner_id, plan_key, is_group=False):
    # 建立訂單並回傳 HTML 自動提交表單
    if plan_key not in ECPAY_PLANS:
        return None, '不支援的方案'
    plan_code, days, amount, item_name = ECPAY_PLANS[plan_key]
    tw_now = datetime.utcnow() + timedelta(hours=8)
    trade_no = 'W' + tw_now.strftime('%m%d%H%M%S') + uuid.uuid4().hex[:9].upper()
    trade_date = tw_now.strftime('%Y/%m/%d %H:%M:%S')

    # 存訂單到 payments 表
    conn = get_db()
    c = conn.cursor()
    note = ('group:' if is_group else 'user:') + owner_id + ':' + plan_key + ':' + str(days) + ':' + trade_no
    c.execute('''INSERT INTO payments (user_id, amount, plan, payment_date, status, note)
                 VALUES (%s, %s, %s, %s, %s, %s)''',
              (owner_id, amount, plan_code, trade_date, 'pending', note))
    conn.commit()
    conn.close()

    params = {
        'MerchantID':        ECPAY_MERCHANT_ID,
        'MerchantTradeNo':   trade_no,
        'MerchantTradeDate': trade_date,
        'PaymentType':       'aio',
        'TotalAmount':       amount,
        'TradeDesc':         urllib.parse.quote('萬語通付款'),
        'ItemName':          item_name,
        'ReturnURL':         BOT_BASE_URL + '/ecpay/notify',
        'OrderResultURL':    BOT_BASE_URL + '/ecpay/return',
        'CustomField1':      owner_id,
        'CustomField2':      plan_key,
        'CustomField3':      'group' if is_group else 'user',
        'CustomField4':      str(days),
        'ChoosePayment':     'ALL',
        'EncryptType':       1,
    }
    params['CheckMacValue'] = ecpay_generate_check_mac(params)

    # 產生自動提交的 HTML 表單
    form_fields = ''.join(
        f'<input type="hidden" name="{k}" value="{v}">'
        for k, v in params.items()
    )
    html = f'''<!DOCTYPE html><html><head><meta charset="utf-8">
<title>萬語通付款中...</title></head><body>
<p style="font-family:sans-serif;text-align:center;margin-top:40px">正在前往付款頁面，請稍候...</p>
<form id="f" method="POST" action="{ECPAY_PAYMENT_URL}">{form_fields}</form>
<script>document.getElementById('f').submit();</script>
</body></html>'''
    return trade_no, html


# ===== 資料庫初始化 =====
def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        status TEXT DEFAULT 'free',
        plan TEXT DEFAULT 'none',
        expire_date TEXT DEFAULT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        target_lang TEXT DEFAULT 'ID',
        target_name TEXT DEFAULT '印尼文',
        timezone TEXT DEFAULT 'Asia/Taipei',
        lang_a TEXT DEFAULT 'ZH-HANT',
        lang_a_name TEXT DEFAULT '繁體中文',
        crm_tag TEXT DEFAULT '',
        crm_note TEXT DEFAULT ''
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        user_id TEXT,
        amount INTEGER,
        plan TEXT,
        payment_date TEXT DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'pending',
        note TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
        user_id TEXT PRIMARY KEY,
        reason TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id SERIAL PRIMARY KEY,
        action TEXT NOT NULL,
        target TEXT DEFAULT '',
        detail TEXT DEFAULT '',
        ip TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute("""CREATE TABLE IF NOT EXISTS groups (
        group_id TEXT PRIMARY KEY,
        status TEXT DEFAULT 'inactive',
        plan TEXT DEFAULT 'basic',
        expire_date TEXT DEFAULT NULL,
        lang_a TEXT DEFAULT 'ZH-HANT',
        lang_a_name TEXT DEFAULT '繁體中文',
        lang_b TEXT DEFAULT 'ID',
        lang_b_name TEXT DEFAULT '印尼文',
        is_translating INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        note TEXT DEFAULT '',
        crm_tag TEXT DEFAULT '',
        crm_note TEXT DEFAULT ''
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS translation_history (
        id SERIAL PRIMARY KEY,
        owner_id TEXT NOT NULL,
        original TEXT NOT NULL,
        translated TEXT NOT NULL,
        direction TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ignore_words (
        id SERIAL PRIMARY KEY,
        owner_id TEXT NOT NULL,
        word TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(owner_id, word)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS daily_usage (
        user_id TEXT,
        use_date TEXT,
        count INTEGER DEFAULT 0,
        PRIMARY KEY (user_id, use_date)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS saved_phrases (
        id SERIAL PRIMARY KEY,
        owner_id TEXT NOT NULL,
        name TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(owner_id, name)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS confirm_requests (
        id SERIAL PRIMARY KEY,
        group_id TEXT NOT NULL,
        requester_id TEXT NOT NULL,
        original_text TEXT NOT NULL,
        translated_text TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS confirm_replies (
        id SERIAL PRIMARY KEY,
        request_id INTEGER NOT NULL,
        reply_user_id TEXT NOT NULL,
        reply_choice INTEGER NOT NULL,
        replied_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(request_id, reply_user_id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS group_multilang (
        group_id TEXT NOT NULL,
        lang_code TEXT NOT NULL,
        lang_name TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0,
        PRIMARY KEY (group_id, lang_code)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS group_dnd (
        group_id TEXT PRIMARY KEY,
        start_hour INTEGER NOT NULL,
        start_min INTEGER NOT NULL,
        end_hour INTEGER NOT NULL,
        end_min INTEGER NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS industry_words (
        id SERIAL PRIMARY KEY,
        industry TEXT NOT NULL,
        word TEXT NOT NULL,
        UNIQUE(industry, word)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS translation_ratings (
        id SERIAL PRIMARY KEY,
        owner_id TEXT NOT NULL,
        original_text TEXT NOT NULL,
        translated_text TEXT NOT NULL,
        rating INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS crm_notes (
        id SERIAL PRIMARY KEY,
        owner_id TEXT NOT NULL,
        note TEXT NOT NULL,
        tag TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS competitor_snapshots (
        id SERIAL PRIMARY KEY,
        competitor_id TEXT,
        snapshot_type TEXT,
        content_hash TEXT,
        content_preview TEXT,
        crawled_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS competitor_changes (
        id SERIAL PRIMARY KEY,
        competitor_id TEXT,
        change_type TEXT,
        description TEXT,
        detected_at TEXT DEFAULT CURRENT_TIMESTAMP,
        reported INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS monitor_reports (
        id SERIAL PRIMARY KEY,
        report_date TEXT,
        summary TEXT,
        sent_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("ALTER TABLE competitor_snapshots ADD COLUMN IF NOT EXISTS competitor_id TEXT")
    c.execute("ALTER TABLE competitor_snapshots ADD COLUMN IF NOT EXISTS snapshot_type TEXT")
    c.execute("ALTER TABLE competitor_snapshots ADD COLUMN IF NOT EXISTS content_preview TEXT")
    c.execute("ALTER TABLE competitor_snapshots ADD COLUMN IF NOT EXISTS crawled_at TEXT DEFAULT CURRENT_TIMESTAMP")
    c.execute("ALTER TABLE competitor_changes ADD COLUMN IF NOT EXISTS competitor_id TEXT")
    c.execute("ALTER TABLE competitor_changes ADD COLUMN IF NOT EXISTS description TEXT")
    c.execute("ALTER TABLE competitor_changes ADD COLUMN IF NOT EXISTS detected_at TEXT DEFAULT CURRENT_TIMESTAMP")
    c.execute("ALTER TABLE competitor_changes ADD COLUMN IF NOT EXISTS reported INTEGER DEFAULT 0")
    c.execute("ALTER TABLE monitor_reports ADD COLUMN IF NOT EXISTS report_date TEXT")
    c.execute("ALTER TABLE monitor_reports ADD COLUMN IF NOT EXISTS summary TEXT")
    c.execute("ALTER TABLE monitor_reports ADD COLUMN IF NOT EXISTS sent_at TEXT DEFAULT CURRENT_TIMESTAMP")
    c.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='competitor_snapshots' AND column_name='competitor') THEN
                ALTER TABLE competitor_snapshots ALTER COLUMN competitor DROP NOT NULL;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='competitor_snapshots' AND column_name='url') THEN
                ALTER TABLE competitor_snapshots ALTER COLUMN url DROP NOT NULL;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='competitor_changes' AND column_name='competitor') THEN
                ALTER TABLE competitor_changes ALTER COLUMN competitor DROP NOT NULL;
            END IF;
        END $$;
    """)
    c.execute("""CREATE TABLE IF NOT EXISTS page_views (
        id SERIAL PRIMARY KEY,
        page TEXT NOT NULL,
        referrer TEXT,
        ua TEXT,
        ip TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS referral_codes (
        owner_id TEXT PRIMARY KEY,
        owner_type TEXT DEFAULT 'user',
        code TEXT UNIQUE NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS referral_records (
        id SERIAL PRIMARY KEY,
        referral_code TEXT NOT NULL,
        referrer_id TEXT NOT NULL,
        referred_id TEXT NOT NULL,
        referred_type TEXT DEFAULT 'user',
        status TEXT DEFAULT 'pending',
        plan_key TEXT DEFAULT '',
        referrer_reward_days INTEGER DEFAULT 0,
        referred_reward_days INTEGER DEFAULT 0,
        trade_no TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        rewarded_at TEXT DEFAULT NULL,
        UNIQUE(referred_id, referred_type)
    )""")
    conn.commit()
    conn.close()


init_db()


def fix_date_format():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT user_id, expire_date FROM users WHERE expire_date IS NOT NULL')
        rows = c.fetchall()
        for user_id, expire_date in rows:
            try:
                parsed = datetime.strptime(expire_date, '%Y-%m-%d')
                fixed = parsed.strftime('%Y-%m-%d')
                if fixed != expire_date:
                    c.execute('UPDATE users SET expire_date=%s WHERE user_id=%s', (fixed, user_id))
            except:
                pass
        conn.commit()
        conn.close()
    except Exception as e:
        print("[日期修正] 失敗: " + str(e))


fix_date_format()


# ===== 黑名單操作 =====
def is_blacklisted(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT user_id FROM blacklist WHERE user_id=%s', (user_id,))
    result = c.fetchone()
    conn.close()
    return result is not None


def add_blacklist(user_id, reason=''):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO blacklist (user_id, reason) VALUES (%s, %s) ON CONFLICT (user_id) DO NOTHING', (user_id, reason))
    conn.commit()
    conn.close()


def remove_blacklist(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM blacklist WHERE user_id=%s', (user_id,))
    conn.commit()
    conn.close()


# ===== 時間轉換工具 =====
def utc_to_tw(utc_str):
    if not utc_str:
        return utc_str
    try:
        dt = datetime.strptime(utc_str, '%Y-%m-%d %H:%M:%S')
        tw = dt + timedelta(hours=8)
        return tw.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return utc_str


# ===== 異常偵測 =====
def check_rate_limit(user_id):
    now = time.time()
    times = user_message_times[user_id]
    times = [t for t in times if now - t < RATE_LIMIT_SECONDS]
    times.append(now)
    user_message_times[user_id] = times
    if len(times) > RATE_LIMIT_COUNT:
        add_blacklist(user_id, reason='自動封鎖：' + str(RATE_LIMIT_SECONDS) + '秒內發送超過' + str(RATE_LIMIT_COUNT) + '條訊息')
        return False
    return True


# ===== 時區對照表 =====
TIMEZONE_OFFSETS = {
    'Asia/Taipei': 8, 'Asia/Tokyo': 9, 'Asia/Seoul': 9,
    'Asia/Bangkok': 7, 'Asia/Jakarta': 7, 'Asia/Singapore': 8,
    'Asia/Kuala_Lumpur': 8, 'Asia/Manila': 8, 'Asia/Ho_Chi_Minh': 7,
    'Asia/Kolkata': 5.5, 'Asia/Dubai': 4, 'Asia/Riyadh': 3,
    'Europe/London': 0, 'Europe/Paris': 1, 'Europe/Berlin': 1,
    'America/New_York': -5, 'America/Chicago': -6,
    'America/Los_Angeles': -8, 'Australia/Sydney': 10,
    'Pacific/Auckland': 12, 'UTC': 0,
}


# ===== 自動到期檢查 =====
def check_expiry():
    while True:
        try:
            conn = get_db()
            c = conn.cursor()
            tw_now = datetime.utcnow() + timedelta(hours=8)
            tw_today = tw_now.strftime('%Y-%m-%d')
            tw_remind_3 = (tw_now + timedelta(days=3)).strftime('%Y-%m-%d')
            tw_remind_1 = (tw_now + timedelta(days=1)).strftime('%Y-%m-%d')

            # 個人版：3 天前提醒（已停用，改為只推1天前）
            # c.execute(...)

            # 個人版：1 天前提醒
            c.execute('SELECT user_id, expire_date FROM users WHERE status=%s AND expire_date=%s',
                      ('active', tw_remind_1))
            for user_id, expire_date in c.fetchall():
                try:
                    line_bot_api.push_message(user_id, TextSendMessage(
                        text="⚠️ 萬語通明天到期！\n到期日：" + expire_date + "\n剩餘 1 天\n\n續費請直接傳送：\n@購買 月付 或 @購買 年付\n即可重新開通，方案無縫銜接。"
                    ))
                except:
                    pass

            # 個人版：已過期 → 停用
            c.execute('SELECT user_id FROM users WHERE status=%s AND expire_date<%s',
                      ('active', tw_today))
            for (user_id,) in c.fetchall():
                c.execute('UPDATE users SET status=%s WHERE user_id=%s', ('inactive', user_id))
                try:
                    line_bot_api.push_message(user_id, TextSendMessage(
                        text="❌ 萬語通已到期！\n\n續費請直接傳送：\n@購買 月付 或 @購買 年付\n即可重新開通，感謝您的支持！"
                    ))
                except:
                    pass

            # 群組版：3 天前提醒（已停用，改為只推1天前）
            # c.execute(...)

            # 群組版：1 天前提醒
            c.execute('SELECT group_id, expire_date FROM groups WHERE status=%s AND expire_date=%s',
                      ('active', tw_remind_1))
            for group_id_r, expire_date in c.fetchall():
                if is_group_in_dnd(group_id_r):
                    continue  # 勿擾時段，丟棄
                try:
                    line_bot_api.push_message(group_id_r, TextSendMessage(
                        text="⚠️ 萬語通群組翻譯明天到期！\n到期日：" + expire_date + "\n剩餘 1 天\n\n續費請聯繫客服 fishxit，或直接傳送 @購買 選擇方案重新開通。"
                    ))
                except:
                    pass

            # 群組版：已過期 → 停用
            c.execute('SELECT group_id FROM groups WHERE status=%s AND expire_date<%s',
                      ('active', tw_today))
            for (group_id_exp,) in c.fetchall():
                c.execute('UPDATE groups SET status=%s, is_translating=0 WHERE group_id=%s',
                          ('inactive', group_id_exp))
                if is_group_in_dnd(group_id_exp):
                    continue  # 勿擾時段，丟棄
                try:
                    line_bot_api.push_message(group_id_exp, TextSendMessage(
                        text="❌ 萬語通群組翻譯已到期，翻譯功能已自動停止。\n\n續費請直接傳送 @購買 選擇方案重新開通，或聯繫客服 fishxit。"
                    ))
                except:
                    pass

            conn.commit()
            conn.close()
        except Exception as e:
            print("[到期檢查] 失敗: " + str(e))

        time.sleep(3600)


expiry_thread = threading.Thread(target=check_expiry, daemon=True)
expiry_thread.start()


# ===== 競品監控排程 =====
# 修正：schedule 使用 UTC 時間，台灣 23:30 = UTC 15:30
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', '')
ADMIN_LINE_IDS = [
    uid.strip()
    for uid in os.environ.get('ADMIN_LINE_IDS', '').split(',')
    if uid.strip()
]
admin_auth_failures = defaultdict(list)
ADMIN_AUTH_RATE_LIMIT = 20
ADMIN_AUTH_RATE_WINDOW = 300
ADMIN_AUTH_BLOCK_SECONDS = 900
ADMIN_SESSION_COOKIE = 'wyt_admin_session'
ADMIN_SESSION_TTL_SECONDS = 8 * 3600
admin_sessions = {}

def get_admin_token():
    """從 header 優先讀取後台 Token；保留 query token 作為舊連結相容。"""
    return request.headers.get('X-Admin-Token') or request.args.get('token')

def admin_cookie_secure():
    return request.is_secure or request.headers.get('X-Forwarded-Proto', '').lower() == 'https'

def cleanup_admin_sessions(now=None):
    now = now or time.time()
    expired = [sid for sid, data in admin_sessions.items() if data.get('expires', 0) <= now]
    for sid in expired:
        admin_sessions.pop(sid, None)

def is_admin_session_valid():
    sid = request.cookies.get(ADMIN_SESSION_COOKIE)
    if not sid:
        return False
    now = time.time()
    data = admin_sessions.get(sid)
    if not data or data.get('expires', 0) <= now:
        admin_sessions.pop(sid, None)
        return False
    data['expires'] = now + ADMIN_SESSION_TTL_SECONDS
    return True

def create_admin_session():
    cleanup_admin_sessions()
    sid = secrets.token_urlsafe(32)
    admin_sessions[sid] = {
        'ip': get_client_ip(),
        'created_at': time.time(),
        'expires': time.time() + ADMIN_SESSION_TTL_SECONDS,
    }
    return sid

def validate_admin_token_value(token):
    token = token or ''
    ip = get_client_ip()
    now = time.time()

    block_until = blocked_ips.get(ip)
    if block_until:
        if now < block_until:
            return False
        blocked_ips.pop(ip, None)

    failures = [t for t in admin_auth_failures[ip] if now - t < ADMIN_AUTH_RATE_WINDOW]
    admin_auth_failures[ip] = failures

    if bool(ADMIN_TOKEN) and hmac.compare_digest(str(token), str(ADMIN_TOKEN)):
        admin_auth_failures.pop(ip, None)
        return True

    failures.append(now)
    admin_auth_failures[ip] = failures[-ADMIN_AUTH_RATE_LIMIT:]
    if len(failures) >= ADMIN_AUTH_RATE_LIMIT:
        blocked_ips[ip] = now + ADMIN_AUTH_BLOCK_SECONDS
        log_admin_action('admin_auth_blocked', ip, 'too_many_invalid_token_attempts')
    return False

def is_admin_token_valid():
    if is_admin_session_valid():
        return True
    return validate_admin_token_value(get_admin_token())

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json(silent=True) or {}
    token = (data.get('token') or get_admin_token() or '').strip()
    if not validate_admin_token_value(token):
        return jsonify({'error': 'Token 錯誤或已暫時封鎖'}), 403
    sid = create_admin_session()
    resp = make_response(jsonify({
        'success': True,
        'message': '登入成功',
        'expires_in_seconds': ADMIN_SESSION_TTL_SECONDS,
    }))
    resp.set_cookie(
        ADMIN_SESSION_COOKIE,
        sid,
        max_age=ADMIN_SESSION_TTL_SECONDS,
        httponly=True,
        secure=admin_cookie_secure(),
        samesite='Strict',
        path='/admin',
    )
    log_admin_action('admin_login', 'admin', 'session_cookie_created')
    return resp

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    sid = request.cookies.get(ADMIN_SESSION_COOKIE)
    if sid:
        admin_sessions.pop(sid, None)
    resp = make_response(jsonify({'success': True, 'message': '已登出'}))
    resp.delete_cookie(ADMIN_SESSION_COOKIE, path='/admin')
    log_admin_action('admin_logout', 'admin', 'session_cookie_cleared')
    return resp

@app.route('/admin/session', methods=['GET'])
def admin_session_status():
    return jsonify({'authenticated': is_admin_session_valid()})


def scheduled_competitor_monitor():
    print("[競品監控] 排程啟動 " + str(datetime.utcnow()) + " UTC（台灣時間約 23:30）")
    if not ADMIN_LINE_IDS:
        print("[競品監控] 錯誤：ADMIN_LINE_IDS 未設定，請到 Render 環境變數新增")
        return
    run_competitor_monitor(
        line_token=os.environ.get('LINE_CHANNEL_ACCESS_TOKEN'),
        admin_user_ids=ADMIN_LINE_IDS,
        pg_url=DATABASE_URL,
    )


def run_schedule():
    # UTC 15:30 = 台灣時間 23:30
    schedule.every().day.at("15:30").do(scheduled_competitor_monitor)
    while True:
        schedule.run_pending()
        time.sleep(60)


schedule_thread = threading.Thread(target=run_schedule, daemon=True)
schedule_thread.start()


# ===== 用戶資料庫操作 =====
def get_user(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
    user = c.fetchone()
    if not user:
        c.execute('INSERT INTO users (user_id) VALUES (%s)', (user_id,))
        conn.commit()
        c.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
        user = c.fetchone()
    conn.close()
    return user


def get_tw_today():
    return (datetime.utcnow() + timedelta(hours=8)).date()


def is_active(user_id):
    user = get_user(user_id)
    if user[1] == 'active':
        expire = user[3]
        if expire:
            try:
                tw_today = (datetime.utcnow() + timedelta(hours=8)).date()
                if datetime.strptime(expire, '%Y-%m-%d').date() >= tw_today:
                    return True
            except:
                pass
    return False


def activate_user(user_id, plan, days):
    expire = (datetime.utcnow() + timedelta(hours=8) + timedelta(days=days)).strftime('%Y-%m-%d')
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET status=%s, plan=%s, expire_date=%s WHERE user_id=%s',
              ('active', plan, expire, user_id))
    conn.commit()
    conn.close()


def extend_user_days(user_id, days, plan='referral_bonus'):
    if not user_id or int(days) <= 0:
        return None
    get_user(user_id)
    tw_today = (datetime.utcnow() + timedelta(hours=8)).date()
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT expire_date FROM users WHERE user_id=%s', (user_id,))
    row = c.fetchone()
    base_date = tw_today
    if row and row[0]:
        try:
            old_expire = datetime.strptime(row[0], '%Y-%m-%d').date()
            if old_expire > base_date:
                base_date = old_expire
        except:
            pass
    new_expire = (base_date + timedelta(days=int(days))).strftime('%Y-%m-%d')
    c.execute('UPDATE users SET status=%s, expire_date=%s WHERE user_id=%s',
              ('active', new_expire, user_id))
    conn.commit()
    conn.close()
    return new_expire


def extend_group_days(group_id, days, plan='referral_bonus'):
    if not group_id or int(days) <= 0:
        return None
    tw_today = (datetime.utcnow() + timedelta(hours=8)).date()
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT expire_date FROM groups WHERE group_id=%s', (group_id,))
    row = c.fetchone()
    if not row:
        c.execute('INSERT INTO groups (group_id, status, plan, expire_date, is_translating) VALUES (%s,%s,%s,%s,1) ON CONFLICT (group_id) DO NOTHING',
                  (group_id, 'active', plan, tw_today.strftime('%Y-%m-%d')))
        row = (tw_today.strftime('%Y-%m-%d'),)
    base_date = tw_today
    if row and row[0]:
        try:
            old_expire = datetime.strptime(row[0], '%Y-%m-%d').date()
            if old_expire > base_date:
                base_date = old_expire
        except:
            pass
    new_expire = (base_date + timedelta(days=int(days))).strftime('%Y-%m-%d')
    c.execute('UPDATE groups SET status=%s, expire_date=%s, is_translating=1 WHERE group_id=%s',
              ('active', new_expire, group_id))
    conn.commit()
    conn.close()
    return new_expire


def normalize_referral_code(code):
    return re.sub(r'[^A-Z0-9]', '', str(code or '').upper())[:16]


def ensure_referral_code(owner_id, owner_type='user'):
    owner_id = str(owner_id or '').strip()
    if not owner_id:
        return ''
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT code FROM referral_codes WHERE owner_id=%s', (owner_id,))
    row = c.fetchone()
    if row and row[0]:
        conn.close()
        return row[0]
    for _ in range(10):
        code = 'WYT' + secrets.token_hex(3).upper()
        try:
            c.execute('INSERT INTO referral_codes (owner_id, owner_type, code) VALUES (%s,%s,%s)',
                      (owner_id, owner_type, code))
            conn.commit()
            conn.close()
            return code
        except psycopg2.IntegrityError:
            conn.rollback()
    conn.close()
    return ''


def bind_referral_code(referred_id, referred_type, code):
    referred_id = str(referred_id or '').strip()
    referred_type = 'group' if referred_type == 'group' else 'user'
    code = normalize_referral_code(code)
    if not referred_id or not code:
        return False, '請輸入推薦碼'
    if referred_type == 'group':
        return False, REFERRAL_GROUP_USE_BLOCK_TEXT

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT owner_id FROM referral_codes WHERE code=%s', (code,))
    ref_row = c.fetchone()
    if not ref_row:
        conn.close()
        return False, '找不到此推薦碼，請確認是否輸入正確'
    referrer_id = ref_row[0]
    if referred_id == referrer_id:
        conn.close()
        return False, '不能使用自己的推薦碼'

    c.execute("SELECT COUNT(*) FROM payments WHERE user_id=%s AND status IN ('paid','success')",
              (referred_id,))
    paid_count = c.fetchone()[0] or 0
    if paid_count > 0:
        conn.close()
        return False, (
            '此帳號已經有付費或開通紀錄，不能再補綁推薦碼。\n\n'
            '推薦優惠只給新個人用戶首次付款前使用：\n'
            '1. 推薦人在個人版傳 @推薦，取得自己的推薦碼\n'
            '2. 推薦人把推薦碼給新朋友\n'
            '3. 新朋友加入萬語通後，付款前傳 @使用推薦碼 XXXXX\n'
            '4. 首次付款成功後，雙方自動獲得翻譯天數\n\n'
            '要查看天數是否增加，請在個人版傳 @到期。'
        )

    try:
        c.execute('''INSERT INTO referral_records (referral_code, referrer_id, referred_id, referred_type, status)
                     VALUES (%s,%s,%s,%s,%s)''',
                  (code, referrer_id, referred_id, referred_type, 'pending'))
        conn.commit()
        conn.close()
        return True, '推薦碼已綁定，首次付費成功後雙方會自動獲得翻譯天數。\n\n付款成功後可傳 @到期 查看新的到期日。'
    except psycopg2.IntegrityError:
        conn.rollback()
        conn.close()
        return False, (
            '此帳號已經綁定過推薦碼，不能重複綁定。\n\n'
            '請直接完成首次付款；付款成功後，系統會依已綁定的推薦碼自動發放雙方翻譯天數。\n\n'
            '付款成功後可傳 @到期 查看新的到期日。'
        )


def get_referral_summary(owner_id):
    code = ensure_referral_code(owner_id, 'user')
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM referral_records WHERE referrer_id=%s", (owner_id,))
    total = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM referral_records WHERE referrer_id=%s AND status=%s",
              (owner_id, 'rewarded'))
    rewarded = c.fetchone()[0] or 0
    conn.close()
    return code, total, rewarded


def award_referral_if_needed(owner_id, owner_type, plan_key, trade_no=''):
    if owner_type == 'group':
        return None
    referrer_days, referred_days = REFERRAL_REWARD_RULES.get(plan_key, (14, 7))
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT id, referrer_id, referred_id, referred_type
                 FROM referral_records
                 WHERE referred_id=%s AND referred_type=%s AND status=%s
                 ORDER BY id ASC LIMIT 1''',
              (owner_id, 'group' if owner_type == 'group' else 'user', 'pending'))
    row = c.fetchone()
    if not row:
        conn.close()
        return None
    referral_id, referrer_id, referred_id, referred_type = row
    c.execute('''UPDATE referral_records
                 SET status=%s, plan_key=%s, referrer_reward_days=%s, referred_reward_days=%s,
                     trade_no=%s, rewarded_at=%s
                 WHERE id=%s AND status=%s''',
              ('rewarded', plan_key, referrer_days, referred_days, trade_no,
               (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S'),
               referral_id, 'pending'))
    if c.rowcount == 0:
        conn.rollback()
        conn.close()
        return None
    conn.commit()
    conn.close()

    referrer_expire = extend_user_days(referrer_id, referrer_days, 'referral_bonus')
    if referred_type == 'group':
        referred_expire = extend_group_days(referred_id, referred_days, 'referral_bonus')
    else:
        referred_expire = extend_user_days(referred_id, referred_days, 'referral_bonus')

    try:
        line_bot_api.push_message(referrer_id, TextSendMessage(
            text="🎁 好友推薦獎勵已發放！\n\n你成功推薦一位新付費用戶。\n已送你 " + str(referrer_days) + " 天翻譯天數。\n新的到期日：" + str(referrer_expire) + "\n\n也可傳 @到期 查看目前天數。"
        ))
    except Exception as e:
        print("[推薦獎勵通知 referrer] 失敗: " + str(e))

    try:
        line_bot_api.push_message(referred_id, TextSendMessage(
            text="🎁 推薦碼優惠已發放！\n\n已加贈 " + str(referred_days) + " 天翻譯天數。\n新的到期日：" + str(referred_expire) + "\n\n也可傳 @到期 查看目前天數。\nAI 翻譯結果仍請重要內容再人工確認。"
        ))
    except Exception as e:
        print("[推薦獎勵通知 referred] 失敗: " + str(e))

    return {
        'referrer_id': referrer_id,
        'referred_id': referred_id,
        'referrer_days': referrer_days,
        'referred_days': referred_days,
    }


def referral_plan_key_from_plan(plan, owner_type='user'):
    if owner_type == 'group':
        if plan == 'pro':
            return 'group_pro'
        if plan == 'trial':
            return 'group_trial'
        return 'group_basic'
    if plan == 'yearly':
        return 'personal_yearly'
    if plan == 'trial':
        return 'personal_trial'
    return 'personal_monthly'


def record_manual_payment(owner_id, amount, plan, note='manual_admin_activate'):
    if not amount or int(amount) <= 0:
        return
    tw_now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO payments (user_id, amount, plan, payment_date, status, note)
                 VALUES (%s, %s, %s, %s, %s, %s)''',
              (owner_id, int(amount), plan, tw_now, 'success', note))
    conn.commit()
    conn.close()


def get_user_lang(user_id):
    user = get_user(user_id)
    return (user[5], user[6])


# ===== 忽略詞操作 =====
def get_ignore_words(owner_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT word FROM ignore_words WHERE owner_id=%s ORDER BY created_at ASC', (owner_id,))
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]


def add_ignore_words(owner_id, words):
    conn = get_db()
    c = conn.cursor()
    added = []
    for w in words:
        w = w.strip()
        if not w:
            continue
        try:
            c.execute('INSERT INTO ignore_words (owner_id, word) VALUES (%s, %s)', (owner_id, w))
            added.append(w)
        except:
            pass  # UNIQUE constraint，已存在就跳過
    conn.commit()
    conn.close()
    return added


def delete_ignore_word(owner_id, word):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM ignore_words WHERE owner_id=%s AND word=%s', (owner_id, word.strip()))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def apply_ignore_words(text, ignore_list):
    # 翻譯前：把忽略詞換成佔位符，回傳 (處理後文字, 還原對照表)
    if not ignore_list:
        return text, {}
    placeholder_map = {}
    result = text
    for i, word in enumerate(ignore_list):
        placeholder = '__IGN' + str(i) + '__'
        if word in result:
            result = result.replace(word, placeholder)
            placeholder_map[placeholder] = word
    return result, placeholder_map


def restore_ignore_words(text, placeholder_map):
    # 翻譯後：把佔位符換回原詞
    result = text
    for placeholder, word in placeholder_map.items():
        result = result.replace(placeholder, word)
    return result


# ===== 常用句操作 =====
def save_phrase(owner_id, name, content):
    """儲存常用句，回傳 True=新增成功，False=名稱已存在"""
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO saved_phrases (owner_id, name, content) VALUES (%s,%s,%s)',
                  (owner_id, name.strip(), content.strip()))
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False


def get_phrases(owner_id):
    """取得常用句清單，回傳 [(name, content), ...]"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT name, content FROM saved_phrases WHERE owner_id=%s ORDER BY created_at ASC', (owner_id,))
    rows = c.fetchall()
    conn.close()
    return rows


def delete_phrase(owner_id, name):
    """刪除常用句，回傳 True=成功，False=找不到"""
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM saved_phrases WHERE owner_id=%s AND name=%s', (owner_id, name.strip()))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def get_phrase_content(owner_id, name):
    """取得單一常用句內容，找不到回傳 None"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT content FROM saved_phrases WHERE owner_id=%s AND name=%s', (owner_id, name.strip()))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None


# ===== 行業詞庫 =====
INDUSTRY_PRESETS = {
    '製造業': [
        '班長', '領班', '作業員', '機台', '模具', '衝床', '車床', '銑床', '鑽床',
        '品管', 'QC', 'QA', '不良品', '良品', '報廢', '重工', '抽檢', '全檢',
        '產線', '流水線', '生產線', '工單', '備料', '換線', '停機', '保養',
        '安全帽', '手套', '防護眼鏡', '警示燈', '緊急停機', '消防栓',
        'kg', 'mm', 'pcs', 'lot', '批次', '料號', 'BOM'
    ],
    '餐飲': [
        '備料', '前置作業', '出餐', '外帶', '內用', '訂位', '催菜',
        '主廚', '二廚', '學徒', '外場', '內場', '洗碗工', '收銀',
        '食材', '食材驗收', '庫存', '冷凍', '冷藏', '常溫', '效期',
        '清潔', '消毒', '截切', '醃漬', '預熱', '打烊', '結帳',
        '菜單', '套餐', '單點', '飲料', '甜點', '加點'
    ],
    '建築': [
        '工地', '工班', '師傅', '學徒', '工頭', '監工', '工程師',
        '鋼筋', '混凝土', '模板', '鷹架', '吊車', '怪手', '壓路機',
        '澆置', '搗實', '養護', '拆模', '綁筋', '焊接', '切割',
        '安全帽', '安全繩', '護欄', '禁止進入', '小心落物', '危險',
        '圖說', '施工圖', '竣工', '驗收', '變更設計', '追加減帳'
    ],
    '農業': [
        '農地', '溫室', '網室', '育苗', '移植', '定植', '採收',
        '施肥', '噴藥', '灌溉', '除草', '疏果', '套袋', '修枝',
        '有機肥', '化肥', '農藥', '除蟲', '病害', '蟲害',
        '產銷履歷', '有機認證', '包裝', '分級', '冷鏈', '運輸',
        '耕耘機', '插秧機', '收割機', '噴藥機', '水泵'
    ]
}

INDUSTRY_NAME_MAP = {
    '製造': '製造業', '製造業': '製造業', 'manufacturing': '製造業',
    '餐飲': '餐飲', '餐廳': '餐飲', '廚房': '餐飲', 'food': '餐飲',
    '建築': '建築', '工地': '建築', '營造': '建築', 'construction': '建築',
    '農業': '農業', '農場': '農業', '農園': '農業', 'farm': '農業'
}

def init_industry_words():
    """初始化行業詞庫（第一次啟動時塞入預設詞）"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM industry_words')
    count = c.fetchone()[0]
    if count == 0:
        for industry, words in INDUSTRY_PRESETS.items():
            for word in words:
                try:
                    c.execute('INSERT INTO industry_words (industry, word) VALUES (%s,%s) ON CONFLICT (industry, word) DO NOTHING',
                              (industry, word))
                except:
                    pass
        conn.commit()
    conn.close()

init_industry_words()  # 在定義後立即呼叫

# ===== 群組勿擾模式 =====
def set_group_dnd(group_id, start_hour, start_min, end_hour, end_min):
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO group_dnd
        (group_id, start_hour, start_min, end_hour, end_min)
        VALUES (%s,%s,%s,%s,%s)
        ON CONFLICT (group_id) DO UPDATE SET start_hour=EXCLUDED.start_hour, start_min=EXCLUDED.start_min, end_hour=EXCLUDED.end_hour, end_min=EXCLUDED.end_min''', (group_id, start_hour, start_min, end_hour, end_min))
    conn.commit()
    conn.close()

def clear_group_dnd(group_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM group_dnd WHERE group_id=%s', (group_id,))
    conn.commit()
    conn.close()

def get_group_dnd(group_id):
    """回傳 (start_hour, start_min, end_hour, end_min) 或 None"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT start_hour, start_min, end_hour, end_min FROM group_dnd WHERE group_id=%s', (group_id,))
    row = c.fetchone()
    conn.close()
    return row

def is_group_in_dnd(group_id):
    """檢查群組目前是否在勿擾時段內（台灣時間）"""
    dnd = get_group_dnd(group_id)
    if not dnd:
        return False
    sh, sm, eh, em = dnd
    now_tw = datetime.utcnow() + timedelta(hours=8)
    now_minutes = now_tw.hour * 60 + now_tw.minute
    start_minutes = sh * 60 + sm
    end_minutes = eh * 60 + em
    if start_minutes <= end_minutes:
        # 同日時段，例如 09:00-18:00
        return start_minutes <= now_minutes <= end_minutes
    else:
        # 跨日時段，例如 22:00-07:00
        return now_minutes >= start_minutes or now_minutes <= end_minutes


# ===== 群組持久多語設定 =====
def set_group_multilang(group_id, lang_list):
    """設定群組持久多語，lang_list = [(code, name), ...]"""
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM group_multilang WHERE group_id=%s', (group_id,))
    for i, (code, name) in enumerate(lang_list):
        c.execute('INSERT INTO group_multilang (group_id, lang_code, lang_name, sort_order) VALUES (%s,%s,%s,%s)',
                  (group_id, code, name, i))
    conn.commit()
    conn.close()

def clear_group_multilang(group_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM group_multilang WHERE group_id=%s', (group_id,))
    conn.commit()
    conn.close()

def get_group_multilang(group_id):
    """回傳 [(code, name), ...] 或 []"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT lang_code, lang_name FROM group_multilang WHERE group_id=%s ORDER BY sort_order',
              (group_id,))
    rows = [(r[0], r[1]) for r in c.fetchall()]
    conn.close()
    return rows


def load_industry_words(owner_id, industry):
    """把行業詞庫載入為該用戶的忽略詞，回傳新增數量"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT word FROM industry_words WHERE industry=%s', (industry,))
    words = [row[0] for row in c.fetchall()]
    added = 0
    for word in words:
        try:
            c.execute('INSERT INTO ignore_words (owner_id, word) VALUES (%s,%s) ON CONFLICT (owner_id, word) DO NOTHING',
                      (owner_id, word))
            if c.rowcount > 0:
                added += 1
        except:
            pass
    conn.commit()
    conn.close()
    return added, len(words)


# ===== 整頁網址翻譯 =====
def fetch_url_text(url):
    """抓取網址內容，回傳純文字，失敗回傳 None"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; WanyuTong/1.0)'}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        # 移除 HTML 標籤
        text = re.sub(r'<script[^>]*>.*?</script>', '', resp.text, flags=re.DOTALL)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL)
        text = re.sub(r'<[^>]+>', '', text)
        text = re.sub(r'&nbsp;', ' ', text)
        text = re.sub(r'&amp;', '&', text)
        text = re.sub(r'&lt;', '<', text)
        text = re.sub(r'&gt;', '>', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text[:3000]  # 最多 3000 字元
    except Exception as e:
        return None

def translate_url_content(url, target_lang, target_lang_name, lang_a_name):
    """翻譯網址內容，回傳翻譯結果訊息"""
    page_text = fetch_url_text(url)
    if not page_text:
        return "❌ 無法讀取該網址內容。\n可能原因：網站拒絕訪問、需要登入、或網址無效。"
    if len(page_text) < 20:
        return "❌ 該網頁內容太少，無法翻譯。"
    # 分段翻譯（每段 500 字元）
    chunk_size = 500
    chunks = [page_text[i:i+chunk_size] for i in range(0, len(page_text), chunk_size)]
    translated_parts = []
    for chunk in chunks[:6]:  # 最多翻 6 段（約 3000 字）
        try:
            result = translator.translate_text(chunk, target_lang=target_lang)
            translated_parts.append(result.text)
        except:
            break
    if not translated_parts:
        return "❌ 翻譯失敗，請稍後再試。"
    total_chars = len(page_text)
    translated_text = '\n'.join(translated_parts)
    header = ("🌐 網址內容翻譯\n"
              "目標語言：" + target_lang_name + "\n"
              "原文長度：約 " + str(total_chars) + " 字元\n"
              "（已翻譯前 " + str(min(total_chars, 3000)) + " 字元）\n"
              "─────────────\n")
    return header + translated_text


# ===== 翻譯品質評分 =====
# 記錄最近一次翻譯，等待評分
last_translation = {}  # {owner_id: (original, translated)}

def save_rating(owner_id, original, translated, rating):
    conn = get_db()
    c = conn.cursor()
    tw_now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute('INSERT INTO translation_ratings (owner_id, original_text, translated_text, rating, created_at) VALUES (%s,%s,%s,%s,%s)',
              (owner_id, original, translated, rating, tw_now))
    conn.commit()
    conn.close()


# ===== 翻譯歷史操作 =====
def save_translation_history(owner_id, original, translated, direction):
    try:
        tw_now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO translation_history (owner_id, original, translated, direction, created_at) VALUES (%s, %s, %s, %s, %s)',
                  (owner_id, original[:500], translated[:500], direction, tw_now))
        # 只保留最近100筆，刪除多的
        c.execute('''DELETE FROM translation_history WHERE owner_id=%s AND id NOT IN (
            SELECT id FROM translation_history WHERE owner_id=%s ORDER BY id DESC LIMIT 100
        )''', (owner_id, owner_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print("[翻譯歷史] 儲存失敗: " + str(e))


def get_translation_history(owner_id, limit=20):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT original, translated, direction, created_at FROM translation_history WHERE owner_id=%s ORDER BY id DESC LIMIT %s',
              (owner_id, limit))
    rows = c.fetchall()
    conn.close()
    return rows  # 最新在前


# ===== 語音轉錄（Whisper）=====
def transcribe_audio(audio_data):
    # audio_data: bytes（LINE 下載的 m4a 音訊）
    # 回傳轉錄文字，失敗回傳 None
    try:
        import io
        audio_file = io.BytesIO(audio_data)
        audio_file.name = 'audio.m4a'
        transcript = openai_client.audio.transcriptions.create(
            model='whisper-1',
            file=audio_file,
        )
        return transcript.text.strip()
    except Exception as e:
        print("[語音轉錄] 失敗: " + str(e))
        return None


def get_user_lang_pair(user_id):
    # 回傳 (lang_a_code, lang_a_name, lang_b_code, lang_b_name)
    # lang_a 是新增欄位，舊用戶可能是 NULL，預設繁體中文
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT target_lang, target_name, lang_a, lang_a_name FROM users WHERE user_id=%s', (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return ('ZH-HANT', '繁體中文', 'ID', '印尼文')
    lang_b_code = row[0] or 'ID'
    lang_b_name = row[1] or '印尼文'
    lang_a_code = row[2] or 'ZH-HANT'
    lang_a_name = row[3] or '繁體中文'
    return (lang_a_code, lang_a_name, lang_b_code, lang_b_name)


def set_user_lang(user_id, lang_code, lang_name):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET target_lang=%s, target_name=%s WHERE user_id=%s',
              (lang_code, lang_name, user_id))
    conn.commit()
    conn.close()


def set_user_lang_pair(user_id, lang_a_code, lang_a_name, lang_b_code, lang_b_name):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET lang_a=%s, lang_a_name=%s, target_lang=%s, target_name=%s WHERE user_id=%s',
              (lang_a_code, lang_a_name, lang_b_code, lang_b_name, user_id))
    conn.commit()
    conn.close()


# ===== 群組資料庫操作 =====
def get_group(group_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM groups WHERE group_id=%s', (group_id,))
    row = c.fetchone()
    if not row:
        c.execute('INSERT INTO groups (group_id) VALUES (%s)', (group_id,))
        conn.commit()
        c.execute('SELECT * FROM groups WHERE group_id=%s', (group_id,))
        row = c.fetchone()
    conn.close()
    return row


def is_group_active(group_id):
    row = get_group(group_id)
    if row[1] != 'active':
        return False
    expire = row[3]
    if expire:
        try:
            tw_today = (datetime.utcnow() + timedelta(hours=8)).date()
            if datetime.strptime(expire, '%Y-%m-%d').date() >= tw_today:
                return True
        except:
            pass
    return False


def is_group_translating(group_id):
    row = get_group(group_id)
    return row[8] == 1


def set_group_translating(group_id, flag):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE groups SET is_translating=%s WHERE group_id=%s', (1 if flag else 0, group_id))
    conn.commit()
    conn.close()


def set_group_langs(group_id, lang_a, lang_a_name, lang_b, lang_b_name):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE groups SET lang_a=%s, lang_a_name=%s, lang_b=%s, lang_b_name=%s WHERE group_id=%s',
              (lang_a, lang_a_name, lang_b, lang_b_name, group_id))
    conn.commit()
    conn.close()


def activate_group(group_id, plan, days, note=''):
    expire = (datetime.utcnow() + timedelta(hours=8) + timedelta(days=days)).strftime('%Y-%m-%d')
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO groups (group_id) VALUES (%s) ON CONFLICT (group_id) DO NOTHING', (group_id,))
    c.execute('UPDATE groups SET status=%s, plan=%s, expire_date=%s, note=%s WHERE group_id=%s',
              ('active', plan, expire, note, group_id))
    conn.commit()
    conn.close()


# ===== 群組翻譯語言對照表（36 種）=====
GROUP_LANG_MAP = {
    '繁體中文': ('ZH-HANT', '繁體中文'),
    '簡體中文': ('ZH-HANS', '簡體中文'),
    '英文':     ('EN-US',   '英文'),
    '日文':     ('JA',      '日文'),
    '韓文':     ('KO',      '韓文'),
    '印尼文':   ('ID',      '印尼文'),
    '越南文':   ('VI',      '越南文'),
    '泰文':     ('TH',      '泰文'),
    '法文':     ('FR',      '法文'),
    '德文':     ('DE',      '德文'),
    '西班牙文': ('ES',      '西班牙文'),
    '俄文':     ('RU',      '俄文'),
    '葡萄牙文': ('PT-BR',   '葡萄牙文'),
    '義大利文': ('IT',      '義大利文'),
    '阿拉伯文': ('AR',      '阿拉伯文'),
    '荷蘭文':   ('NL',      '荷蘭文'),
    '波蘭文':   ('PL',      '波蘭文'),
    '土耳其文': ('TR',      '土耳其文'),
    '瑞典文':   ('SV',      '瑞典文'),
    '捷克文':   ('CS',      '捷克文'),
    '羅馬尼亞文': ('RO',    '羅馬尼亞文'),
    '匈牙利文': ('HU',      '匈牙利文'),
    '希伯來文': ('HE',      '希伯來文'),
    '保加利亞文': ('BG',    '保加利亞文'),
    '丹麥文':   ('DA',      '丹麥文'),
    '芬蘭文':   ('FI',      '芬蘭文'),
    '希臘文':   ('EL',      '希臘文'),
    '愛沙尼亞文': ('ET',    '愛沙尼亞文'),
    '拉脫維亞文': ('LV',    '拉脫維亞文'),
    '立陶宛文': ('LT',      '立陶宛文'),
    '挪威文':   ('NB',      '挪威文'),
    '斯洛伐克文': ('SK',    '斯洛伐克文'),
    '斯洛維尼亞文': ('SL',  '斯洛維尼亞文'),
    '烏克蘭文': ('UK',      '烏克蘭文'),
    '馬來文':   ('MS',      '馬來文'),
    '印尼文':   ('ID',      '印尼文'),
}


def group_translate(text, group_id):
    row = get_group(group_id)
    lang_a = row[4]
    lang_a_name = row[5]
    lang_b = row[6]
    lang_b_name = row[7]
    try:
        ignore_list = get_ignore_words(group_id)
        clean_text, ph_map = apply_ignore_words(text, ignore_list)
        detected = translator.translate_text(clean_text, target_lang='EN-US')
        src = detected.detected_source_lang.upper()
        lang_a_base = lang_a.split('-')[0].upper()
        lang_b_base = lang_b.split('-')[0].upper()
        if src in [lang_a_base, lang_a.upper()]:
            result = translator.translate_text(clean_text, target_lang=lang_b)
            translated_text = restore_ignore_words(result.text, ph_map)
            direction = lang_a_name + " → " + lang_b_name
            save_translation_history(group_id, text, translated_text, direction)
            return translated_text + "\n（" + direction + "）"
        elif src in [lang_b_base, lang_b.upper()]:
            result = translator.translate_text(clean_text, target_lang=lang_a)
            translated_text = restore_ignore_words(result.text, ph_map)
            direction = lang_b_name + " → " + lang_a_name
            save_translation_history(group_id, text, translated_text, direction)
            return translated_text + "\n（" + direction + "）"
        else:
            return None
    except Exception as e:
        print("[群組翻譯] 失敗: " + str(e))
        return None


GROUP_HELP_TEXT = """📖 萬語通群組版指令
━━━━━━━━━━━━━━
直接傳文字：自動雙向翻譯
免費版：每日 15 次文字翻譯
付費版：語音翻譯；商務版加圖片 OCR

【語言】
@語言設定 繁體中文 印尼文
@語言
@多語 印尼文 越南文 泰文
@群組多語 關閉

【確認與管理】
@確認 明天8點上班
回覆 1：收到／2：不明白
@確認進度
@群組歷史
@勿擾 22:00-07:00

【常用句與忽略詞】
@儲存句 名稱 內容
@我的句子
@忽略 詞1 詞2
@忽略詞

【帳號】
@群組狀態
@方案
@購買 體驗版 / 商務版
@我的ID
@客服

【文件】
@條款 / @隱私 / @退費

⏰ 到期一律以台灣時間 UTC+8 計算。"""


# ===== 時區顯示與指令 =====
TIMEZONE_DISPLAY = {
    'Asia/Taipei':        '🇹🇼 台灣／台北 (UTC+8)',
    'Asia/Tokyo':         '🇯🇵 日本／東京 (UTC+9)',
    'Asia/Seoul':         '🇰🇷 韓國／首爾 (UTC+9)',
    'Asia/Bangkok':       '🇹🇭 泰國／曼谷 (UTC+7)',
    'Asia/Jakarta':       '🇮🇩 印尼／雅加達 (UTC+7)',
    'Asia/Singapore':     '🇸🇬 新加坡 (UTC+8)',
    'Asia/Kuala_Lumpur':  '🇲🇾 馬來西亞 (UTC+8)',
    'Asia/Manila':        '🇵🇭 菲律賓 (UTC+8)',
    'Asia/Ho_Chi_Minh':   '🇻🇳 越南 (UTC+7)',
    'Asia/Kolkata':       '🇮🇳 印度 (UTC+5:30)',
    'Asia/Dubai':         '🇦🇪 杜拜 (UTC+4)',
    'Asia/Riyadh':        '🇸🇦 沙烏地 (UTC+3)',
    'Europe/London':      '🇬🇧 英國 (UTC+0)',
    'Europe/Paris':       '🇫🇷 法國 (UTC+1)',
    'Europe/Berlin':      '🇩🇪 德國 (UTC+1)',
    'America/New_York':   '🇺🇸 美東 (UTC-5)',
    'America/Chicago':    '🇺🇸 美中 (UTC-6)',
    'America/Los_Angeles': '🇺🇸 美西 (UTC-8)',
    'Australia/Sydney':   '🇦🇺 澳洲／雪梨 (UTC+10)',
    'Pacific/Auckland':   '🇳🇿 紐西蘭 (UTC+12)',
    'UTC':                '🌐 UTC+0',
}

TIMEZONE_CMD = {
    '@台灣': 'Asia/Taipei', '@日本': 'Asia/Tokyo', '@韓國': 'Asia/Seoul',
    '@泰國': 'Asia/Bangkok', '@印尼時區': 'Asia/Jakarta', '@新加坡': 'Asia/Singapore',
    '@馬來西亞': 'Asia/Kuala_Lumpur', '@菲律賓': 'Asia/Manila', '@越南時區': 'Asia/Ho_Chi_Minh',
    '@印度': 'Asia/Kolkata', '@杜拜': 'Asia/Dubai', '@沙烏地': 'Asia/Riyadh',
    '@英國': 'Europe/London', '@法國': 'Europe/Paris', '@德國': 'Europe/Berlin',
    '@美東': 'America/New_York', '@美中': 'America/Chicago', '@美西': 'America/Los_Angeles',
    '@澳洲': 'Australia/Sydney', '@紐西蘭': 'Pacific/Auckland', '@UTC': 'UTC',
}

TIMEZONE_HELP = """🌍 時區設定指令

傳送以下指令設定您的時區：

🌏 亞洲
@台灣 @日本 @韓國
@泰國 @印尼時區 @新加坡
@馬來西亞 @菲律賓 @越南時區
@印度 @杜拜 @沙烏地

🌍 歐洲
@英國 @法國 @德國

🌎 美洲／大洋洲
@美東 @美中 @美西
@澳洲 @紐西蘭 @UTC

傳送 @我的時區 查看目前設定"""


def get_user_timezone(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT timezone FROM users WHERE user_id=%s', (user_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row and row[0] else 'Asia/Taipei'


def set_user_timezone(user_id, tz_str):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET timezone=%s WHERE user_id=%s', (tz_str, user_id))
    conn.commit()
    conn.close()


def get_user_today(user_id):
    tz = get_user_timezone(user_id)
    offset = TIMEZONE_OFFSETS.get(tz, 8)
    return (datetime.utcnow() + timedelta(hours=offset)).date()


def get_user_now_str(user_id):
    tz = get_user_timezone(user_id)
    offset = TIMEZONE_OFFSETS.get(tz, 8)
    return (datetime.utcnow() + timedelta(hours=offset)).strftime('%Y-%m-%d %H:%M')


# ===== 客服自動回覆文字 =====
CS_TEXTS = {
    'terms': """📋 萬語通使用條款
━━━━━━━━━━━━━━━━━━
1. 本服務由 11stars 開發營運。
2. 免費版每日 15 次翻譯，付費版依方案提供功能。
3. 到期日以台灣時間 UTC+8 計算。
4. 翻譯、語音、圖片 OCR 可能送至第三方 AI / 翻譯 / OCR 服務處理。
5. 翻譯結果僅供溝通參考，不保證法律、醫療、財務、契約或安全指示完全正確。
6. 禁止用於違法、詐騙、騷擾、散播不實資訊或侵害他人權益。

🔗 完整條款
https://one1stars-line-bot.onrender.com/terms

🔒 隱私政策
https://one1stars-line-bot.onrender.com/privacy""",

    'privacy': """🔒 萬語通隱私提醒
━━━━━━━━━━━━━━━━━━
本服務會處理：
• LINE User ID / Group ID
• 語言設定、用量、到期日
• 付款與後台操作紀錄
• 翻譯文字、語音轉錄、圖片辨識文字

⚠️ 請勿傳送
身分證、病歷、帳密、薪資、銀行資料、公司機密。

第三方處理：
翻譯內容可能送至 DeepL、Google、OpenAI、Anthropic 等服務。

資料查詢或刪除：
請聯繫客服 LINE ID：fishxit

完整政策：
https://one1stars-line-bot.onrender.com/privacy""",

    'refund': """💸 退費政策

⚠️ 本服務為數位內容，依消費者保護法第19條，數位內容一經提供即喪失解除契約權利，付款後原則上不退費。

【唯一例外】
付款後 24 小時內，若 Bot 完全無法回應（非網路、LINE 本身問題），可提出申請。

【不受理退費的情況】
• 已成功使用翻譯功能（即使只用 1 次）
• 翻譯品質不如預期
• 個人原因（不想用、忘記使用、操作不熟）
• 超過 24 小時
• 語音／圖片功能部分異常（文字翻譯仍正常）

【申請方式】
請於 24 小時內聯繫客服 LINE ID：fishxit
說明付款時間與問題截圖，審核後 5～7 工作天處理。
跨行轉帳手續費由申請人自行負擔。""",

    # 修正：移除戶名，僅保留銀行代碼與帳號
    'plan_detail': """💳 萬語通付費方案

📅 月付方案：NT$199／月
  • 無限次翻譯
  • 支援 36 種語言
  • 圖片 OCR 翻譯
  • 語音訊息翻譯

📆 年付方案：NT$1,590／年
  • 月付方案所有功能
  • 相當於每月 NT$133（買 8 個月送 4 個月）

免費版：每日 15 次，功能相同

🔄 續約說明：
到期後直接傳送 @購買 月付 或 @購買 年付
即可重新開通，方案無縫銜接，不需要聯繫客服。

💬 付款方式：
請聯繫客服 LINE ID：fishxit 索取匯款帳號
付款後請傳送截圖給客服確認開通

⚠️ 本服務為數位內容，付款後原則上不退費。
詳見退費政策：傳送 @退費 查看""",

    'plan_compare': """📊 方案差異說明

━━━━━━━━━━━━━━━━━
【個人版：月付 vs 年付】
━━━━━━━━━━━━━━━━━
功能完全一樣，只是付款方式不同。

月付 NT$199／月
年付 NT$1,590／年（買8個月送4個月）
→ 省下 NT$798，等於多用 4 個月

確定長期使用，年付比較划算。

━━━━━━━━━━━━━━━━━
【群組版：體驗版 vs 商務版】
━━━━━━━━━━━━━━━━━
體驗版 NT$199／月
✅ 文字翻譯（無限次）
✅ 語音訊息翻譯
✅ 翻譯歷史＋忽略詞

商務版 NT$499／月
✅ 體驗版所有功能
✅ 圖片 OCR 翻譯
   → 工廠警示貼紙
   → 主管傳的文件截圖
   → 員工帶來的證件

需要拍照翻譯，選商務版。
只需要文字和語音溝通，體驗版就夠。""",

    'contact': """💬 客服聯繫

LINE ID：fishxit

服務時間：每日回覆，一般 24 小時內處理

常見問題請先傳送：
@條款 → 使用條款與隱私權
@隱私 → 隱私與資料處理提醒
@退費 → 退費政策
@方案說明 → 方案詳細說明
@方案比較 → 各方案差異一覽
@方案 → 購買方式""",
}

CS_CMD = {
    '@條款': 'terms',
    '@使用條款': 'terms',
    '@隱私': 'privacy',
    '@隱私權': 'privacy',
    '@退費': 'refund',
    '@退款': 'refund',
    '@方案說明': 'plan_detail',
    '@方案比較': 'plan_compare',
    '@客服': 'contact',
}


# ===== 後台 API =====
@app.route('/admin/users', methods=['GET'])
def admin_users():
    if not check_admin_ip():
        return jsonify({'error': '存取被拒絕'}), 403
    if not check_api_rate_limit():
        return jsonify({'error': '請求過於頻繁，請稍後再試'}), 429
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT user_id, status, plan, expire_date, created_at FROM users')
    users = c.fetchall()
    conn.close()
    return jsonify([{
        'user_id': u[0], 'status': u[1], 'plan': u[2],
        'expire_date': u[3], 'created_at': u[4]
    } for u in users])


@app.route('/admin/referrals', methods=['GET'])
def admin_referrals():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM referral_codes")
    code_count = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM referral_records")
    total = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM referral_records WHERE status=%s", ('pending',))
    pending = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM referral_records WHERE status=%s", ('rewarded',))
    rewarded = c.fetchone()[0] or 0
    c.execute("SELECT COALESCE(SUM(referrer_reward_days),0), COALESCE(SUM(referred_reward_days),0) FROM referral_records WHERE status=%s",
              ('rewarded',))
    reward_days = c.fetchone()
    c.execute('''SELECT id, referral_code, referrer_id, referred_id, referred_type, status,
                        plan_key, referrer_reward_days, referred_reward_days, trade_no,
                        created_at, rewarded_at
                 FROM referral_records
                 ORDER BY id DESC LIMIT 100''')
    rows = c.fetchall()
    c.execute('''SELECT owner_id, owner_type, code, created_at
                 FROM referral_codes
                 ORDER BY created_at DESC LIMIT 100''')
    codes = c.fetchall()
    conn.close()
    return jsonify({
        'summary': {
            'code_count': code_count,
            'total': total,
            'pending': pending,
            'rewarded': rewarded,
            'referrer_reward_days': int(reward_days[0] or 0),
            'referred_reward_days': int(reward_days[1] or 0),
        },
        'records': [{
            'id': r[0],
            'referral_code': r[1],
            'referrer_id': r[2],
            'referred_id': r[3],
            'referred_type': r[4],
            'status': r[5],
            'plan_key': r[6],
            'referrer_reward_days': r[7],
            'referred_reward_days': r[8],
            'trade_no': r[9],
            'created_at': utc_to_tw(r[10]),
            'rewarded_at': utc_to_tw(r[11]) if r[11] else '',
        } for r in rows],
        'codes': [{
            'owner_id': r[0],
            'owner_type': r[1],
            'code': r[2],
            'created_at': utc_to_tw(r[3]),
        } for r in codes],
    })


@app.route('/admin/referral-test-award', methods=['POST'])
def admin_referral_test_award():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'TEST_REFERRAL_AWARD':
        return jsonify({'error': '請輸入 TEST_REFERRAL_AWARD 才能測試發獎'}), 400

    referred_id = (data.get('referred_id') or '').strip()
    referred_type = (data.get('referred_type') or 'user').strip()
    plan_key = (data.get('plan_key') or '').strip()
    if referred_id.startswith('C') or referred_type == 'group':
        return jsonify({'error': '推薦獎勵已改為僅限個人對個人，不能測試群組發獎'}), 400
    if referred_type != 'user':
        return jsonify({'error': 'referred_type 只能是 user'}), 400
    if not referred_id:
        return jsonify({'error': '缺少 referred_id'}), 400
    if not plan_key:
        plan_key = 'personal_monthly'
    if plan_key not in REFERRAL_REWARD_RULES:
        return jsonify({'error': '不支援的測試方案：' + plan_key}), 400

    award = award_referral_if_needed(
        referred_id,
        referred_type,
        plan_key,
        'TEST_REFERRAL_AWARD_' + (datetime.utcnow() + timedelta(hours=8)).strftime('%Y%m%d%H%M%S')
    )
    if not award:
        return jsonify({'error': '找不到待發獎的推薦紀錄。請先讓新個人帳號傳 @使用推薦碼 XXXXX 綁定。'}), 404

    log_admin_action('referral_test_award', referred_id, 'type=' + referred_type + ', plan_key=' + plan_key)
    return jsonify({'success': True, 'award': award})


@app.route('/admin/referral-test-bind', methods=['POST'])
def admin_referral_test_bind():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'TEST_REFERRAL_BIND':
        return jsonify({'error': '請輸入 TEST_REFERRAL_BIND 才能建立測試綁定'}), 400

    referred_id = (data.get('referred_id') or '').strip()
    referred_type = (data.get('referred_type') or 'user').strip()
    referral_code = normalize_referral_code(data.get('referral_code') or '')
    if referred_id.startswith('C') or referred_type == 'group':
        return jsonify({'error': '推薦獎勵已改為僅限個人對個人，不能測試群組綁定'}), 400
    if referred_type != 'user':
        return jsonify({'error': 'referred_type 只能是 user'}), 400
    if not referred_id:
        return jsonify({'error': '缺少 referred_id'}), 400
    if not referral_code:
        return jsonify({'error': '缺少 referral_code'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT owner_id FROM referral_codes WHERE code=%s', (referral_code,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': '找不到此推薦碼'}), 404
    referrer_id = row[0]
    if referrer_id == referred_id:
        conn.close()
        return jsonify({'error': '不能使用自己的推薦碼'}), 400

    # 測試專用：不檢查付款紀錄，並重建此對象的 pending 紀錄。
    c.execute('DELETE FROM referral_records WHERE referred_id=%s AND referred_type=%s',
              (referred_id, referred_type))
    c.execute('''INSERT INTO referral_records (referral_code, referrer_id, referred_id, referred_type, status)
                 VALUES (%s,%s,%s,%s,%s)''',
              (referral_code, referrer_id, referred_id, referred_type, 'pending'))
    conn.commit()
    conn.close()
    log_admin_action('referral_test_bind', referred_id,
                     'type=' + referred_type + ', code=' + referral_code + ', referrer=' + referrer_id)
    return jsonify({
        'success': True,
        'message': '已建立測試 pending 推薦綁定，可接著執行測試發獎',
        'referral_code': referral_code,
        'referrer_id': referrer_id,
        'referred_id': referred_id,
        'referred_type': referred_type,
    })


@app.route('/admin/referral-test-users', methods=['POST'])
def admin_referral_test_users():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'CREATE_REFERRAL_TEST_USERS':
        return jsonify({'error': '請輸入 CREATE_REFERRAL_TEST_USERS 才能建立推薦測試用戶'}), 400

    referrer_id = 'U_TEST_REFERRER_001'
    friend_id = 'U_TEST_FRIEND_001'
    tw_now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

    get_user(referrer_id)
    get_user(friend_id)
    code = ensure_referral_code(referrer_id, 'user')

    conn = get_db()
    c = conn.cursor()
    c.execute('''UPDATE users
                 SET status=%s, plan=%s, expire_date=NULL, target_lang=%s, target_name=%s,
                     lang_a=%s, lang_a_name=%s
                 WHERE user_id=%s''',
              ('free', 'none', 'ID', '印尼文', 'ZH-HANT', '繁體中文', referrer_id))
    c.execute('''UPDATE users
                 SET status=%s, plan=%s, expire_date=NULL, target_lang=%s, target_name=%s,
                     lang_a=%s, lang_a_name=%s
                 WHERE user_id=%s''',
              ('free', 'none', 'VI', '越南文', 'ZH-HANT', '繁體中文', friend_id))
    c.execute('DELETE FROM payments WHERE user_id IN (%s,%s)', (referrer_id, friend_id))
    c.execute('DELETE FROM referral_records WHERE referred_id=%s AND referred_type=%s',
              (friend_id, 'user'))
    c.execute('''INSERT INTO referral_records
                 (referral_code, referrer_id, referred_id, referred_type, status, created_at)
                 VALUES (%s,%s,%s,%s,%s,%s)''',
              (code, referrer_id, friend_id, 'user', 'pending', tw_now))
    conn.commit()
    conn.close()
    log_admin_action('referral_test_users', friend_id, 'referrer=' + referrer_id + ', code=' + code)
    return jsonify({
        'success': True,
        'message': '已建立推薦測試用戶與 pending 綁定。請到個人版管理開通新朋友 ID，驗證自動發獎。',
        'referrer_id': referrer_id,
        'friend_id': friend_id,
        'referral_code': code,
        'next_step': '個人版管理 → 開通用戶 → User ID 填 ' + friend_id + ' → 選月付或年付 → 開通',
    })


@app.route('/admin/user-info', methods=['GET'])
def admin_user_info():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    user_id = request.args.get('user_id', '').strip()
    if not user_id:
        return jsonify({'error': '缺少 user_id 參數'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT user_id, status, plan, expire_date, created_at, target_lang, target_name, timezone FROM users WHERE user_id=%s',
              (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': '找不到此用戶'}), 404

    tw_today = (datetime.utcnow() + timedelta(hours=8)).date().strftime('%Y-%m-%d')
    c.execute("""
        CREATE TABLE IF NOT EXISTS daily_usage (
            user_id TEXT, use_date TEXT, count INTEGER DEFAULT 0,
            PRIMARY KEY (user_id, use_date)
        )
    """)
    c.execute("SELECT count FROM daily_usage WHERE user_id=%s AND use_date=%s", (user_id, tw_today))
    usage_row = c.fetchone()
    today_used = usage_row[0] if usage_row else 0

    c.execute('SELECT reason, created_at FROM blacklist WHERE user_id=%s', (user_id,))
    bl = c.fetchone()
    conn.close()

    days_left = None
    is_really_active = False
    if row[3]:
        try:
            expire_d = datetime.strptime(row[3], '%Y-%m-%d').date()
            today_d = (datetime.utcnow() + timedelta(hours=8)).date()
            days_left = (expire_d - today_d).days
            is_really_active = (row[1] == 'active' and expire_d >= today_d)
        except:
            pass

    return jsonify({
        'user_id': row[0], 'status': row[1], 'is_really_active': is_really_active,
        'plan': row[2], 'expire_date': row[3], 'days_left': days_left,
        'created_at': row[4], 'target_lang': row[5], 'target_name': row[6],
        'timezone': row[7] or 'Asia/Taipei',
        'today_used': today_used, 'today_remain_free': max(0, FREE_DAILY_LIMIT - today_used),
        'is_blacklisted': bl is not None,
        'blacklist_reason': bl[0] if bl else None,
        'blacklist_since': bl[1] if bl else None,
        'query_at_taiwan_time': (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S'),
    })


@app.route('/admin/activate', methods=['POST'])
def admin_activate():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    user_id = (data.get('user_id') or '').strip()
    if not user_id:
        return jsonify({'error': '缺少 user_id'}), 400
    try:
        plan = validate_admin_plan(data.get('plan', 'monthly'), 'user')
        days = validate_admin_days(data.get('days', 30))
        amount = validate_admin_amount(data.get('amount', PLAN_AMOUNTS.get(plan, 0)))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT user_id FROM users WHERE user_id=%s', (user_id,))
    exists = c.fetchone()
    conn.close()
    if not exists:
        return jsonify({'error': '找不到此用戶'}), 404
    activate_user(user_id, plan, days)
    record_manual_payment(user_id, amount, plan, 'manual:user:' + user_id + ':' + plan + ':' + str(days))
    award_referral_if_needed(user_id, 'user', referral_plan_key_from_plan(plan, 'user'), 'manual_admin_activate')
    log_admin_action('activate_user', user_id, 'plan=' + str(plan) + ', days=' + str(days) + ', amount=' + str(amount))
    tw_expire = (datetime.utcnow() + timedelta(hours=8) + timedelta(days=days)).strftime('%Y-%m-%d')
    try:
        line_bot_api.push_message(user_id, TextSendMessage(
            text="✅ 萬語通已開通！\n方案：" + plan + "\n到期日：" + tw_expire + "\n\n感謝您的支持！"
        ))
    except Exception as e:
        print("[個人開通通知] 失敗: " + str(e))
    return jsonify({'success': True})


@app.route('/admin/backfill-payment', methods=['POST'])
def admin_backfill_payment():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    owner_id = (data.get('owner_id') or '').strip()
    owner_type = (data.get('owner_type') or 'user').strip()
    if owner_id.startswith('C'):
        owner_type = 'group'
    raw_plan = (data.get('plan') or 'monthly').strip()
    note = (data.get('note') or 'manual_backfill').strip()
    plan = normalize_plan_key(raw_plan, owner_type, data.get('amount'))
    try:
        amount = int(data.get('amount', PLAN_AMOUNTS.get(plan, 0)))
    except:
        return jsonify({'error': '金額格式錯誤'}), 400
    if not owner_id:
        return jsonify({'error': '缺少 owner_id'}), 400
    if owner_type not in ('user', 'group'):
        return jsonify({'error': 'owner_type 只能是 user 或 group'}), 400
    if plan not in PLAN_AMOUNTS:
        return jsonify({'error': '不支援的方案：' + str(raw_plan) + '。可用：trial / monthly / yearly / basic / pro'}), 400
    if amount < 0:
        return jsonify({'error': '金額不可小於 0'}), 400
    expected_amount = PLAN_AMOUNTS.get(plan)
    generic_notes = ('', 'manual_backfill', '舊付款補記')
    if expected_amount is not None and amount != expected_amount and note in generic_notes:
        return jsonify({'error': '金額與方案預設不一致，請在備註寫明折扣、補差或更正原因'}), 400
    if len(note) > 200:
        return jsonify({'error': '備註不可超過 200 字'}), 400

    conn = get_db()
    c = conn.cursor()
    if owner_type == 'group':
        c.execute('SELECT group_id FROM groups WHERE group_id=%s', (owner_id,))
    else:
        c.execute('SELECT user_id FROM users WHERE user_id=%s', (owner_id,))
    exists = c.fetchone()
    conn.close()
    if not exists:
        return jsonify({'error': '找不到此' + ('群組' if owner_type == 'group' else '用戶')}), 404

    record_manual_payment(owner_id, amount, plan, 'backfill:' + owner_type + ':' + owner_id + ':' + plan + ':' + note)
    log_admin_action('backfill_payment', owner_id, 'type=' + owner_type + ', plan=' + plan + ', amount=' + str(amount) + ', note=' + note)
    return jsonify({'success': True, 'owner_id': owner_id, 'owner_type': owner_type, 'plan': plan, 'amount': amount})


@app.route('/admin/deactivate', methods=['POST'])
def admin_deactivate():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    user_id = (data.get('user_id') or '').strip()
    if not user_id:
        return jsonify({'error': '缺少 user_id'}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET status=%s WHERE user_id=%s', ('inactive', user_id))
    if c.rowcount == 0:
        conn.rollback()
        conn.close()
        return jsonify({'error': '找不到此用戶'}), 404
    conn.commit()
    conn.close()
    log_admin_action('deactivate_user', user_id, '')
    return jsonify({'success': True})


@app.route('/admin/set-expire', methods=['POST'])
def admin_set_expire():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    user_id = (data.get('user_id') or '').strip()
    if not user_id:
        return jsonify({'error': '缺少 user_id'}), 400
    try:
        expire_date = validate_admin_date(data.get('expire_date'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET expire_date=%s, status=%s WHERE user_id=%s',
              (expire_date, 'active', user_id))
    if c.rowcount == 0:
        conn.rollback()
        conn.close()
        return jsonify({'error': '找不到此用戶'}), 404
    conn.commit()
    conn.close()
    log_admin_action('set_user_expire', user_id, 'expire_date=' + expire_date)
    return jsonify({'success': True})


@app.route('/admin/test-expiry', methods=['GET'])
def test_expiry():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    tw_now = datetime.utcnow() + timedelta(hours=8)
    tw_today = tw_now.strftime('%Y-%m-%d')
    tw_remind = (tw_now + timedelta(days=3)).strftime('%Y-%m-%d')
    c.execute('SELECT user_id, expire_date FROM users WHERE status=%s AND expire_date=%s',
              ('active', tw_remind))
    remind_users = c.fetchall()
    c.execute('SELECT user_id, expire_date FROM users WHERE status=%s AND expire_date<%s',
              ('active', tw_today))
    expired_users = c.fetchall()
    conn.close()
    return jsonify({
        'taiwan_now': tw_now.strftime('%Y-%m-%d %H:%M'),
        'taiwan_today': tw_today,
        'remind_in_3_days': [{'user_id': u[0], 'expire_date': u[1]} for u in remind_users],
        'already_expired': [{'user_id': u[0], 'expire_date': u[1]} for u in expired_users]
    })


@app.route('/admin/run-expiry', methods=['POST'])
def run_expiry():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'RUN_EXPIRY':
        return jsonify({'error': '請確認 RUN_EXPIRY 才能執行個人到期檢查'}), 400
    conn = get_db()
    c = conn.cursor()
    tw_now = datetime.utcnow() + timedelta(hours=8)
    tw_today = tw_now.strftime('%Y-%m-%d')
    tw_remind = (tw_now + timedelta(days=3)).strftime('%Y-%m-%d')

    c.execute('SELECT user_id, expire_date FROM users WHERE status=%s AND expire_date=%s',
              ('active', tw_remind))
    remind_rows = c.fetchall()
    reminded = 0
    for user_id, expire_date in remind_rows:
        try:
            line_bot_api.push_message(user_id, TextSendMessage(
                text="⏰ 萬語通即將到期！\n到期日：" + expire_date + "\n\n請盡快續費，傳送 @方案 查看方式！"
            ))
            reminded += 1
        except:
            pass

    c.execute('SELECT user_id FROM users WHERE status=%s AND expire_date<%s',
              ('active', tw_today))
    expired_rows = c.fetchall()
    expired = 0
    for (user_id,) in expired_rows:
        c.execute('UPDATE users SET status=%s WHERE user_id=%s', ('inactive', user_id))
        try:
            line_bot_api.push_message(user_id, TextSendMessage(
                text="❌ 萬語通已到期！\n\n續費請直接傳送：\n@購買 月付 或 @購買 年付\n即可重新開通，感謝您的支持！"
            ))
            expired += 1
        except:
            pass

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'reminded': reminded, 'expired': expired})


# ===== 黑名單 API =====
@app.route('/admin/blacklist', methods=['GET'])
def admin_blacklist():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT user_id, reason, created_at FROM blacklist')
    rows = c.fetchall()
    conn.close()
    return jsonify([{'user_id': r[0], 'reason': r[1], 'created_at': r[2]} for r in rows])


@app.route('/admin/blacklist/add', methods=['POST'])
def admin_blacklist_add():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    user_id = (data.get('user_id') or '').strip()
    reason = (data.get('reason') or '手動封鎖').strip()
    if not user_id:
        return jsonify({'error': '缺少 user_id'}), 400
    if len(reason) > 200:
        return jsonify({'error': '封鎖原因不可超過 200 字'}), 400
    add_blacklist(user_id, reason)
    log_admin_action('blacklist_add', user_id, reason)
    return jsonify({'success': True})


@app.route('/admin/blacklist/remove', methods=['POST'])
def admin_blacklist_remove():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    user_id = (data.get('user_id') or '').strip()
    if not user_id:
        return jsonify({'error': '缺少 user_id'}), 400
    remove_blacklist(user_id)
    log_admin_action('blacklist_remove', user_id, '')
    return jsonify({'success': True})


# ===== 競品監控 API =====
@app.route('/admin/competitors')
def admin_competitors():
    with open('admin_competitors.html', 'r', encoding='utf-8') as f:
        return f.read()


@app.route('/admin/run-competitor-monitor', methods=['POST'])
def admin_run_competitor_monitor():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'RUN_COMPETITOR_MONITOR':
        return jsonify({'error': '請確認 RUN_COMPETITOR_MONITOR 才能執行競品監控'}), 400
    if not ADMIN_LINE_IDS:
        return jsonify({'error': 'ADMIN_LINE_IDS 未設定，請到 Render 環境變數新增'}), 400

    def run_in_background():
        try:
            run_competitor_monitor(
                line_token=os.environ.get('LINE_CHANNEL_ACCESS_TOKEN'),
                admin_user_ids=ADMIN_LINE_IDS,
                pg_url=DATABASE_URL,
            )
        except Exception as e:
            print("[競品監控] 背景執行失敗：" + str(e))

    t = threading.Thread(target=run_in_background, daemon=True)
    t.start()
    return jsonify({'success': True, 'message': '競品監控已在背景啟動，約1分鐘後完成，結果將推播到您的LINE'})


@app.route('/admin/competitor-snapshots')
def admin_competitor_snapshots():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    try:
        from competitor_monitor import COMPETITORS
        url_map = {}
        for c_def in COMPETITORS:
            url_map[(c_def['id'], 'pricing')] = c_def['pricing_url']
            url_map[(c_def['id'], 'news')] = c_def['news_url']
    except:
        url_map = {}

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT competitor_id, snapshot_type, content_hash, crawled_at
        FROM competitor_snapshots
        WHERE id IN (
            SELECT MAX(id) FROM competitor_snapshots
            GROUP BY competitor_id, snapshot_type
        )
        ORDER BY competitor_id
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'competitor_id': r[0], 'snapshot_type': r[1],
        'content_hash': r[2], 'crawled_at': utc_to_tw(r[3]),
        'url': url_map.get((r[0], r[1])),
    } for r in rows])


@app.route('/admin/competitor-reports')
def admin_competitor_reports():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT report_date, summary, sent_at FROM monitor_reports ORDER BY sent_at DESC LIMIT 7")
    rows = c.fetchall()
    conn.close()
    return jsonify([{'report_date': r[0], 'summary': r[1], 'sent_at': utc_to_tw(r[2])} for r in rows])


@app.route('/admin/competitor-history')
def admin_competitor_history():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT competitor_id, change_type, description, detected_at
        FROM competitor_changes ORDER BY detected_at DESC LIMIT 50
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'competitor_id': r[0], 'change_type': r[1],
        'description': r[2], 'detected_at': utc_to_tw(r[3]),
    } for r in rows])


@app.route('/admin/competitor-health')
def admin_competitor_health():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT report_date, sent_at FROM monitor_reports ORDER BY sent_at DESC LIMIT 1")
    last_report = c.fetchone()
    c.execute("""
        SELECT competitor_id, snapshot_type, MAX(crawled_at) as last_crawl
        FROM competitor_snapshots GROUP BY competitor_id, snapshot_type ORDER BY competitor_id
    """)
    snapshots = c.fetchall()
    c.execute("SELECT COUNT(*) FROM competitor_changes WHERE detected_at::timestamp >= NOW() - INTERVAL '7 days'")
    recent_changes = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM competitor_snapshots")
    total_snapshots = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM competitor_changes")
    total_changes = c.fetchone()[0]
    conn.close()

    competitor_status = {}
    for comp_id, snap_type, last_crawl in snapshots:
        if comp_id not in competitor_status:
            competitor_status[comp_id] = {}
        competitor_status[comp_id][snap_type] = utc_to_tw(last_crawl)

    tw_now = datetime.utcnow() + timedelta(hours=8)
    warnings = []
    if not last_report:
        warnings.append("尚未執行過任何監控，請先手動執行一次")
    else:
        try:
            last_sent = datetime.strptime(last_report[1], '%Y-%m-%d %H:%M:%S')
            hours_since = (datetime.utcnow() - last_sent).total_seconds() / 3600
            if hours_since > 30:
                warnings.append("最後一次報告已是 " + str(int(hours_since)) + " 小時前，排程可能有問題")
        except:
            pass
    if not ADMIN_LINE_IDS:
        warnings.append("ADMIN_LINE_IDS 環境變數未設定，無法推播報告")

    return jsonify({
        'status': 'warning' if warnings else 'ok',
        'warnings': warnings,
        'taiwan_now': tw_now.strftime('%Y-%m-%d %H:%M:%S'),
        'last_report': {
            'date': last_report[0] if last_report else None,
            'sent_at_taiwan': utc_to_tw(last_report[1]) if last_report else None,
        },
        'recent_7d_changes': recent_changes,
        'total_snapshots': total_snapshots,
        'total_changes': total_changes,
        'admin_line_ids_count': len(ADMIN_LINE_IDS),
        'competitor_last_crawl_taiwan': competitor_status,
        'schedule': '每天 23:30（台灣時間）= UTC 15:30 自動執行',
    })


@app.route('/admin/cs-texts', methods=['GET'])
def admin_cs_texts():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    return jsonify({
        'cs_texts': CS_TEXTS,
        'trigger_keywords': list(CS_CMD.keys()),
        'note': '用戶傳送觸發關鍵字時 Bot 會自動回覆對應文字',
    })


# ===== 語言設定（36 種）=====
LANG_MAP = {
    # 亞洲
    '@印尼':     ('ID',      '印尼文'),
    '@英文':     ('EN-US',   '英文'),
    '@日文':     ('JA',      '日文'),
    '@韓文':     ('KO',      '韓文'),
    '@泰文':     ('TH',      '泰文'),
    '@越南':     ('VI',      '越南文'),
    '@馬來':     ('MS',      '馬來文'),
    # 歐洲常用
    '@法文':     ('FR',      '法文'),
    '@德文':     ('DE',      '德文'),
    '@西班牙':   ('ES',      '西班牙文'),
    '@俄文':     ('RU',      '俄文'),
    '@葡萄牙':   ('PT-BR',   '葡萄牙文'),
    '@義大利':   ('IT',      '義大利文'),
    '@荷蘭':     ('NL',      '荷蘭文'),
    '@波蘭':     ('PL',      '波蘭文'),
    '@土耳其':   ('TR',      '土耳其文'),
    '@瑞典':     ('SV',      '瑞典文'),
    '@捷克':     ('CS',      '捷克文'),
    '@羅馬尼亞': ('RO',      '羅馬尼亞文'),
    '@匈牙利':   ('HU',      '匈牙利文'),
    '@烏克蘭':   ('UK',      '烏克蘭文'),
    '@保加利亞': ('BG',      '保加利亞文'),
    '@丹麥':     ('DA',      '丹麥文'),
    '@芬蘭':     ('FI',      '芬蘭文'),
    '@希臘':     ('EL',      '希臘文'),
    '@愛沙尼亞': ('ET',      '愛沙尼亞文'),
    '@拉脫維亞': ('LV',      '拉脫維亞文'),
    '@立陶宛':   ('LT',      '立陶宛文'),
    '@挪威':     ('NB',      '挪威文'),
    '@斯洛伐克': ('SK',      '斯洛伐克文'),
    '@斯洛維尼亞': ('SL',    '斯洛維尼亞文'),
    # 中東
    '@阿拉伯':   ('AR',      '阿拉伯文'),
    '@希伯來':   ('HE',      '希伯來文'),
    # 中文
    '@簡體':     ('ZH-HANS', '簡體中文'),
}

HELP_TEXT = """📖 萬語通個人版指令
━━━━━━━━━━━━━━
直接傳文字：自動雙向翻譯
免費版：每日 15 次翻譯
圖片文字：自動 OCR 翻譯
語音訊息：付費版可用

【語言】
@語言設定 繁體中文 印尼文
@語言
@多語 印尼文 越南文 泰文

【常用句】
@儲存句 名稱 內容
@我的句子
@刪除句 名稱
@名稱

【歷史與忽略詞】
@歷史
@忽略 詞1 詞2
@忽略詞
@刪除忽略 詞

【帳號】
@到期
@方案
@方案說明
@購買 月付 / 年付
@推薦
@使用推薦碼 推薦碼
@我的ID

【文件】
@條款 / @隱私 / @退費
@客服

⏰ 到期一律以台灣時間 UTC+8 計算。"""

PLAN_TEXT = """💎 萬語通方案
━━━━━━━━━━━━━━━━━━
🆓 免費版
每日 15 次翻譯

👤 個人版
7日體驗：NT$49
月付：NT$199
年付：NT$1,590
功能：文字、圖片 OCR、語音翻譯、36 種語言

👥 群組版
7日體驗：NT$49
體驗版：NT$199 / 月
商務版：NT$499 / 月

體驗版：文字翻譯 + 語音翻譯
商務版：再加圖片 OCR

🔄 續約
到期後傳 @購買，即可重新開通。

💬 付款
請聯繫客服 LINE ID：fishxit
付款後傳截圖確認。

🎁 好友推薦
傳 @推薦 取得推薦碼。
推薦人把推薦碼給新朋友；新朋友首次付費前傳 @使用推薦碼 推薦碼。
付款成功後雙方都送翻譯天數，可傳 @到期 查看新的到期日。"""


# ===== 群組歡迎訊息 =====
def build_group_welcome(group_id):
    return (
        "🌐 萬語通已加入群組！翻譯已自動啟動。\n"
        "\n"
        "📋 此群組 ID（開通時需要）：\n"
        + group_id + "\n"
        "\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "📖 快速開始\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "\n"
        "🆓 免費試用：每日 15 次（立即可用）\n"
        "\n"
        "【STEP 1】設定翻譯語言\n"
        "@語言設定 繁體中文 印尼文\n"
        "（可替換為任意兩種語言）\n"
        "\n"
        "支援 36 種語言：\n"
        "繁體中文、英文、日文、韓文\n"
        "印尼文、越南文、泰文、馬來文 等\n"
        "\n"
        "【STEP 2】升級付費（無限翻譯）\n"
        "將群組 ID 傳給客服：LINE ID fishxit\n"
        "• 體驗版 NT$199／月（文字＋語音翻譯）\n"
        "• 商務版 NT$499／月（含圖片OCR，工廠貼紙、文件截圖直接翻）\n"
        "\n"
        "【常用指令】\n"
        "@群組狀態   → 查看方案與到期日\n"
        "@語言設定 中文 英文 → 切換語言\n"
        "@群組說明   → 顯示所有指令\n"
        "\n"
        "🔒 隱私提醒\n"
        "群組文字、語音或圖片可能送至翻譯／OCR／AI 服務處理。\n"
        "請勿傳送身分證、病歷、帳密、薪資、銀行資料或公司機密。\n"
        "完整政策可傳送 @隱私 查看。\n"
        "\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "💡 設定語言後即可直接開始翻譯！\n"
        "━━━━━━━━━━━━━━━━━━"
    )


# ===== Webhook =====
@app.route('/')
def health_check():
    return 'OK', 200


@app.route('/healthz')
def healthz():
    db_ok = False
    db_error = ''
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT 1')
        db_ok = c.fetchone()[0] == 1
        conn.close()
    except Exception as e:
        db_error = str(e)[:160]
    status = 'ok' if db_ok else 'error'
    http_status = 200 if db_ok else 503
    return jsonify({
        'status': status,
        'service': '11STARS-line-bot',
        'database': 'ok' if db_ok else 'error',
        'taiwan_time': (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S'),
        'error': db_error,
    }), http_status



@app.route('/webhook', methods=['POST'])
def webhook():
    # LINE webhook requests can share platform IPs across many users. Applying
    # crawler IP blocking here can silence every auto-reply for an hour.
    signature = request.headers.get('X-Line-Signature', '')
    body = request.get_data(as_text=True)
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)
    return 'OK'


def normalize_line_text(text):
    text = (text or '').strip().replace('＠', '@')
    if text.startswith('@ '):
        text = '@' + text[2:].lstrip()
    return text


# Bot 被邀請加入群組時觸發
@handler.add(JoinEvent)
def handle_join(event):
    if hasattr(event.source, 'group_id'):
        group_id = event.source.group_id
        # 加入即自動開始翻譯
        set_group_translating(group_id, True)
        try:
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text=build_group_welcome(group_id))
            )
        except Exception as e:
            print("[群組加入] 歡迎訊息發送失敗: " + str(e))


# Bot 被人拉進已存在的群組（MemberJoined）時也觸發
@handler.add(MemberJoinedEvent)
def handle_member_joined(event):
    if not hasattr(event.source, 'group_id'):
        return
    group_id = event.source.group_id
    # 只有當加入的成員包含 Bot 自己時才發歡迎訊息
    bot_id = None
    try:
        bot_id = line_bot_api.get_bot_info().user_id
    except:
        pass
    joined_ids = []
    try:
        joined_ids = [m.user_id for m in event.joined.members if hasattr(m, 'user_id')]
    except:
        pass
    if bot_id and bot_id not in joined_ids:
        return  # 不是 Bot 加入，是其他成員加入，略過
    # 加入即自動開始翻譯
    set_group_translating(group_id, True)
    try:
        line_bot_api.push_message(
            group_id,
            TextSendMessage(text=build_group_welcome(group_id))
        )
    except Exception as e:
        print("[群組成員加入] 歡迎訊息發送失敗: " + str(e))


@handler.add(MessageEvent, message=TextMessage)
def handle_text(event):
    user_id = event.source.user_id

    if hasattr(event.source, 'group_id'):
        group_id = event.source.group_id
        text = normalize_line_text(event.message.text)
        handle_group_text(event, group_id, user_id, text)
        return

    if is_blacklisted(user_id):
        return

    if not check_rate_limit(user_id):
        try:
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text="⚠️ 您的帳號因異常行為已被暫時封鎖，請聯繫客服。")
            )
        except:
            pass
        return

    text = normalize_line_text(event.message.text)
    user = get_user(user_id)
    active = is_active(user_id)

    if text == '@我的ID':
        reply = "你的LINE User ID：\n" + user_id

    elif text == '@語言':
        lang_a_code, lang_a_name, lang_b_code, lang_b_name = get_user_lang_pair(user_id)
        reply = "🌐 目前設定：" + lang_a_name + " ↔ " + lang_b_name

    elif text == '@說明':
        reply = HELP_TEXT

    elif text == '@方案':
        reply = PLAN_TEXT

    elif text == '@推薦' or text == '@推薦好友':
        code, total, rewarded = get_referral_summary(user_id)
        reply = ("🎁 萬語通好友推薦\n"
                 "━━━━━━━━━━━━━━\n"
                 "你的推薦碼：" + code + "\n\n"
                 "請把推薦碼給新朋友。\n"
                 "新朋友加入萬語通後，付款前傳送：\n"
                 "@使用推薦碼 " + code + "\n\n"
                 "好友首次付費成功後：\n"
                 "• 你可獲得 3-90 天翻譯天數\n"
                 "• 好友也可獲得 3-30 天翻譯天數\n"
                 "• 雙方可傳 @到期 查看新的到期日\n\n"
                 "目前推薦：" + str(total) + " 筆\n"
                 "已成功發獎：" + str(rewarded) + " 筆\n\n"
                 "獎勵以首次付費方案為準；不可自己推薦自己。")

    elif text.startswith('@使用推薦碼 ') or text.startswith('@使用推薦碼　'):
        code_input = text.replace('@使用推薦碼　', '').replace('@使用推薦碼 ', '').strip()
        ok, msg = bind_referral_code(user_id, 'user', code_input)
        reply = ("✅ " if ok else "⚠️ ") + msg

    elif text == '@購買' or text.startswith('@購買 '):
        if not ECPAY_MERCHANT_ID:
            reply = "💳 付款系統準備中，目前請聯繫客服 fishxit 手動開通。\n\n" + PLAN_TEXT
        else:
            pay_text = text.replace('@購買', '').strip()
            plan_map = {
                '7日': 'personal_trial', '體驗': 'personal_trial',
                '月付': 'personal_monthly', '月': 'personal_monthly',
                '年付': 'personal_yearly', '年': 'personal_yearly',
            }
            plan_key = plan_map.get(pay_text, '')
            if not plan_key:
                reply = ("💳 選擇購買方案，傳送以下指令：\n\n"
                         "@購買 7日 → NT$49（7天體驗）\n"
                         "@購買 月付 → NT$199（30天）\n"
                         "@購買 年付 → NT$1,590（365天，買8送4）")
            else:
                trade_no, html_or_err = ecpay_create_order(user_id, plan_key, is_group=False)
                if trade_no:
                    pay_url = BOT_BASE_URL + '/pay/' + trade_no + '/' + user_id + '/' + plan_key + '/user'
                    reply = ("💳 請點擊以下連結完成付款：\n\n" + pay_url +
                             "\n\n⚠️ 請用右下角 ··· → 在瀏覽器中開啟\n付款完成後系統將自動開通，無需等待。\n連結 30 分鐘內有效。")
                else:
                    reply = "❌ 建立訂單失敗，請聯繫客服 fishxit。"

    elif text in CS_CMD:
        reply = CS_TEXTS[CS_CMD[text]]

    elif text == '@到期':
        if active:
            try:
                expire_d = datetime.strptime(user[3], '%Y-%m-%d').date()
                tw_today = (datetime.utcnow() + timedelta(hours=8)).date()
                days_left = (expire_d - tw_today).days
                if days_left <= 3:
                    icon = '⚠️'
                    hint = '\n剩餘 ' + str(days_left) + ' 天，請盡快續費！\n傳送 @方案 查看方式'
                elif days_left <= 7:
                    icon = '⏰'
                    hint = '\n剩餘 ' + str(days_left) + ' 天'
                else:
                    icon = '✅'
                    hint = '\n剩餘 ' + str(days_left) + ' 天'
                reply = icon + " 狀態：使用中\n到期日：" + user[3] + hint + "\n（以台灣時間 UTC+8 為準）"
            except:
                reply = "✅ 狀態：使用中\n到期日：" + user[3] + "\n（以台灣時間 UTC+8 為準）"
        else:
            try:
                tw_today = (datetime.utcnow() + timedelta(hours=8)).date().strftime('%Y-%m-%d')
                conn_u = get_db()
                c_u = conn_u.cursor()
                c_u.execute("""
                    CREATE TABLE IF NOT EXISTS daily_usage (
                        user_id TEXT, use_date TEXT, count INTEGER DEFAULT 0,
                        PRIMARY KEY (user_id, use_date)
                    )
                """)
                c_u.execute("SELECT count FROM daily_usage WHERE user_id=%s AND use_date=%s",
                            (user_id, tw_today))
                row = c_u.fetchone()
                conn_u.close()
                used = row[0] if row else 0
                remain = max(0, FREE_DAILY_LIMIT - used)
                reply = "❌ 尚未開通付費方案\n\n📊 今日免費次數剩餘：" + str(remain) + "/" + str(FREE_DAILY_LIMIT) + "\n\n傳送 @方案 查看購買方式"
            except:
                reply = "❌ 尚未開通付費方案\n\n傳送 @方案 查看購買方式"

    elif text == '@我的時區':
        tz = get_user_timezone(user_id)
        display = TIMEZONE_DISPLAY.get(tz, tz)
        now_str = get_user_now_str(user_id)
        reply = "🌍 您的時區設定：\n" + display + "\n\n🕐 您的當地時間：" + now_str + "\n\n傳送 @時區設定 查看所有可設定的時區\n\n⚠️ 時區僅影響顯示，到期時間統一以台灣時間為準"

    elif text == '@時區設定':
        reply = TIMEZONE_HELP

    elif text in TIMEZONE_CMD:
        tz_str = TIMEZONE_CMD[text]
        set_user_timezone(user_id, tz_str)
        display = TIMEZONE_DISPLAY.get(tz_str, tz_str)
        now_str = get_user_now_str(user_id)
        reply = "✅ 時區已設定！\n" + display + "\n\n🕐 您的當地時間：" + now_str + "\n\n⚠️ 時區僅影響顯示，到期時間統一以台灣時間為準"

    elif text == '@選行業' or text == '@行業詞庫':
        reply = ("🏭 行業詞庫\n\n"
                 "選擇行業，自動載入專業忽略詞（翻譯時保留原文不翻）\n\n"
                 "@選行業 製造業\n"
                 "@選行業 餐飲\n"
                 "@選行業 建築\n"
                 "@選行業 農業\n\n"
                 "載入後可用 @忽略詞 查看清單。")

    elif text.startswith('@選行業 ') or text.startswith('@選行業　'):
        industry_input = text.replace('@選行業　', '').replace('@選行業 ', '').strip()
        industry = INDUSTRY_NAME_MAP.get(industry_input)
        if not industry:
            reply = ("❓ 找不到「" + industry_input + "」行業。\n\n"
                     "支援行業：\n製造業、餐飲、建築、農業\n\n"
                     "例如：@選行業 製造業")
        else:
            added, total = load_industry_words(user_id, industry)
            reply = ("✅ 已載入【" + industry + "】詞庫\n\n"
                     "共 " + str(total) + " 個專業詞\n"
                     "新增 " + str(added) + " 個忽略詞（已有的不重複加）\n\n"
                     "翻譯時這些專業術語將保留原文。\n"
                     "傳送 @忽略詞 查看完整清單。")

    elif text in ('👍', '👎'):
        if user_id in last_translation:
            orig, trans = last_translation[user_id]
            rating = 1 if text == '👍' else 0
            save_rating(user_id, orig, trans, rating)
            del last_translation[user_id]
            reply = "謝謝您的評分！" if rating == 1 else "謝謝您的回饋，我們會持續改善翻譯品質！"
        else:
            reply = "目前沒有可評分的翻譯記錄。"

    elif text.startswith('@儲存句 ') or text.startswith('@儲存句　'):
        # @儲存句 名稱 內容
        content_part = text.replace('@儲存句　', '').replace('@儲存句 ', '').strip()
        parts = content_part.split(' ', 1)
        if len(parts) < 2 or not parts[0] or not parts[1]:
            reply = "格式：@儲存句 名稱 內容\n例如：@儲存句 早安 早安！今天幾點上班？\n\n名稱不能有空格，內容可以很長。"
        else:
            pname, pcontent = parts[0], parts[1]
            if save_phrase(user_id, pname, pcontent):
                reply = "✅ 已儲存常用句「" + pname + "」\n\n傳送 @" + pname + " 即可直接翻譯這句話。\n傳送 @我的句子 查看所有常用句。"
            else:
                reply = "⚠️ 名稱「" + pname + "」已存在。\n請先用 @刪除句 " + pname + " 刪除後重新儲存，或換一個名稱。"

    elif text == '@我的句子':
        phrases = get_phrases(user_id)
        if not phrases:
            reply = "📋 目前沒有儲存的常用句。\n\n用 @儲存句 名稱 內容 新增常用句。\n例如：@儲存句 早安 早安！今天幾點上班？"
        else:
            lines = ["📋 常用句清單（" + str(len(phrases)) + " 個）\n"]
            for nm, ct in phrases:
                short = ct[:30] + "…" if len(ct) > 30 else ct
                lines.append("【@" + nm + "】 " + short)
            lines.append("\n傳送 @名稱 直接觸發翻譯")
            lines.append("傳送 @刪除句 名稱 刪除")
            reply = "\n".join(lines)

    elif text.startswith('@刪除句 ') or text.startswith('@刪除句　'):
        pname = text.replace('@刪除句　', '').replace('@刪除句 ', '').strip()
        if not pname:
            reply = "格式：@刪除句 名稱\n例如：@刪除句 早安"
        else:
            if delete_phrase(user_id, pname):
                reply = "✅ 已刪除常用句「" + pname + "」"
            else:
                reply = "❓ 找不到常用句「" + pname + "」\n\n傳送 @我的句子 查看清單"

    elif text == '@歷史':
        rows = get_translation_history(user_id, limit=20)
        if not rows:
            reply = "📋 目前沒有翻譯歷史記錄。"
        else:
            lines = ["📋 最近 " + str(len(rows)) + " 筆翻譯記錄（最新在上）\n"]
            for i, (orig, trans, direction, created_at) in enumerate(rows, 1):
                lines.append(str(i) + ". [" + created_at[5:16] + "] " + direction)
                lines.append("   原：" + orig)
                lines.append("   譯：" + trans)
            full = "\n".join(lines)
            # LINE 單則限 5000 字元，超過就截斷
            if len(full) > 4800:
                full = full[:4800] + "\n\n（記錄過長，已截斷）"
            reply = full

    elif text.startswith('@忽略') and not text.startswith('@忽略詞') and not text.startswith('@刪除忽略'):
        words_input = text.replace('@忽略', '').strip().split()
        if not words_input:
            reply = "格式：@忽略 詞1 詞2\n例如：@忽略 Budi COVID-19\n\n傳送 @忽略詞 查看目前清單"
        else:
            added = add_ignore_words(user_id, words_input)
            if added:
                reply = "✅ 已新增忽略詞：" + "、".join(added) + "\n翻譯時這些詞將保持原樣不翻譯。\n\n傳送 @忽略詞 查看完整清單"
            else:
                reply = "⚠️ 這些詞已在忽略清單中，無需重複新增。"

    elif text == '@忽略詞':
        words = get_ignore_words(user_id)
        if not words:
            reply = "📋 目前忽略詞清單為空。\n\n傳送 @忽略 詞1 詞2 新增忽略詞"
        else:
            reply = "📋 目前忽略詞（" + str(len(words)) + " 個）：\n" + "、".join(words) + "\n\n傳送 @刪除忽略 詞 可刪除單一忽略詞"

    elif text.startswith('@刪除忽略'):
        word_to_del = text.replace('@刪除忽略', '').strip()
        if not word_to_del:
            reply = "格式：@刪除忽略 詞\n例如：@刪除忽略 Budi"
        else:
            deleted = delete_ignore_word(user_id, word_to_del)
            if deleted:
                reply = "✅ 已刪除忽略詞：" + word_to_del
            else:
                reply = "❓ 找不到忽略詞：" + word_to_del + "\n\n傳送 @忽略詞 查看目前清單"

    elif text.startswith('@多語') or text.startswith('@ 多語'):
        clean_ml = text.replace('@ 多語', '').replace('@多語', '').strip()
        lang_names = clean_ml.split()
        if not lang_names:
            reply = "格式：@多語 語言1 語言2 語言3\n例如：@多語 印尼文 越南文 泰文\n\n傳送這個指令後，下一則訊息會同時翻成這些語言。"
        else:
            valid = []
            invalid = []
            for ln in lang_names:
                if ln in GROUP_LANG_MAP:
                    valid.append((GROUP_LANG_MAP[ln][0], GROUP_LANG_MAP[ln][1]))
                else:
                    invalid.append(ln)
            if invalid:
                reply = "❓ 不支援的語言：" + "、".join(invalid) + "\n\n傳送 @說明 查看可用語言清單"
            elif len(valid) > 8:
                reply = "⚠️ 最多同時翻譯 8 種語言，請減少語言數量。"
            else:
                multilang_pending[user_id] = valid
                names = "、".join([n for _, n in valid])
                reply = "✅ 已設定多語翻譯！\n目標語言：" + names + "\n\n請傳送要翻譯的文字，Bot 將同時翻成以上語言。"

    elif text in LANG_MAP:
        # 舊捷徑：@印尼 @英文 等 → lang_a 固定繁體中文，lang_b 為目標語言
        lang_b_code, lang_b_name = LANG_MAP[text]
        set_user_lang_pair(user_id, 'ZH-HANT', '繁體中文', lang_b_code, lang_b_name)
        reply = "✅ 語言已設定！\n繁體中文 ↔ " + lang_b_name + "\n翻譯已自動啟動。"

    elif text.startswith('@語言設定') or text.startswith('@ 語言設定'):
        # 完整雙語設定：@語言設定 語言A 語言B（任意兩種語言）
        clean = text.replace('@ 語言設定', '').replace('@語言設定', '').strip()
        parts = clean.split()
        if len(parts) < 2:
            reply = "格式：@語言設定 語言A 語言B\n例如：@語言設定 繁體中文 印尼文\n\n傳送 @說明 查看可用語言"
        else:
            name_a = parts[0]
            name_b = parts[1]
            if name_a not in GROUP_LANG_MAP:
                reply = "❓ 不支援的語言：" + name_a + "\n\n傳送 @說明 查看所有可用語言"
            elif name_b not in GROUP_LANG_MAP:
                reply = "❓ 不支援的語言：" + name_b + "\n\n傳送 @說明 查看所有可用語言"
            else:
                code_a, label_a = GROUP_LANG_MAP[name_a]
                code_b, label_b = GROUP_LANG_MAP[name_b]
                set_user_lang_pair(user_id, code_a, label_a, code_b, label_b)
                reply = "✅ 語言已設定！\n" + label_a + " ↔ " + label_b + "\n翻譯已自動啟動。"

    else:
        if user[1] == 'inactive' or (user[1] == 'active' and not is_active(user_id)):
            user_status = 'inactive'
        else:
            user_status = user[1]

        # ── 常用句觸發（@名稱 直接翻譯）──
        if text.startswith('@') and len(text) > 1:
            pname = text[1:].strip()
            pcontent = get_phrase_content(user_id, pname)
            if pcontent is not None:
                text = pcontent  # 把常用句內容當作輸入，繼續走翻譯流程

        # ── 整頁網址翻譯 ──
        if (text.startswith('http://') or text.startswith('https://')) and user_status != 'inactive':
            if user_status == 'free':
                reply = "🔒 整頁網址翻譯為付費版功能。\n傳送 @方案 查看升級方式。"
            else:
                user = get_user(user_id)
                lang_b_code = user[5] if user else 'ID'
                lang_b_name = user[6] if user else '印尼文'
                lang_a_name = user[7] if user else '繁體中文'
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="⏳ 正在讀取網頁並翻譯，請稍候..."))
                def do_url_translate():
                    result = translate_url_content(text, lang_b_code, lang_b_name, lang_a_name)
                    try:
                        line_bot_api.push_message(user_id, TextSendMessage(text=result))
                    except:
                        pass
                threading.Thread(target=do_url_translate).start()
            return

        # ── 多語翻譯（優先檢查）──
        if user_id in multilang_pending and user_status != 'inactive':
            lang_list = multilang_pending.pop(user_id)
            try:
                ignore_list = get_ignore_words(user_id)
                clean_text, ph_map = apply_ignore_words(text, ignore_list)
                lines = ["🌐 多語翻譯結果：\n原文：" + text]
                for lang_code, lang_name in lang_list:
                    result = translator.translate_text(clean_text, target_lang=lang_code)
                    translated_text = restore_ignore_words(result.text, ph_map)
                    lines.append("\n【" + lang_name + "】\n" + translated_text)
                    save_translation_history(user_id, text, translated_text, "多語 → " + lang_name)
                reply = "\n".join(lines)
            except Exception as e:
                reply = "多語翻譯失敗，請稍後再試。\n錯誤：" + str(e)

        elif user_status == 'inactive':
            reply = "❌ 您的帳號已停用或到期。\n\n傳送 @方案 查看續費方式，感謝您的支持！"

        elif user_status == 'free':
            today_str = get_user_today(user_id).strftime('%Y-%m-%d')
            conn_check = get_db()
            c_check = conn_check.cursor()
            c_check.execute("""
                CREATE TABLE IF NOT EXISTS daily_usage (
                    user_id TEXT, use_date TEXT, count INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, use_date)
                )
            """)
            c_check.execute("SELECT count FROM daily_usage WHERE user_id=%s AND use_date=%s",
                            (user_id, today_str))
            row = c_check.fetchone()
            today_count = row[0] if row else 0

            if today_count >= FREE_DAILY_LIMIT:
                reply = "⚠️ 免費版今日翻譯次數已達上限（" + str(FREE_DAILY_LIMIT) + "次）。\n\n升級付費方案即可無限使用！\n傳送 @方案 查看購買方式。"
                conn_check.close()
            else:
                c_check.execute("""
                    INSERT INTO daily_usage (user_id, use_date, count) VALUES (%s, %s, 1)
                    ON CONFLICT(user_id, use_date) DO UPDATE SET count = count + 1
                """, (user_id, today_str))
                conn_check.commit()
                conn_check.close()
                try:
                    lang_a_code, lang_a_name, lang_b_code, lang_b_name = get_user_lang_pair(user_id)
                    ignore_list = get_ignore_words(user_id)
                    clean_text, ph_map = apply_ignore_words(text, ignore_list)
                    detected = translator.translate_text(clean_text, target_lang='EN-US')
                    src = detected.detected_source_lang.upper()
                    lang_a_base = lang_a_code.split('-')[0].upper()
                    remain = FREE_DAILY_LIMIT - today_count - 1
                    suffix = "\n\n🆓 免費試用 " + str(today_count + 1) + "/" + str(FREE_DAILY_LIMIT) + "（今日剩餘 " + str(remain) + " 次）"
                    if remain == 0:
                        suffix += "\n升級付費方案即可無限使用！傳送 @方案 查看購買方式。"
                    if src in [lang_a_base, lang_a_code.upper()]:
                        result = translator.translate_text(clean_text, target_lang=lang_b_code)
                        translated_text = restore_ignore_words(result.text, ph_map)
                        direction = lang_a_name + " → " + lang_b_name
                    else:
                        result = translator.translate_text(clean_text, target_lang=lang_a_code)
                        translated_text = restore_ignore_words(result.text, ph_map)
                        direction = lang_b_name + " → " + lang_a_name
                    save_translation_history(user_id, text, translated_text, direction)
                    reply = translated_text + "\n（" + direction + "）" + suffix + "\n翻譯品質如何？回傳 👍 或 👎"
                    last_translation[user_id] = (text, translated_text)
                except Exception as e:
                    reply = "翻譯失敗，請稍後再試。\n錯誤：" + str(e)

        else:
            try:
                lang_a_code, lang_a_name, lang_b_code, lang_b_name = get_user_lang_pair(user_id)
                ignore_list = get_ignore_words(user_id)
                clean_text, ph_map = apply_ignore_words(text, ignore_list)
                detected = translator.translate_text(clean_text, target_lang='EN-US')
                src = detected.detected_source_lang.upper()
                lang_a_base = lang_a_code.split('-')[0].upper()
                if src in [lang_a_base, lang_a_code.upper()]:
                    result = translator.translate_text(clean_text, target_lang=lang_b_code)
                    translated_text = restore_ignore_words(result.text, ph_map)
                    direction = lang_a_name + " → " + lang_b_name
                else:
                    result = translator.translate_text(clean_text, target_lang=lang_a_code)
                    translated_text = restore_ignore_words(result.text, ph_map)
                    direction = lang_b_name + " → " + lang_a_name
                save_translation_history(user_id, text, translated_text, direction)
                reply = translated_text + "\n\n（" + direction + "）\n翻譯品質如何？回傳 👍 或 👎"
                last_translation[user_id] = (text, translated_text)
            except Exception as e:
                reply = "翻譯失敗，請稍後再試。\n錯誤：" + str(e)

    line_bot_api.reply_message(
        event.reply_token,
        TextSendMessage(text=reply)
    )


@handler.add(MessageEvent, message=ImageMessage)
def handle_image(event):
    user_id = event.source.user_id

    if hasattr(event.source, 'group_id'):
        group_id = event.source.group_id
        handle_group_image(event, group_id)
        return

    if is_blacklisted(user_id):
        return

    if not check_rate_limit(user_id):
        return

    user = get_user(user_id)
    if user[1] == 'inactive' or (user[1] == 'active' and not is_active(user_id)):
        user_status = 'inactive'
    else:
        user_status = user[1]

    if user_status == 'inactive':
        line_bot_api.reply_message(
            event.reply_token,
            TextSendMessage(text="❌ 您的帳號已停用或到期。\n\n傳送 @方案 查看續費方式！")
        )
        return

    if user_status == 'free':
        today_str = get_user_today(user_id).strftime('%Y-%m-%d')
        conn_check = get_db()
        c_check = conn_check.cursor()
        c_check.execute("SELECT count FROM daily_usage WHERE user_id=%s AND use_date=%s",
                        (user_id, today_str))
        row = c_check.fetchone()
        today_count = row[0] if row else 0
        if today_count >= FREE_DAILY_LIMIT:
            conn_check.close()
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text="⚠️ 免費版今日翻譯次數已達上限（" + str(FREE_DAILY_LIMIT) + "次）。\n\n傳送 @方案 查看購買方式。")
            )
            return
        c_check.execute("""
            INSERT INTO daily_usage (user_id, use_date, count) VALUES (%s, %s, 1)
            ON CONFLICT(user_id, use_date) DO UPDATE SET count = count + 1
        """, (user_id, today_str))
        conn_check.commit()
        conn_check.close()

    lang_a_code, lang_a_name, lang_b_code, lang_b_name = get_user_lang_pair(user_id)

    try:
        message_content = line_bot_api.get_message_content(event.message.id)
        image_data = b''.join(chunk for chunk in message_content.iter_content())
        image_base64 = base64.b64encode(image_data).decode('utf-8')

        response = claude.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1000,
            messages=[{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_base64}},
                {"type": "text", "text": IMAGE_OCR_PROMPT}
            ]}]
        )

        extracted_text = clean_image_ocr_text(response.content[0].text.strip())

        if extracted_text == '圖片中沒有文字':
            reply = "⚠️ 圖片中沒有偵測到文字。"
        else:
            detected = translator.translate_text(extracted_text, target_lang='EN-US')
            src = detected.detected_source_lang.upper()
            lang_a_base = lang_a_code.split('-')[0].upper()
            if src in [lang_a_base, lang_a_code.upper()]:
                result = translator.translate_text(extracted_text, target_lang=lang_b_code)
                reply = build_image_translation_reply(extracted_text, result.text, lang_a_name + " → " + lang_b_name)
            else:
                result = translator.translate_text(extracted_text, target_lang=lang_a_code)
                reply = build_image_translation_reply(extracted_text, result.text, lang_b_name + " → " + lang_a_name)

    except Exception as e:
        reply = "圖片翻譯失敗，請稍後再試。\n錯誤：" + str(e)

    reply_text_chunks(event.reply_token, reply)


def handle_group_text(event, group_id, user_id, text):
    if text in ('@群組說明', '@群組指令'):
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=GROUP_HELP_TEXT))
        return

    if text == '@推薦' or text == '@推薦好友':
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=REFERRAL_GROUP_BLOCK_TEXT))
        return

    if text.startswith('@使用推薦碼 ') or text.startswith('@使用推薦碼　'):
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=REFERRAL_GROUP_USE_BLOCK_TEXT))
        return

    # ── 翻譯品質評分 ──
    if text in ('👍', '👎'):
        if group_id in last_translation:
            orig, trans = last_translation[group_id]
            rating = 1 if text == '👍' else 0
            save_rating(group_id, orig, trans, rating)
            del last_translation[group_id]
            reply_r = "謝謝您的評分！" if rating == 1 else "謝謝您的回饋，我們會持續改善翻譯品質！"
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_r))
            return
        # 沒有待評分記錄，讓數字走正常流程（不回應）
        return

    # ── 群組持久多語設定 ──
    if text == '@群組多語':
        langs = get_group_multilang(group_id)
        if not langs:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text=("🌐 群組多語設定\n\n"
                      "設定後，@確認 發出的指令會同時翻成多種語言。\n\n"
                      "格式：@群組多語 印尼文 越南文 泰文\n"
                      "（最多8種）\n\n"
                      "取消：@群組多語 關閉\n\n"
                      "目前狀態：未設定")))
        else:
            names = "、".join([n for _, n in langs])
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text=("🌐 群組多語設定\n\n"
                      "目前已設定：" + names + "\n\n"
                      "@確認 發出的指令會同時翻成以上語言。\n\n"
                      "修改：@群組多語 語言1 語言2 ...\n"
                      "取消：@群組多語 關閉")))
        return

    if text == '@群組多語 關閉' or text == '@群組多語　關閉':
        clear_group_multilang(group_id)
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="✅ 群組多語已關閉。\n@確認 將只翻譯群組預設語言。"))
        return

    if text.startswith('@群組多語 ') or text.startswith('@群組多語　'):
        lang_str = text.replace('@群組多語　', '').replace('@群組多語 ', '').strip()
        lang_names = lang_str.split()
        valid = []
        invalid = []
        for name in lang_names[:8]:
            if name in GROUP_LANG_MAP:
                code, label = GROUP_LANG_MAP[name]
                valid.append((code, label))
            else:
                invalid.append(name)
        if not valid:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="❌ 沒有可識別的語言。\n\n請傳送 @群組說明 查看支援語言清單。"))
            return
        set_group_multilang(group_id, valid)
        names = "、".join([n for _, n in valid])
        msg = "✅ 群組多語已設定！\n\n語言：" + names + "\n\n@確認 發出的指令將同時翻成以上語言。"
        if invalid:
            msg += "\n\n⚠️ 以下語言無法識別，已略過：" + "、".join(invalid)
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=msg))
        return

    # ── 勿擾模式 ──
    if text == '@勿擾':
        dnd = get_group_dnd(group_id)
        if not dnd:
            reply_dnd = ("🔕 勿擾模式說明\n\n"
                "設定後，Bot 在指定時段內不會主動推播通知給此群組。\n"
                "（包含：確認進度通知、到期提醒等）\n\n"
                "⚠️ 勿擾時段內的通知會【直接丟棄】，不會補發。\n\n"
                "設定格式：\n"
                "@勿擾 22:00-07:00\n"
                "@勿擾 23:30-08:00\n\n"
                "取消勿擾：\n"
                "@勿擾 關閉\n\n"
                "目前狀態：未設定")
        else:
            sh, sm, eh, em = dnd
            now_in_dnd = is_group_in_dnd(group_id)
            reply_dnd = ("🔕 勿擾模式說明\n\n"
                "設定後，Bot 在指定時段內不會主動推播通知給此群組。\n"
                "（包含：確認進度通知、到期提醒等）\n\n"
                "⚠️ 勿擾時段內的通知會【直接丟棄】，不會補發。\n\n"
                "目前狀態：已開啟\n"
                "勿擾時段：{:02d}:{:02d} - {:02d}:{:02d}\n".format(sh, sm, eh, em) +
                "現在：" + ("🔕 勿擾中" if now_in_dnd else "✅ 正常接收") + "\n\n"
                "取消勿擾：@勿擾 關閉")
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_dnd))
        return

    if text == '@勿擾 關閉' or text == '@勿擾　關閉':
        clear_group_dnd(group_id)
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="✅ 勿擾模式已關閉，Bot 通知恢復正常。"))
        return

    if text.startswith('@勿擾 ') or text.startswith('@勿擾　'):
        time_str = text.replace('@勿擾　', '').replace('@勿擾 ', '').strip()
        # 解析 HH:MM-HH:MM
        import re as _re
        m = _re.match(r'^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$', time_str)
        if not m:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="❌ 格式錯誤。\n\n請使用：@勿擾 22:00-07:00"))
            return
        sh, sm, eh, em = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
        if sh > 23 or sm > 59 or eh > 23 or em > 59:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="❌ 時間格式錯誤，小時需在 0-23，分鐘需在 0-59。"))
            return
        set_group_dnd(group_id, sh, sm, eh, em)
        cross = "（跨日）" if sh * 60 + sm > eh * 60 + em else ""
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text=("🔕 勿擾模式已設定{}\n\n"
                  "時段：{:02d}:{:02d} - {:02d}:{:02d}\n\n"
                  "⚠️ 此時段內的推播通知將【直接丟棄】，不會補發。\n\n"
                  "取消請傳：@勿擾 關閉").format(cross, sh, sm, eh, em)))
        return

    # ── 翻譯確認系統 @確認 ──
    if text == '@確認進度':
        conn_cr = get_db()
        c_cr = conn_cr.cursor()
        c_cr.execute('''SELECT id, original_text, translated_text, created_at
            FROM confirm_requests
            WHERE group_id=%s AND status='pending'
            ORDER BY created_at DESC LIMIT 1''', (group_id,))
        latest = c_cr.fetchone()
        if not latest:
            conn_cr.close()
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="📊 目前沒有進行中的確認請求。\n\n發起確認：@確認 指令內容"))
            return
        req_id, orig, trans, created_at = latest
        c_cr.execute('''SELECT reply_choice, COUNT(*) FROM confirm_replies
            WHERE request_id=%s GROUP BY reply_choice''', (req_id,))
        counts = {row[0]: row[1] for row in c_cr.fetchall()}
        yes_count = counts.get(1, 0)
        no_count = counts.get(2, 0)
        total = yes_count + no_count
        conn_cr.close()
        status_msg = ("📊 確認進度查詢\n\n"
            "指令：" + orig + "\n"
            "發出時間：" + created_at[5:16] + "\n"
            "─────────────\n"
            "✅ 收到明白：" + str(yes_count) + " 人\n"
            "❓ 不明白：" + str(no_count) + " 人\n"
            "📝 總回覆：" + str(total) + " 人\n\n")
        if no_count > 0:
            status_msg += "⚠️ 有人表示不明白，請重新說明。\n\n"
        status_msg += "重新發起：@確認 指令內容"
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=status_msg))
        return

    if text.startswith('@確認 ') or text.startswith('@確認　'):
        content = text.replace('@確認　', '').replace('@確認 ', '').strip()
        if not content:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="格式：@確認 指令內容\n例如：@確認 明天上班時間改為 8:00\n\nBot 會翻譯這句話後，要求外勞回覆 1=收到 或 2=不明白。"))
            return
        # 翻譯這段內容
        row = get_group(group_id)
        lang_b = row[6]
        lang_b_name = row[7]
        lang_a_name = row[5]
        # 檢查群組持久多語設定
        multilang_list = get_group_multilang(group_id)
        try:
            if multilang_list:
                # 多語模式：同時翻多種語言
                lines = ["【" + lang_a_name + "】 " + content]
                all_translated = []
                for lang_code, lang_name in multilang_list:
                    result = translator.translate_text(content, target_lang=lang_code)
                    lines.append("【" + lang_name + "】 " + result.text)
                    all_translated.append(result.text)
                translated_display = "\n".join(lines)
                translated_store = " / ".join(all_translated)
            else:
                # 單語模式
                result = translator.translate_text(content, target_lang=lang_b)
                translated_display = ("【" + lang_a_name + "】 " + content + "\n"
                                     "【" + lang_b_name + "】 " + result.text)
                translated_store = result.text
            # 存入 confirm_requests
            tw_now_str = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
            conn_cr = get_db()
            c_cr = conn_cr.cursor()
            c_cr.execute('''INSERT INTO confirm_requests
                (group_id, requester_id, original_text, translated_text, status, created_at)
                VALUES (%s,%s,%s,%s,'pending',%s)''',
                (group_id, user_id, content, translated_store, tw_now_str))
            conn_cr.commit()
            conn_cr.close()
            reply_msg = ("📢 指令確認請求\n\n"
                + translated_display + "\n\n"
                "✅ 請回覆：\n"
                "1 → 收到，明白了\n"
                "2 → 不明白，需要說明")
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_msg))
        except Exception as e:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="❌ 翻譯失敗，請稍後再試。"))
        return

    # ── 確認回覆處理（外勞回覆 1 或 2）──
    if text in ('1', '2'):
        conn_cr = get_db()
        c_cr = conn_cr.cursor()
        # 找最新一筆 pending 的確認請求
        c_cr.execute('''SELECT id, requester_id, original_text, translated_text
            FROM confirm_requests
            WHERE group_id=%s AND status='pending'
            ORDER BY created_at DESC LIMIT 1''', (group_id,))
        pending = c_cr.fetchone()
        if pending:
            req_id, requester_id, orig, trans = pending
            choice = int(text)
            # 記錄這個人的回覆（UNIQUE 防重複）
            try:
                c_cr.execute('''INSERT INTO confirm_replies
                    (request_id, reply_user_id, reply_choice)
                    VALUES (%s,%s,%s)
                    ON CONFLICT (request_id, reply_user_id) DO NOTHING''', (req_id, user_id, choice))
                conn_cr.commit()
                is_new_reply = c_cr.rowcount > 0
            except:
                is_new_reply = False

            # 統計目前回覆狀況
            c_cr.execute('''SELECT reply_choice, COUNT(*) FROM confirm_replies
                WHERE request_id=%s GROUP BY reply_choice''', (req_id,))
            counts = {row[0]: row[1] for row in c_cr.fetchall()}
            yes_count = counts.get(1, 0)
            no_count = counts.get(2, 0)
            total_replied = yes_count + no_count

            conn_cr.close()

            # 回覆給外勞
            if choice == 1:
                result_text = "✅ 已記錄：收到，明白了"
            else:
                result_text = "❓ 已記錄：不明白，需要說明"
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=result_text))
            return
        else:
            conn_cr.close()
            # 沒有待確認的請求，讓數字走正常翻譯流程

    # ── 群組常用句指令 ──
    if text.startswith('@儲存句 ') or text.startswith('@儲存句　'):
        content_part = text.replace('@儲存句　', '').replace('@儲存句 ', '').strip()
        parts = content_part.split(' ', 1)
        if len(parts) < 2 or not parts[0] or not parts[1]:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="格式：@儲存句 名稱 內容\n例如：@儲存句 早安 早安！今天幾點上班？"))
        else:
            pname, pcontent = parts[0], parts[1]
            if save_phrase(group_id, pname, pcontent):
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="✅ 已儲存常用句「" + pname + "」\n\n傳送 @" + pname + " 即可直接翻譯。"))
            else:
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="⚠️ 名稱「" + pname + "」已存在。\n請先用 @刪除句 " + pname + " 刪除後重新儲存。"))
        return

    if text == '@我的句子':
        phrases = get_phrases(group_id)
        if not phrases:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="📋 目前沒有儲存的常用句。\n用 @儲存句 名稱 內容 新增。"))
        else:
            lines = ["📋 群組常用句（" + str(len(phrases)) + " 個）\n"]
            for nm, ct in phrases:
                short = ct[:30] + "…" if len(ct) > 30 else ct
                lines.append("【@" + nm + "】 " + short)
            lines.append("\n傳送 @名稱 直接觸發翻譯")
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text="\n".join(lines)))
        return

    if text.startswith('@刪除句 ') or text.startswith('@刪除句　'):
        pname = text.replace('@刪除句　', '').replace('@刪除句 ', '').strip()
        if delete_phrase(group_id, pname):
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="✅ 已刪除常用句「" + pname + "」"))
        else:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="❓ 找不到常用句「" + pname + "」\n\n傳送 @我的句子 查看清單"))
        return

    # 群組客服指令（條款、退費、客服）
    if text in CS_CMD:
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=CS_TEXTS[CS_CMD[text]]))
        return

    # 群組 ID 查詢（方便客戶複製給客服開通）
    if text == '@我的ID':
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="📋 此群組 ID：\n" + group_id + "\n\n升級付費請將此 ID 傳給客服 fishxit。"
        ))
        return

    if text == '@群組狀態':
        row = get_group(group_id)
        status_icon = '🟢 翻譯中' if row[8] == 1 else '⏸ 已暫停'
        lang_pair = row[5] + " ↔ " + row[7]
        if row[1] == 'suspended':
            reply = "❌ 此群組已被停用。\n\n如有疑問請聯繫客服 fishxit。"
        elif is_group_active(group_id):
            plan_name = '商務版（文字＋語音＋圖片OCR）' if row[2] == 'pro' else '體驗版（文字＋語音翻譯）'
            expire_str = row[3] if row[3] else '無到期日'
            reply = ("📊 群組翻譯狀態\n方案：" + plan_name + "（付費版）\n狀態：" + status_icon +
                     "\n語言：" + lang_pair + "\n到期日：" + expire_str +
                     "\n\n傳送 @群組說明 查看所有指令")
        else:
            tw_today_str = (datetime.utcnow() + timedelta(hours=8)).date().strftime('%Y-%m-%d')
            conn_s = get_db()
            c_s = conn_s.cursor()
            c_s.execute("""
                CREATE TABLE IF NOT EXISTS daily_usage (
                    user_id TEXT, use_date TEXT, count INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, use_date)
                )
            """)
            c_s.execute("SELECT count FROM daily_usage WHERE user_id=%s AND use_date=%s",
                        (group_id, tw_today_str))
            row_s = c_s.fetchone()
            conn_s.close()
            s_count = row_s[0] if row_s else 0
            s_remain = max(0, FREE_DAILY_LIMIT - s_count)
            reply = ("📊 群組翻譯狀態\n方案：🆓 免費試用\n狀態：" + status_icon +
                     "\n語言：" + lang_pair +
                     "\n今日免費剩餘：" + str(s_remain) + "/" + str(FREE_DAILY_LIMIT) + " 次" +
                     "\n\n💎 升級付費請聯繫客服 fishxit\n（將群組 ID 傳給客服開通）")
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply))
        return

    if text == '@方案':
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=PLAN_TEXT))
        return

    if text == '@購買' or text.startswith('@購買 '):
        if not ECPAY_MERCHANT_ID:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="💳 付款系統準備中，目前請聯繫客服 fishxit 手動開通。\n\n群組版方案：\n7日體驗 NT$49\n體驗版 NT$199／月（文字＋語音翻譯）\n商務版 NT$499／月（體驗版全部＋圖片OCR）"))
        else:
            pay_text = text.replace('@購買', '').strip()
            plan_map = {
                '7日': 'group_trial', '體驗': 'group_trial',
                '體驗版': 'group_basic', '199': 'group_basic',
                '商務版': 'group_pro', '499': 'group_pro',
            }
            plan_key = plan_map.get(pay_text, '')
            if not plan_key:
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="💳 選擇購買方案，傳送以下指令：\n\n"
                         "@購買 7日 → NT$49（7天體驗）\n"
                         "@購買 體驗版 → NT$199（30天，文字＋語音翻譯）\n"
                         "@購買 商務版 → NT$499（30天，體驗版全部＋圖片OCR）"))
            else:
                trade_no, html_or_err = ecpay_create_order(group_id, plan_key, is_group=True)
                if trade_no:
                    pay_url = BOT_BASE_URL + '/pay/' + trade_no + '/' + group_id + '/' + plan_key + '/group'
                    line_bot_api.reply_message(event.reply_token, TextSendMessage(
                        text="💳 請點擊以下連結完成付款：\n\n" + pay_url +
                             "\n\n⚠️ 請用右下角 ··· → 在瀏覽器中開啟\n付款完成後系統將自動開通，無需等待。\n連結 30 分鐘內有效。"))
                else:
                    line_bot_api.reply_message(event.reply_token, TextSendMessage(
                        text="❌ 建立訂單失敗，請聯繫客服 fishxit。"))
        return

    if text.startswith('@語言設定') or text.startswith('@ 語言設定'):
        # 容忍 @ 和語言設定之間有空格
        clean_g = text.replace('@ 語言設定', '').replace('@語言設定', '').strip()
        parts = clean_g.split()
        if len(parts) < 2:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="格式：@語言設定 語言A 語言B\n例如：@語言設定 繁體中文 印尼文\n\n傳送 @群組說明 查看可用語言"))
            return
        name_a = parts[0]
        name_b = parts[1]
        if name_a not in GROUP_LANG_MAP or name_b not in GROUP_LANG_MAP:
            unknown = name_a if name_a not in GROUP_LANG_MAP else name_b
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="❓ 不支援的語言：" + unknown + "\n\n傳送 @群組說明 查看可用語言清單"))
            return
        code_a, label_a = GROUP_LANG_MAP[name_a]
        code_b, label_b = GROUP_LANG_MAP[name_b]
        set_group_langs(group_id, code_a, label_a, code_b, label_b)
        set_group_translating(group_id, True)
        if is_group_active(group_id):
            tip = ""
        else:
            tip = "\n\n🆓 免費試用：每日 " + str(FREE_DAILY_LIMIT) + " 次"
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="✅ 語言已設定！\n" + label_a + " ↔ " + label_b + "\n翻譯已自動啟動。" + tip))
        return

    # 保護：被 @ 開頭但上方沒匹配到的指令，不做翻譯
    if text == '@群組歷史':
        rows = get_translation_history(group_id, limit=20)
        if not rows:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="📋 目前沒有翻譯歷史記錄。"))
        else:
            lines = ["📋 最近 " + str(len(rows)) + " 筆翻譯記錄（最新在上）\n"]
            for i, (orig, trans, direction, created_at) in enumerate(rows, 1):
                lines.append(str(i) + ". [" + created_at[5:16] + "] " + direction)
                lines.append("   原：" + orig)
                lines.append("   譯：" + trans)
            full = "\n".join(lines)
            if len(full) > 4800:
                full = full[:4800] + "\n\n（記錄過長，已截斷）"
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=full))
        return

    if (text.startswith('@忽略') and not text.startswith('@忽略詞') and not text.startswith('@刪除忽略')):
        words_input = text.replace('@忽略', '').strip().split()
        if not words_input:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="格式：@忽略 詞1 詞2\n例如：@忽略 Budi 永科機械\n\n傳送 @忽略詞 查看目前清單"))
        else:
            added = add_ignore_words(group_id, words_input)
            if added:
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="✅ 已新增忽略詞：" + "、".join(added) + "\n翻譯時這些詞將保持原樣不翻譯。"))
            else:
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="⚠️ 這些詞已在忽略清單中，無需重複新增。"))
        return

    if text == '@忽略詞':
        words = get_ignore_words(group_id)
        if not words:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="📋 目前忽略詞清單為空。\n\n傳送 @忽略 詞1 詞2 新增忽略詞"))
        else:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="📋 目前忽略詞（" + str(len(words)) + " 個）：\n" + "、".join(words) + "\n\n傳送 @刪除忽略 詞 可刪除單一忽略詞"))
        return

    if text.startswith('@刪除忽略'):
        word_to_del = text.replace('@刪除忽略', '').strip()
        if not word_to_del:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="格式：@刪除忽略 詞\n例如：@刪除忽略 Budi"))
        else:
            deleted = delete_ignore_word(group_id, word_to_del)
            if deleted:
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="✅ 已刪除忽略詞：" + word_to_del))
            else:
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="❓ 找不到忽略詞：" + word_to_del + "\n\n傳送 @忽略詞 查看目前清單"))
        return

    if text.startswith('@多語') or text.startswith('@ 多語'):
        clean_ml = text.replace('@ 多語', '').replace('@多語', '').strip()
        lang_names = clean_ml.split()
        if not lang_names:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="格式：@多語 語言1 語言2 語言3\n例如：@多語 印尼文 越南文 泰文\n\n傳送後下一則訊息將同時翻成這些語言。"))
        else:
            valid = []
            invalid = []
            for ln in lang_names:
                if ln in GROUP_LANG_MAP:
                    valid.append((GROUP_LANG_MAP[ln][0], GROUP_LANG_MAP[ln][1]))
                else:
                    invalid.append(ln)
            if invalid:
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="❓ 不支援的語言：" + "、".join(invalid) + "\n\n傳送 @群組說明 查看可用語言清單"))
            elif len(valid) > 8:
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="⚠️ 最多同時翻譯 8 種語言，請減少語言數量。"))
            else:
                multilang_pending[group_id] = valid
                names = "、".join([n for _, n in valid])
                line_bot_api.reply_message(event.reply_token, TextSendMessage(
                    text="✅ 已設定多語翻譯！\n目標語言：" + names + "\n\n請傳送要翻譯的文字，Bot 將同時翻成以上語言。"))
        return

    if text.startswith('@'):
        return

    # ── 群組翻譯邏輯 ──
    # 常用句觸發（@名稱 → 自動翻譯常用句內容）
    if text.startswith('@') and len(text) > 1:
        pname = text[1:].strip()
        pcontent = get_phrase_content(group_id, pname)
        if pcontent is not None:
            text = pcontent  # 把常用句內容當作輸入，繼續走翻譯流程

    # 多語翻譯（優先）
    if group_id in multilang_pending:
        lang_list = multilang_pending.pop(group_id)
        row_check = get_group(group_id)
        if row_check[1] == 'suspended':
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="❌ 此群組翻譯功能已被停用。\n\n如有疑問請聯繫客服 fishxit。"))
            return
        try:
            ignore_list = get_ignore_words(group_id)
            clean_text, ph_map = apply_ignore_words(text, ignore_list)
            lines = ["🌐 多語翻譯結果：\n原文：" + text]
            for lang_code, lang_name in lang_list:
                result = translator.translate_text(clean_text, target_lang=lang_code)
                translated_text = restore_ignore_words(result.text, ph_map)
                lines.append("\n【" + lang_name + "】\n" + translated_text)
                save_translation_history(group_id, text, translated_text, "多語 → " + lang_name)
            reply_text = "\n".join(lines)
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_text))
        except Exception as e:
            print("[群組多語翻譯] 失敗: " + str(e))
        return

    # 已開通且有效 → 正常翻譯
    if is_group_active(group_id):
        translated = group_translate(text, group_id)
        if translated:
            last_translation[group_id] = (text, translated)
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text=translated + "\n翻譯品質如何？回傳 👍 或 👎"))
        return

    row_check = get_group(group_id)

    # 管理員手動停用（suspended）→ 直接擋
    if row_check[1] == 'suspended':
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="❌ 此群組翻譯功能已被停用。\n\n如有疑問請聯繫客服 fishxit。"
        ))
        return

    # 曾經開通但已過期（status=active 但 expire_date 過了）→ 直接擋掉，提示續費
    if row_check[1] == 'active':
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="❌ 此群組翻譯方案已到期，翻譯功能已停止。\n\n續費請直接傳送 @購買 選擇方案重新開通，或聯繫客服 fishxit。"
        ))
        return

    # 從未開通（status=inactive）→ 走免費試用
    tw_today_str = (datetime.utcnow() + timedelta(hours=8)).date().strftime('%Y-%m-%d')
    conn_g = get_db()
    c_g = conn_g.cursor()
    c_g.execute("""
        CREATE TABLE IF NOT EXISTS daily_usage (
            user_id TEXT, use_date TEXT, count INTEGER DEFAULT 0,
            PRIMARY KEY (user_id, use_date)
        )
    """)
    c_g.execute("SELECT count FROM daily_usage WHERE user_id=%s AND use_date=%s",
                (group_id, tw_today_str))
    row_g = c_g.fetchone()
    g_count = row_g[0] if row_g else 0
    if g_count >= FREE_DAILY_LIMIT:
        conn_g.close()
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="⚠️ 群組今日免費翻譯次數已達上限（" + str(FREE_DAILY_LIMIT) + "次）。\n\n請聯繫客服 fishxit 開通付費方案，即可無限翻譯！"
        ))
        return
    # 先嘗試翻譯，成功才扣次數（避免無法翻譯的語言白扣）
    translated = group_translate(text, group_id)
    if translated:
        c_g.execute("""
            INSERT INTO daily_usage (user_id, use_date, count) VALUES (%s, %s, 1)
            ON CONFLICT(user_id, use_date) DO UPDATE SET count = count + 1
        """, (group_id, tw_today_str))
        conn_g.commit()
        conn_g.close()
        remain = FREE_DAILY_LIMIT - g_count - 1
        suffix = "\n\n🆓 免費試用 " + str(g_count + 1) + "/" + str(FREE_DAILY_LIMIT) + "（今日剩餘 " + str(remain) + " 次）"
        if remain == 0:
            suffix += "\n開通付費方案即可無限使用，聯繫客服：fishxit"
        last_translation[group_id] = (text, translated)
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text=translated + suffix + "\n翻譯品質如何？回傳 👍 或 👎"))
    else:
        conn_g.close()


@handler.add(MessageEvent, message=AudioMessage)
def handle_audio(event):
    user_id = event.source.user_id

    if hasattr(event.source, 'group_id'):
        group_id = event.source.group_id
        handle_group_audio(event, group_id)
        return

    # 個人版語音
    if is_blacklisted(user_id):
        return
    if not check_rate_limit(user_id):
        return

    user = get_user(user_id)
    if user[1] == 'inactive' or (user[1] == 'active' and not is_active(user_id)):
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="❌ 您的帳號已停用或到期。\n\n傳送 @方案 查看續費方式！"))
        return

    # 免費版次數檢查
    if user[1] == 'free':
        today_str = get_user_today(user_id).strftime('%Y-%m-%d')
        conn_a = get_db()
        c_a = conn_a.cursor()
        c_a.execute("SELECT count FROM daily_usage WHERE user_id=%s AND use_date=%s", (user_id, today_str))
        row_a = c_a.fetchone()
        today_count = row_a[0] if row_a else 0
        if today_count >= FREE_DAILY_LIMIT:
            conn_a.close()
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="⚠️ 免費版今日翻譯次數已達上限（" + str(FREE_DAILY_LIMIT) + "次）。\n\n傳送 @方案 查看購買方式。"))
            return
        c_a.execute("""
            INSERT INTO daily_usage (user_id, use_date, count) VALUES (%s, %s, 1)
            ON CONFLICT(user_id, use_date) DO UPDATE SET count = count + 1
        """, (user_id, today_str))
        conn_a.commit()
        conn_a.close()

    try:
        message_content = line_bot_api.get_message_content(event.message.id)
        audio_data = b''.join(chunk for chunk in message_content.iter_content())
        transcribed = transcribe_audio(audio_data)
        if not transcribed:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="⚠️ 語音轉錄失敗，請稍後再試。"))
            return

        lang_a_code, lang_a_name, lang_b_code, lang_b_name = get_user_lang_pair(user_id)
        ignore_list = get_ignore_words(user_id)
        clean_text, ph_map = apply_ignore_words(transcribed, ignore_list)
        detected = translator.translate_text(clean_text, target_lang='EN-US')
        src = detected.detected_source_lang.upper()
        lang_a_base = lang_a_code.split('-')[0].upper()
        if src in [lang_a_base, lang_a_code.upper()]:
            result = translator.translate_text(clean_text, target_lang=lang_b_code)
            translated_text = restore_ignore_words(result.text, ph_map)
            direction = lang_a_name + " → " + lang_b_name
        else:
            result = translator.translate_text(clean_text, target_lang=lang_a_code)
            translated_text = restore_ignore_words(result.text, ph_map)
            direction = lang_b_name + " → " + lang_a_name
        save_translation_history(user_id, transcribed, translated_text, direction)
        reply = "🎤 語音原文：\n" + transcribed + "\n\n🌐 翻譯（" + direction + "）：\n" + translated_text
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply))
    except Exception as e:
        print("[個人語音翻譯] 失敗: " + str(e))
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="語音翻譯失敗，請稍後再試。\n錯誤：" + str(e)))


def handle_group_audio(event, group_id):
    if not is_group_active(group_id):
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text="⚠️ 語音翻譯需開通付費方案。\n\n傳送 @方案 查看購買方式，或聯繫客服 fishxit。"
        ))
        return
    row = get_group(group_id)
    lang_a = row[4]
    lang_a_name = row[5]
    lang_b = row[6]
    lang_b_name = row[7]
    try:
        message_content = line_bot_api.get_message_content(event.message.id)
        audio_data = b''.join(chunk for chunk in message_content.iter_content())
        transcribed = transcribe_audio(audio_data)
        if not transcribed:
            return
        ignore_list = get_ignore_words(group_id)
        clean_text, ph_map = apply_ignore_words(transcribed, ignore_list)
        detected = translator.translate_text(clean_text, target_lang='EN-US')
        src = detected.detected_source_lang.upper()
        lang_a_base = lang_a.split('-')[0].upper()
        lang_b_base = lang_b.split('-')[0].upper()
        if src in [lang_a_base, lang_a.upper()]:
            result = translator.translate_text(clean_text, target_lang=lang_b)
            translated_text = restore_ignore_words(result.text, ph_map)
            direction = lang_a_name + " → " + lang_b_name
        elif src in [lang_b_base, lang_b.upper()]:
            result = translator.translate_text(clean_text, target_lang=lang_a)
            translated_text = restore_ignore_words(result.text, ph_map)
            direction = lang_b_name + " → " + lang_a_name
        else:
            return
        save_translation_history(group_id, transcribed, translated_text, direction)
        reply = "🎤 語音原文：\n" + transcribed + "\n\n🌐 翻譯（" + direction + "）：\n" + translated_text
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply))
    except Exception as e:
        print("[群組語音翻譯] 失敗: " + str(e))


def handle_group_image(event, group_id):
    if not is_group_active(group_id):
        return
    row = get_group(group_id)
    if row[2] != 'pro':
        line_bot_api.reply_message(event.reply_token, TextSendMessage(
            text=("📷 圖片 OCR 翻譯需使用群組商務版。\n\n"
                  "目前群組方案：體驗版（文字＋語音翻譯）\n"
                  "可用功能：文字翻譯、語音翻譯\n"
                  "商務版：再加圖片 OCR 翻譯\n\n"
                  "傳送 @購買 商務版 可升級，或傳送 @方案 查看差異。")
        ))
        return
    lang_a = row[4]
    lang_a_name = row[5]
    lang_b = row[6]
    lang_b_name = row[7]
    try:
        message_content = line_bot_api.get_message_content(event.message.id)
        image_data = b''.join(chunk for chunk in message_content.iter_content())
        image_base64 = base64.b64encode(image_data).decode('utf-8')
        response = claude.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1000,
            messages=[{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_base64}},
                {"type": "text", "text": IMAGE_OCR_PROMPT}
            ]}]
        )
        extracted_text = clean_image_ocr_text(response.content[0].text.strip())
        if extracted_text == '圖片中沒有文字':
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="⚠️ 圖片中沒有偵測到可翻譯文字。"
            ))
            return
        detected = translator.translate_text(extracted_text, target_lang='EN-US')
        src = detected.detected_source_lang.upper()
        lang_a_base = lang_a.split('-')[0].upper()
        lang_b_base = lang_b.split('-')[0].upper()
        if src in [lang_a_base, lang_a.upper()]:
            result = translator.translate_text(extracted_text, target_lang=lang_b)
            reply = build_image_translation_reply(extracted_text, result.text, lang_a_name + " → " + lang_b_name)
        elif src in [lang_b_base, lang_b.upper()]:
            result = translator.translate_text(extracted_text, target_lang=lang_a)
            reply = build_image_translation_reply(extracted_text, result.text, lang_b_name + " → " + lang_a_name)
        else:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text=("⚠️ 圖片文字語言與群組設定不一致，暫不自動翻譯。\n\n"
                      "目前群組語言：" + lang_a_name + " ↔ " + lang_b_name + "\n"
                      "如需翻譯這張圖片，請先傳送：\n"
                      "@語言設定 語言A 語言B")
            ))
            return
        reply_text_chunks(event.reply_token, reply)
    except Exception as e:
        print("[群組圖片翻譯] 失敗: " + str(e))
        try:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(
                text="圖片翻譯失敗，請稍後再試。"
            ))
        except Exception:
            pass


# ===== ECPay 付款路由 =====
@app.route('/pay/<trade_no>/<owner_id>/<plan_key>/<owner_type>', methods=['GET'])
def pay_page(trade_no, owner_id, plan_key, owner_type):
    if not ECPAY_MERCHANT_ID:
        return '付款系統尚未開通，請聯繫客服 fishxit', 503
    if plan_key not in ECPAY_PLANS:
        return '方案不存在', 400
    plan_code, days, amt, item_name = ECPAY_PLANS[plan_key]
    is_group = (owner_type == 'group')
    tw_now = datetime.utcnow() + timedelta(hours=8)
    trade_date = tw_now.strftime('%Y/%m/%d %H:%M:%S')
    params = {
        'MerchantID':        ECPAY_MERCHANT_ID,
        'MerchantTradeNo':   trade_no,
        'MerchantTradeDate': trade_date,
        'PaymentType':       'aio',
        'TotalAmount':       amt,
        'TradeDesc':         urllib.parse.quote('萬語通付款'),
        'ItemName':          item_name,
        'ReturnURL':         BOT_BASE_URL + '/ecpay/notify',
        'OrderResultURL':    BOT_BASE_URL + '/ecpay/return',
        'CustomField1':      owner_id,
        'CustomField2':      plan_key,
        'CustomField3':      owner_type,
        'CustomField4':      str(days),
        'ChoosePayment':     'ALL',
        'EncryptType':       1,
    }
    params['CheckMacValue'] = ecpay_generate_check_mac(params)
    form_fields = ''.join(f'<input type="hidden" name="{k}" value="{v}">' for k, v in params.items())
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>萬語通付款</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:sans-serif;background:#0d1117;color:#e8edf5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}}
.card{{background:#161b22;border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:36px 28px;max-width:400px;width:100%;text-align:center;}}
.logo{{font-size:2rem;font-weight:800;color:#06c755;margin-bottom:8px;}}
.subtitle{{font-size:0.85rem;color:#6b7a99;margin-bottom:28px;}}
.amount{{font-size:2.4rem;font-weight:800;color:#fff;margin-bottom:4px;}}
.plan{{font-size:0.9rem;color:#6b7a99;margin-bottom:32px;}}
.pay-btn{{display:block;width:100%;padding:16px;background:#06c755;color:#000;font-size:1rem;font-weight:700;border:none;border-radius:10px;cursor:pointer;transition:opacity 0.2s;}}
.pay-btn:hover{{opacity:0.85;}}
.note{{font-size:0.75rem;color:#6b7a99;margin-top:16px;line-height:1.6;}}
.secure{{display:flex;align-items:center;justify-content:center;gap:6px;margin-top:20px;font-size:0.75rem;color:#6b7a99;}}
</style></head><body>
<div class="card">
  <div class="logo">萬語通</div>
  <div class="subtitle">WanyuTong · LINE 翻譯機器人</div>
  <div class="amount">NT${amt}</div>
  <div class="plan">{item_name}</div>
  <form method="POST" action="{ECPAY_PAYMENT_URL}">{form_fields}
    <button type="submit" class="pay-btn" onclick="this.disabled=true;this.textContent='處理中...';this.form.submit();">🔒 前往付款</button>
  </form>
  <div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:10px;margin-top:12px;font-size:0.78rem;color:#fbbf24;line-height:1.6;">⚠️ 請只點一次「前往付款」<br>重複點擊會導致訂單重複失敗</div>
  <div class="note">付款完成後系統將自動開通，無需等待<br>支援信用卡、Apple Pay、ATM、超商</div>
  <div class="secure">🔒 SSL 加密 · 由綠界科技提供金流服務</div>
</div></body></html>"""
    return html


@app.route('/ecpay/notify', methods=['POST'])
def ecpay_notify():
    # ECPay 付款完成通知（server-to-server）
    data = request.form.to_dict()
    if not data:
        return '0|ErrorMessage', 200

    # 驗證 CheckMacValue
    received_mac = data.pop('CheckMacValue', '')
    expected_mac = ecpay_generate_check_mac(data)
    if received_mac.upper() != expected_mac.upper():
        return '0|CheckMacValue Error', 200

    rtn_code = data.get('RtnCode', '')
    if rtn_code != '1':
        return '1|OK', 200  # 付款失敗，不開通

    owner_id = data.get('CustomField1', '')
    plan_key = data.get('CustomField2', '')
    is_group = data.get('CustomField3', '') == 'group'
    days = int(data.get('CustomField4', '30'))

    if not owner_id or plan_key not in ECPAY_PLANS:
        return '0|Invalid Fields', 200

    plan_code = ECPAY_PLANS[plan_key][0]
    trade_no = data.get('MerchantTradeNo', '')
    amount = int(data.get('TradeAmt', '0'))
    tw_now = datetime.utcnow() + timedelta(hours=8)
    expire = (tw_now + timedelta(days=days)).strftime('%Y-%m-%d')

    # 開通
    conn = get_db()
    c = conn.cursor()
    if trade_no:
        c.execute("SELECT id FROM payments WHERE note LIKE %s AND status IN ('paid','success') LIMIT 1",
                  ('%' + trade_no + '%',))
        if c.fetchone():
            conn.close()
            return '1|OK', 200
    if is_group:
        c.execute('UPDATE groups SET status=%s, plan=%s, expire_date=%s, is_translating=1 WHERE group_id=%s',
                  ('active', plan_code, expire, owner_id))
        if c.rowcount == 0:
            c.execute('INSERT INTO groups (group_id, status, plan, expire_date, is_translating) VALUES (%s,%s,%s,%s,1) ON CONFLICT (group_id) DO NOTHING',
                      (owner_id, 'active', plan_code, expire))
    else:
        c.execute('UPDATE users SET status=%s, plan=%s, expire_date=%s WHERE user_id=%s',
                  ('active', plan_code, expire, owner_id))
    # 記錄付款（INSERT 新紀錄，確保金額正確寫入）
    tw_now_str = tw_now.strftime('%Y-%m-%d %H:%M:%S')
    note = ('group:' if is_group else 'user:') + owner_id + ':' + plan_key + ':' + str(days) + ':' + trade_no
    # 先更新舊的 pending 記錄
    c.execute('''UPDATE payments SET status=%s, amount=%s WHERE note LIKE %s AND status=%s''',
              ('paid', amount, '%' + trade_no + '%', 'pending'))
    # 如果沒有對應記錄，則新增一筆
    if c.rowcount == 0:
        c.execute('''INSERT INTO payments (user_id, amount, plan, payment_date, status, note)
                  VALUES (%s, %s, %s, %s, %s, %s)''',
                  (owner_id, amount, plan_code, tw_now_str, 'paid', note))
    conn.commit()
    conn.close()

    referral_award = award_referral_if_needed(owner_id, 'group' if is_group else 'user', plan_key, trade_no)

    # 推播開通通知給用戶
    plan_label = ECPAY_PLANS[plan_key][3]
    try:
        msg = ("✅ 付款成功！\n方案：" + plan_label +
               "\n到期日：" + expire +
               "\n\n感謝您的支持！")
        if referral_award:
            msg += "\n\n🎁 推薦碼優惠已套用，本次已自動加贈翻譯天數。"
        line_bot_api.push_message(owner_id, TextSendMessage(text=msg))
    except Exception as e:
        print("[ECPay 開通通知] 失敗: " + str(e))

    return '1|OK', 200


@app.route('/ecpay/return', methods=['POST', 'GET'])
def ecpay_return():
    # 用戶付完款後跳轉的頁面
    rtn_code = request.form.get('RtnCode', request.args.get('RtnCode', ''))
    if rtn_code == '1':
        msg = '付款成功！請返回 LINE 查看開通通知。'
        color = '#4CAF50'
    else:
        msg = '付款未完成，如有問題請聯繫客服 fishxit。'
        color = '#f44336'
    return f'''<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>萬語通付款結果</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px;background:#f5f5f5">
<div style="background:#fff;border-radius:12px;padding:32px;max-width:400px;margin:0 auto;box-shadow:0 2px 8px rgba(0,0,0,0.1)">
<div style="font-size:48px;margin-bottom:16px">{"✅" if rtn_code=="1" else "❌"}</div>
<h2 style="color:{color};margin:0 0 12px">{msg}</h2>
<p style="color:#888;font-size:14px">請返回 LINE 繼續使用萬語通</p>
</div></body></html>'''


# ===== 群組管理 API =====
@app.route('/admin/groups', methods=['GET'])
def admin_groups():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT group_id, status, plan, expire_date, lang_a_name, lang_b_name, is_translating, created_at, note FROM groups')
    rows = c.fetchall()
    conn.close()
    tw_today = (datetime.utcnow() + timedelta(hours=8)).date()
    result = []
    for r in rows:
        days_left = None
        if r[3]:
            try:
                days_left = (datetime.strptime(r[3], '%Y-%m-%d').date() - tw_today).days
            except:
                pass
        result.append({
            'group_id': r[0], 'status': r[1], 'plan': r[2],
            'expire_date': r[3], 'days_left': days_left,
            'lang_a': r[4], 'lang_b': r[5],
            'is_translating': r[6] == 1,
            'created_at': r[7], 'note': r[8],
        })
    return jsonify(result)


@app.route('/admin/group-activate', methods=['POST'])
def admin_group_activate():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    group_id = (data.get('group_id') or '').strip()
    if not group_id:
        return jsonify({'error': '缺少 group_id'}), 400
    if not group_id.startswith('C'):
        return jsonify({'error': 'Group ID 應以 C 開頭'}), 400
    try:
        plan = validate_admin_plan(data.get('plan', 'basic'), 'group')
        days = validate_admin_days(data.get('days', 30))
        amount = validate_admin_amount(data.get('amount', PLAN_AMOUNTS.get(plan, 0)))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    note = (data.get('note') or '').strip()
    if len(note) > 200:
        return jsonify({'error': '備註不可超過 200 字'}), 400
    activate_group(group_id, plan, days, note)
    record_manual_payment(group_id, amount, plan, 'manual:group:' + group_id + ':' + plan + ':' + str(days))
    award_referral_if_needed(group_id, 'group', referral_plan_key_from_plan(plan, 'group'), 'manual_group_activate')
    log_admin_action('activate_group', group_id, 'plan=' + str(plan) + ', days=' + str(days) + ', amount=' + str(amount))
    plan_name = '商務版（文字＋語音＋圖片OCR）' if plan == 'pro' else '體驗版（文字＋語音翻譯）'
    tw_expire = (datetime.utcnow() + timedelta(hours=8) + timedelta(days=days)).strftime('%Y-%m-%d')
    try:
        line_bot_api.push_message(group_id, TextSendMessage(
            text="✅ 萬語通群組翻譯已開通！\n方案：" + plan_name + "\n到期日：" + tw_expire +
     "\n\n傳送 @語言設定 繁體中文 印尼文 設定語言\n\n感謝您的支持！"
        ))
    except Exception as e:
        print("[群組開通通知] 失敗: " + str(e))
    return jsonify({'success': True, 'expire_date': tw_expire})


@app.route('/admin/group-deactivate', methods=['POST'])
def admin_group_deactivate():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    group_id = (data.get('group_id') or '').strip()
    if not group_id:
        return jsonify({'error': '缺少 group_id'}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE groups SET status=%s, is_translating=0 WHERE group_id=%s', ('suspended', group_id))
    if c.rowcount == 0:
        conn.rollback()
        conn.close()
        return jsonify({'error': '找不到此群組'}), 404
    conn.commit()
    conn.close()
    log_admin_action('deactivate_group', group_id, '')
    return jsonify({'success': True})


@app.route('/admin/user-reactivate', methods=['POST'])
def admin_user_reactivate():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    user_id = (data.get('user_id') or '').strip()
    if not user_id:
        return jsonify({'error': '缺少 user_id'}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET status=%s WHERE user_id=%s', ('free', user_id))
    if c.rowcount == 0:
        conn.rollback()
        conn.close()
        return jsonify({'error': '找不到此用戶'}), 404
    conn.commit()
    conn.close()
    log_admin_action('reactivate_user', user_id, '')
    return jsonify({'success': True})


@app.route('/admin/group-reactivate', methods=['POST'])
def admin_group_reactivate():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    group_id = (data.get('group_id') or '').strip()
    if not group_id:
        return jsonify({'error': '缺少 group_id'}), 400
    conn = get_db()
    c = conn.cursor()
    # 解除停用：status 回 inactive（走免費試用路徑），expire_date 清空
    c.execute('UPDATE groups SET status=%s, expire_date=NULL, is_translating=0 WHERE group_id=%s', ('inactive', group_id))
    if c.rowcount == 0:
        conn.rollback()
        conn.close()
        return jsonify({'error': '找不到此群組'}), 404
    conn.commit()
    conn.close()
    log_admin_action('reactivate_group', group_id, '')
    return jsonify({'success': True})


@app.route('/admin/inactive-users', methods=['GET'])
def admin_inactive_users():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT user_id, status, plan, expire_date, created_at, target_name FROM users WHERE status=%s',
              ('inactive',))
    rows = c.fetchall()
    conn.close()
    tw_today = (datetime.utcnow() + timedelta(hours=8)).date()
    result = []
    for r in rows:
        days_left = None
        if r[3]:
            try:
                days_left = (datetime.strptime(r[3], '%Y-%m-%d').date() - tw_today).days
            except:
                pass
        result.append({
            'user_id': r[0], 'status': r[1], 'plan': r[2],
            'expire_date': r[3], 'days_left': days_left,
            'created_at': r[4], 'target_name': r[5],
        })
    return jsonify(result)


@app.route('/admin/inactive-groups', methods=['GET'])
def admin_inactive_groups():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT group_id, status, plan, expire_date, lang_a_name, lang_b_name, is_translating, created_at, note FROM groups WHERE status=%s',
              ('suspended',))
    rows = c.fetchall()
    conn.close()
    tw_today = (datetime.utcnow() + timedelta(hours=8)).date()
    result = []
    for r in rows:
        days_left = None
        if r[3]:
            try:
                days_left = (datetime.strptime(r[3], '%Y-%m-%d').date() - tw_today).days
            except:
                pass
        result.append({
            'group_id': r[0], 'status': r[1], 'plan': r[2],
            'expire_date': r[3], 'days_left': days_left,
            'lang_a': r[4], 'lang_b': r[5],
            'is_translating': r[6] == 1,
            'created_at': r[7], 'note': r[8],
        })
    return jsonify(result)


@app.route('/admin/user-daily-usage', methods=['GET'])
def admin_user_daily_usage():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    user_id = request.args.get('user_id', '').strip()
    if not user_id:
        return jsonify({'error': '缺少 user_id'}), 400
    tw_today = (datetime.utcnow() + timedelta(hours=8)).date().strftime('%Y-%m-%d')
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS daily_usage (
            user_id TEXT, use_date TEXT, count INTEGER DEFAULT 0,
            PRIMARY KEY (user_id, use_date)
        )
    """)
    c.execute('SELECT count FROM daily_usage WHERE user_id=%s AND use_date=%s', (user_id, tw_today))
    row = c.fetchone()
    conn.close()
    used = row[0] if row else 0
    return jsonify({'user_id': user_id, 'date': tw_today, 'used': used, 'limit': FREE_DAILY_LIMIT, 'remain': max(0, FREE_DAILY_LIMIT - used)})


# ===== 群組到期驗證 API =====

# 查詢即將到期 / 已過期的群組（GET，查看用，不會改資料）
@app.route('/admin/group-test-expiry', methods=['GET'])
def admin_group_test_expiry():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    tw_now = datetime.utcnow() + timedelta(hours=8)
    tw_today = tw_now.strftime('%Y-%m-%d')
    tw_remind = (tw_now + timedelta(days=3)).strftime('%Y-%m-%d')

    c.execute('SELECT group_id, expire_date, plan FROM groups WHERE status=%s AND expire_date=%s',
              ('active', tw_remind))
    remind_groups = c.fetchall()

    c.execute('SELECT group_id, expire_date, plan FROM groups WHERE status=%s AND expire_date<%s',
              ('active', tw_today))
    expired_groups = c.fetchall()

    c.execute('SELECT group_id, expire_date, plan FROM groups WHERE status=%s ORDER BY expire_date ASC',
              ('active',))
    all_active = c.fetchall()
    conn.close()

    return jsonify({
        'taiwan_now': tw_now.strftime('%Y-%m-%d %H:%M'),
        'taiwan_today': tw_today,
        'remind_in_3_days': [
            {'group_id': g[0], 'expire_date': g[1], 'plan': g[2]}
            for g in remind_groups
        ],
        'already_expired': [
            {'group_id': g[0], 'expire_date': g[1], 'plan': g[2]}
            for g in expired_groups
        ],
        'all_active_groups': [
            {'group_id': g[0], 'expire_date': g[1], 'plan': g[2]}
            for g in all_active
        ],
    })


# 手動觸發群組到期檢查（POST，會真的改資料 + 推播）
@app.route('/admin/run-group-expiry', methods=['POST'])
def admin_run_group_expiry():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'RUN_GROUP_EXPIRY':
        return jsonify({'error': '請確認 RUN_GROUP_EXPIRY 才能執行群組到期檢查'}), 400
    conn = get_db()
    c = conn.cursor()
    tw_now = datetime.utcnow() + timedelta(hours=8)
    tw_today = tw_now.strftime('%Y-%m-%d')
    tw_remind = (tw_now + timedelta(days=3)).strftime('%Y-%m-%d')

    # 3 天後到期提醒
    c.execute('SELECT group_id, expire_date FROM groups WHERE status=%s AND expire_date=%s',
              ('active', tw_remind))
    remind_rows = c.fetchall()
    reminded = 0
    for group_id_r, expire_date in remind_rows:
        try:
            line_bot_api.push_message(group_id_r, TextSendMessage(
                text="⏰ 萬語通群組翻譯即將到期！\n到期日：" + expire_date +
                     "\n\n請盡快聯繫客服 fishxit 續費，避免服務中斷！"
            ))
            reminded += 1
        except Exception as e:
            print("[群組到期提醒] 失敗: " + str(e))

    # 已過期處理
    c.execute('SELECT group_id, expire_date FROM groups WHERE status=%s AND expire_date<%s',
              ('active', tw_today))
    expired_rows = c.fetchall()
    expired = 0
    for group_id_e, expire_date in expired_rows:
        c.execute('UPDATE groups SET status=%s, is_translating=0 WHERE group_id=%s',
                  ('inactive', group_id_e))
        try:
            line_bot_api.push_message(group_id_e, TextSendMessage(
                text="❌ 萬語通群組翻譯已到期，翻譯功能已自動停止。\n到期日：" + expire_date +
                     "\n\n請聯繫客服 fishxit 續費開通。"
            ))
            expired += 1
        except Exception as e:
            print("[群組到期通知] 失敗: " + str(e))

    conn.commit()
    conn.close()
    return jsonify({
        'success': True,
        'reminded': reminded,
        'expired': expired,
        'taiwan_now': tw_now.strftime('%Y-%m-%d %H:%M:%S'),
    })


# 手動設定群組到期日（POST，方便測試用）
@app.route('/admin/group-set-expire', methods=['POST'])
def admin_group_set_expire():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    group_id = (data.get('group_id') or '').strip()
    if not group_id:
        return jsonify({'error': '缺少 group_id'}), 400
    try:
        expire_date = validate_admin_date(data.get('expire_date'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE groups SET expire_date=%s, status=%s, is_translating=1 WHERE group_id=%s',
              (expire_date, 'active', group_id))
    if c.rowcount == 0:
        conn.rollback()
        conn.close()
        return jsonify({'error': '找不到此群組'}), 404
    conn.commit()
    conn.close()
    log_admin_action('set_group_expire', group_id, 'expire_date=' + expire_date)
    return jsonify({
        'success': True,
        'group_id': group_id,
        'new_expire_date': expire_date,
        'note': '已設定到期日（status 一併設為 active，翻譯已啟用），可呼叫 /admin/run-group-expiry 測試到期流程',
    })


@app.route('/admin/dashboard-stats', methods=['GET'])
def admin_dashboard_stats():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    tw_today = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d')
    tw_now = datetime.utcnow() + timedelta(hours=8)

    # ── 用戶總覽 ──
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE status='active'")
    active_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE status='free'")
    free_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE status='inactive'")
    inactive_users = c.fetchone()[0]

    # ── 近7日新增用戶 ──
    c.execute("""
        SELECT DATE(created_at::timestamp + INTERVAL '8 hours') as d, COUNT(*) as cnt
        FROM users
        WHERE created_at::timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY d ORDER BY d
    """)
    new_users_trend = [{'date': str(r[0]), 'count': r[1]} for r in c.fetchall()]
    week_new_users = sum(r['count'] for r in new_users_trend)

    # ── 近14天新增用戶趨勢 ──
    c.execute("""
        SELECT DATE(created_at::timestamp + INTERVAL '8 hours') as d, COUNT(*) as cnt
        FROM users
        WHERE created_at::timestamp >= NOW() - INTERVAL '14 days'
        GROUP BY d ORDER BY d
    """)
    new_users_14d = [{'date': str(r[0]), 'count': r[1]} for r in c.fetchall()]

    # ── 免費轉付費轉換率 ──
    conversion_rate = round(active_users / total_users * 100, 1) if total_users > 0 else 0

    # ── 平均使用天數（黏著度）──
    c.execute("""
        SELECT AVG(day_count) FROM (
            SELECT user_id, COUNT(DISTINCT use_date) as day_count
            FROM daily_usage GROUP BY user_id
        ) t
    """)
    avg_usage_days = round(c.fetchone()[0] or 0, 1)

    # ── 7日留存率 ──
    seven_days_ago = (tw_now - timedelta(days=7)).strftime('%Y-%m-%d')
    fourteen_days_ago = (tw_now - timedelta(days=14)).strftime('%Y-%m-%d')
    c.execute("SELECT COUNT(DISTINCT user_id) FROM daily_usage WHERE use_date <= %s AND use_date >= %s", (seven_days_ago, fourteen_days_ago))
    cohort_users = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(DISTINCT user_id) FROM daily_usage WHERE use_date >= %s", (seven_days_ago,))
    retained_users = c.fetchone()[0] or 0
    retention_rate = round(retained_users / cohort_users * 100, 1) if cohort_users > 0 else 0

    # ── 到期後幾天續訂 ──
    c.execute("""
        SELECT AVG(EXTRACT(DAY FROM (p.payment_date::timestamp - u.expire_date::timestamp)))
        FROM payments p JOIN users u ON p.user_id = u.user_id
        WHERE p.status IN ('paid','success') AND u.expire_date IS NOT NULL
        AND p.payment_date::timestamp > u.expire_date::timestamp
    """)
    avg_renew_days = round(c.fetchone()[0] or 0, 1)

    # ── 個人 vs 群組比例 ──
    c.execute("SELECT COUNT(*) FROM groups")
    total_groups = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM groups WHERE status='active'")
    active_groups = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM groups WHERE plan='pro' AND status='active'")
    pro_groups = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM groups WHERE plan='basic' AND status='active'")
    basic_groups = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM groups WHERE status='inactive'")
    inactive_groups = c.fetchone()[0]

    # ── 翻譯統計 ──
    c.execute("SELECT COUNT(*) FROM translation_history")
    total_translations = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM translation_history WHERE created_at::timestamp >= NOW() - INTERVAL '7 days'")
    week_translations = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM translation_history WHERE created_at::timestamp >= %s::timestamp", (tw_today,))
    today_translations = c.fetchone()[0]

    # ── 每用戶平均翻譯次數 ──
    avg_trans_per_user = round(total_translations / total_users, 1) if total_users > 0 else 0

    # ── 免費額度用滿率 ──
    c.execute("SELECT COUNT(DISTINCT user_id) FROM daily_usage WHERE use_date=%s AND count >= 15", (tw_today,))
    maxed_users = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(DISTINCT user_id) FROM daily_usage WHERE use_date=%s", (tw_today,))
    active_today_users = c.fetchone()[0] or 1
    maxed_rate = round(maxed_users / active_today_users * 100, 1)

    # ── 語言使用量（Top 10）──
    c.execute("""
        SELECT direction, COUNT(*) as cnt
        FROM translation_history
        GROUP BY direction
        ORDER BY cnt DESC
        LIMIT 10
    """)
    lang_stats = [{'direction': r[0], 'count': r[1]} for r in c.fetchall()]

    # ── 24小時使用分佈（長條圖用）──
    c.execute("""
        SELECT EXTRACT(HOUR FROM created_at::timestamp + INTERVAL '8 hours')::INTEGER as hour,
               COUNT(*) as cnt
        FROM translation_history
        GROUP BY hour
        ORDER BY hour
    """)
    hour_rows = c.fetchall()
    hour_stats = {str(h): 0 for h in range(24)}
    for h, cnt in hour_rows:
        hour_stats[str(int(h))] = cnt

    # ── 每日翻譯趨勢（近14天）──
    c.execute("""
        SELECT DATE(created_at::timestamp + INTERVAL '8 hours') as d, COUNT(*) as cnt
        FROM translation_history
        WHERE created_at::timestamp >= NOW() - INTERVAL '14 days'
        GROUP BY d ORDER BY d
    """)
    daily_trend = [{'date': str(r[0]), 'count': r[1]} for r in c.fetchall()]

    # ── 翻譯滿意度 ──
    c.execute("SELECT COUNT(*) FROM translation_ratings WHERE rating=1")
    thumbs_up = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM translation_ratings WHERE rating=0")
    thumbs_down = c.fetchone()[0] or 0
    total_ratings = thumbs_up + thumbs_down
    satisfaction_rate = round(thumbs_up / total_ratings * 100, 1) if total_ratings > 0 else 0

    # ── 近7日滿意度趨勢 ──
    c.execute("""
        SELECT DATE(created_at::timestamp + INTERVAL '8 hours') as d,
               SUM(CASE WHEN rating=1 THEN 1 ELSE 0 END) as up,
               COUNT(*) as total
        FROM translation_ratings
        WHERE created_at::timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY d ORDER BY d
    """)
    rating_trend = [{'date': str(r[0]), 'up': r[1], 'total': r[2],
                     'rate': round(r[1]/r[2]*100, 1) if r[2] > 0 else 0} for r in c.fetchall()]

    # ── 付款統計 ──
    c.execute("SELECT COUNT(*), SUM(amount) FROM payments WHERE status IN ('paid','success')")
    pay_row = c.fetchone()
    total_payments = pay_row[0] or 0
    total_revenue = int(pay_row[1] or 0)

    c.execute("""
        SELECT COUNT(*) FROM users u
        WHERE u.status='active'
        AND (u.expire_date IS NULL OR u.expire_date >= %s)
        AND NOT EXISTS (
            SELECT 1 FROM payments p
            WHERE p.user_id=u.user_id AND p.status IN ('paid','success')
        )
    """, (tw_today,))
    active_unpaid_users = c.fetchone()[0] or 0

    c.execute("""
        SELECT COUNT(*) FROM groups g
        WHERE g.status='active'
        AND (g.expire_date IS NULL OR g.expire_date >= %s)
        AND NOT EXISTS (
            SELECT 1 FROM payments p
            WHERE p.user_id=g.group_id AND p.status IN ('paid','success')
        )
    """, (tw_today,))
    active_unpaid_groups = c.fetchone()[0] or 0

    c.execute("""
        SELECT plan, COUNT(*) as cnt, SUM(amount) as total
        FROM payments WHERE status IN ('paid','success')
        GROUP BY plan ORDER BY total DESC
    """)
    plan_revenue = [{'plan': r[0], 'count': r[1], 'total': int(r[2] or 0)} for r in c.fetchall()]

    # ── 月收入趨勢（近6個月）──
    c.execute("""
        SELECT TO_CHAR(payment_date::timestamp + INTERVAL '8 hours', 'YYYY-MM') as mo,
               SUM(amount) as total
        FROM payments WHERE status IN ('paid','success')
        AND payment_date::timestamp >= NOW() - INTERVAL '6 months'
        GROUP BY mo ORDER BY mo
    """)
    monthly_revenue = [{'month': r[0], 'total': int(r[1] or 0)} for r in c.fetchall()]

    # ── ARPU ──
    arpu = round(total_revenue / active_users, 0) if active_users > 0 else 0

    # ── 續訂率 ──
    c.execute("""
        SELECT COUNT(DISTINCT p1.user_id) FROM payments p1
        JOIN payments p2 ON p1.user_id = p2.user_id AND p2.id != p1.id
        WHERE p1.status IN ('paid','success')
    """)
    renew_users = c.fetchone()[0] or 0
    renew_rate = round(renew_users / total_payments * 100, 1) if total_payments > 0 else 0

    # ── 今日免費用量 ──
    c.execute("SELECT SUM(count) FROM daily_usage WHERE use_date=%s", (tw_today,))
    today_free_usage = c.fetchone()[0] or 0

    # ── 群組平均存活天數 ──
    c.execute("""
        SELECT AVG(EXTRACT(DAY FROM NOW() - created_at::timestamp))
        FROM groups WHERE status='active'
    """)
    avg_group_days = round(c.fetchone()[0] or 0, 1)

    # ── 勿擾模式使用率 ──
    c.execute("SELECT COUNT(*) FROM group_dnd")
    dnd_count = c.fetchone()[0] or 0
    dnd_rate = round(dnd_count / total_groups * 100, 1) if total_groups > 0 else 0

    # ── 多語模式使用率 ──
    c.execute("SELECT COUNT(DISTINCT group_id) FROM group_multilang")
    multilang_count = c.fetchone()[0] or 0
    multilang_rate = round(multilang_count / total_groups * 100, 1) if total_groups > 0 else 0

    # ── 個人功能指標 ──
    c2 = conn.cursor()
    c2.execute("SELECT COUNT(DISTINCT owner_id) FROM ignore_words")
    ignore_words_users = c2.fetchone()[0] or 0
    c2.execute("SELECT COUNT(*) FROM ignore_words")
    ignore_words_total = c2.fetchone()[0] or 0

    c2.execute("SELECT COUNT(DISTINCT owner_id) FROM saved_phrases")
    saved_phrases_users = c2.fetchone()[0] or 0
    c2.execute("SELECT COUNT(*) FROM saved_phrases")
    saved_phrases_total = c2.fetchone()[0] or 0

    c2.execute("SELECT COUNT(DISTINCT requester_id) FROM confirm_requests")
    confirm_users = c2.fetchone()[0] or 0
    c2.execute("SELECT COUNT(*) FROM confirm_requests")
    confirm_total = c2.fetchone()[0] or 0

    c2.execute("SELECT COUNT(DISTINCT owner_id) FROM translation_ratings")
    rating_users = c2.fetchone()[0] or 0
    c2.execute("SELECT COUNT(*) FROM translation_ratings")
    rating_total = c2.fetchone()[0] or 0
    c2.execute("SELECT COUNT(*) FROM translation_ratings WHERE rating=1")
    rating_up = c2.fetchone()[0] or 0

    c2.execute("SELECT COUNT(*) FROM translation_history")
    history_total = c2.fetchone()[0] or 0
    c2.execute("SELECT COUNT(DISTINCT owner_id) FROM translation_history")
    history_users = c2.fetchone()[0] or 0

    ignore_rate = round(ignore_words_users / total_users * 100, 1) if total_users > 0 else 0
    phrase_rate = round(saved_phrases_users / total_users * 100, 1) if total_users > 0 else 0
    confirm_rate = round(confirm_users / total_users * 100, 1) if total_users > 0 else 0
    rating_rate = round(rating_users / total_users * 100, 1) if total_users > 0 else 0
    rating_good_rate = round(rating_up / rating_total * 100, 1) if rating_total > 0 else 0
    avg_history = round(history_total / history_users, 1) if history_users > 0 else 0

    conn.close()
    return jsonify({
        'tw_today': tw_today,
        'users': {
            'total': total_users,
            'active': active_users,
            'free': free_users,
            'inactive': inactive_users,
            'week_new': week_new_users,
            'conversion_rate': conversion_rate,
            'avg_usage_days': avg_usage_days,
            'retention_rate': retention_rate,
            'avg_renew_days': avg_renew_days,
        },
        'groups': {
            'total': total_groups,
            'active': active_groups,
            'inactive': inactive_groups,
            'pro': pro_groups,
            'basic': basic_groups,
            'avg_days': avg_group_days,
            'dnd_rate': dnd_rate,
            'multilang_rate': multilang_rate,
        },
        'translations': {
            'total': total_translations,
            'week': week_translations,
            'today': today_translations,
            'today_free_usage': today_free_usage,
            'avg_per_user': avg_trans_per_user,
            'maxed_rate': maxed_rate,
            'satisfaction_rate': satisfaction_rate,
            'rating_trend': rating_trend,
        },
        'lang_stats': lang_stats,
        'hour_stats': hour_stats,
        'daily_trend': daily_trend,
        'new_users_14d': new_users_14d,
        'new_users_trend': new_users_trend,
        'payments': {
            'count': total_payments,
            'revenue': total_revenue,
            'arpu': int(arpu),
            'renew_rate': renew_rate,
            'by_plan': plan_revenue,
            'monthly': monthly_revenue,
            'active_unpaid_users': active_unpaid_users,
            'active_unpaid_groups': active_unpaid_groups,
            'active_unpaid_total': active_unpaid_users + active_unpaid_groups,
        },
        'personal_features': {
            'ignore_words_users': ignore_words_users,
            'ignore_words_total': ignore_words_total,
            'ignore_rate': ignore_rate,
            'saved_phrases_users': saved_phrases_users,
            'saved_phrases_total': saved_phrases_total,
            'phrase_rate': phrase_rate,
            'confirm_users': confirm_users,
            'confirm_total': confirm_total,
            'confirm_rate': confirm_rate,
            'rating_users': rating_users,
            'rating_total': rating_total,
            'rating_rate': rating_rate,
            'rating_good_rate': rating_good_rate,
            'history_total': history_total,
            'history_users': history_users,
            'avg_history': avg_history,
        },
    })


@app.route('/admin/revenue-audit', methods=['GET'])
def admin_revenue_audit():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    tw_today = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d')

    c.execute("""
        SELECT u.user_id, u.plan, u.expire_date, u.created_at
        FROM users u
        WHERE u.status='active'
        AND (u.expire_date IS NULL OR u.expire_date >= %s)
        AND NOT EXISTS (
            SELECT 1 FROM payments p
            WHERE p.user_id=u.user_id AND p.status IN ('paid','success')
        )
        ORDER BY u.expire_date NULLS LAST, u.created_at DESC
        LIMIT 100
    """, (tw_today,))
    users = [{'user_id': r[0], 'plan': r[1], 'expire_date': r[2], 'created_at': r[3]} for r in c.fetchall()]

    c.execute("""
        SELECT g.group_id, g.plan, g.expire_date, g.created_at, g.note
        FROM groups g
        WHERE g.status='active'
        AND (g.expire_date IS NULL OR g.expire_date >= %s)
        AND NOT EXISTS (
            SELECT 1 FROM payments p
            WHERE p.user_id=g.group_id AND p.status IN ('paid','success')
        )
        ORDER BY g.expire_date NULLS LAST, g.created_at DESC
        LIMIT 100
    """, (tw_today,))
    groups = [{'group_id': r[0], 'plan': r[1], 'expire_date': r[2], 'created_at': r[3], 'note': r[4]} for r in c.fetchall()]

    c.execute("""
        SELECT user_id, amount, plan, payment_date, status, note
        FROM payments
        WHERE status IN ('paid','success')
        ORDER BY payment_date::timestamp DESC NULLS LAST, id DESC
        LIMIT 30
    """)
    recent = [{'user_id': r[0], 'amount': int(r[1] or 0), 'plan': r[2], 'payment_date': r[3], 'status': r[4], 'note': r[5]} for r in c.fetchall()]
    conn.close()
    return jsonify({
        'tw_today': tw_today,
        'active_without_payment_users': users,
        'active_without_payment_groups': groups,
        'recent_payments': recent,
    })


@app.route('/admin/data-health', methods=['GET'])
def admin_data_health():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    tw_today = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d')
    tw_next_7 = (datetime.utcnow() + timedelta(hours=8) + timedelta(days=7)).strftime('%Y-%m-%d')

    def fetch_dicts(sql, params=()):
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM groups")
    total_groups = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM payments WHERE status IN ('paid','success')")
    payment_count = c.fetchone()[0] or 0

    active_unpaid_users = fetch_dicts("""
        SELECT u.user_id AS id, u.plan, u.expire_date, u.created_at
        FROM users u
        WHERE u.status='active'
        AND (u.expire_date IS NULL OR u.expire_date >= %s)
        AND NOT EXISTS (
            SELECT 1 FROM payments p
            WHERE p.user_id=u.user_id AND p.status IN ('paid','success')
        )
        ORDER BY u.expire_date NULLS LAST, u.created_at DESC
        LIMIT 50
    """, (tw_today,))

    active_unpaid_groups = fetch_dicts("""
        SELECT g.group_id AS id, g.plan, g.expire_date, g.created_at
        FROM groups g
        WHERE g.status='active'
        AND (g.expire_date IS NULL OR g.expire_date >= %s)
        AND NOT EXISTS (
            SELECT 1 FROM payments p
            WHERE p.user_id=g.group_id AND p.status IN ('paid','success')
        )
        ORDER BY g.expire_date NULLS LAST, g.created_at DESC
        LIMIT 50
    """, (tw_today,))

    orphan_payments = fetch_dicts("""
        SELECT p.user_id AS id, p.amount, p.plan, p.payment_date, p.note
        FROM payments p
        WHERE p.status IN ('paid','success')
        AND NOT EXISTS (SELECT 1 FROM users u WHERE u.user_id=p.user_id)
        AND NOT EXISTS (SELECT 1 FROM groups g WHERE g.group_id=p.user_id)
        ORDER BY p.payment_date::timestamp DESC NULLS LAST, p.id DESC
        LIMIT 50
    """)

    mismatched_payments = fetch_dicts("""
        SELECT user_id AS id, amount, plan, payment_date, note
        FROM payments
        WHERE status IN ('paid','success')
        AND (
            (plan='trial' AND amount <> 49) OR
            (plan='monthly' AND amount <> 199) OR
            (plan='yearly' AND amount <> 1590) OR
            (plan='basic' AND amount <> 199) OR
            (plan='pro' AND amount <> 499)
        )
        ORDER BY payment_date::timestamp DESC NULLS LAST, id DESC
        LIMIT 50
    """)

    duplicate_payments = fetch_dicts("""
        SELECT user_id AS id, plan, amount, TO_CHAR(DATE(payment_date::timestamp), 'YYYY-MM-DD') AS pay_date, COUNT(*) AS count
        FROM payments
        WHERE status IN ('paid','success')
        GROUP BY user_id, plan, amount, DATE(payment_date::timestamp)
        HAVING COUNT(*) > 1
        ORDER BY pay_date DESC
        LIMIT 50
    """)

    expiring_users = fetch_dicts("""
        SELECT user_id AS id, plan, expire_date
        FROM users
        WHERE status='active' AND expire_date IS NOT NULL
        AND expire_date >= %s AND expire_date <= %s
        ORDER BY expire_date
        LIMIT 50
    """, (tw_today, tw_next_7))

    expiring_groups = fetch_dicts("""
        SELECT group_id AS id, plan, expire_date
        FROM groups
        WHERE status='active' AND expire_date IS NOT NULL
        AND expire_date >= %s AND expire_date <= %s
        ORDER BY expire_date
        LIMIT 50
    """, (tw_today, tw_next_7))

    conn.close()
    critical = len(orphan_payments)
    warnings = len(active_unpaid_users) + len(active_unpaid_groups) + len(mismatched_payments) + len(duplicate_payments)
    status = 'ok'
    if critical:
        status = 'critical'
    elif warnings:
        status = 'warning'
    return jsonify({
        'status': status,
        'tw_today': tw_today,
        'summary': {
            'total_users': total_users,
            'total_groups': total_groups,
            'payment_count': payment_count,
            'critical': critical,
            'warnings': warnings,
            'expiring_7d': len(expiring_users) + len(expiring_groups),
        },
        'checks': {
            'active_unpaid_users': active_unpaid_users,
            'active_unpaid_groups': active_unpaid_groups,
            'orphan_payments': orphan_payments,
            'mismatched_payments': mismatched_payments,
            'duplicate_payments': duplicate_payments,
            'expiring_users': expiring_users,
            'expiring_groups': expiring_groups,
        },
    })


@app.route('/admin/audit-logs', methods=['GET'])
def admin_audit_logs():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT id, action, target, detail, ip, created_at
        FROM admin_audit_logs
        ORDER BY id DESC
        LIMIT 100
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'id': r[0], 'action': r[1], 'target': r[2],
        'detail': r[3], 'ip': r[4], 'created_at': r[5]
    } for r in rows])


@app.route('/admin/seed-test-data', methods=['POST'])
def admin_seed_test_data():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'SEED_TEST_DATA':
        return jsonify({'error': '請確認 SEED_TEST_DATA 才能塞入測試資料'}), 400
    import random
    conn = get_db()
    c = conn.cursor()
    tw_now = datetime.utcnow() + timedelta(hours=8)

    # 塞測試用戶（10個）
    plans = ['free','active','active','active','free','active','inactive','free','active','active']
    plan_names = ['none','monthly','yearly','monthly','none','monthly','monthly','none','yearly','monthly']
    langs = [('ID','印尼文'),('VI','越南文'),('TH','泰文'),('EN-US','英文'),('JA','日文')]
    for i in range(1, 11):
        uid = 'TEST_USER_' + str(i)
        status = plans[i-1]
        plan = plan_names[i-1]
        lang = langs[i % len(langs)]
        expire = (tw_now + timedelta(days=random.randint(3,30))).strftime('%Y-%m-%d') if status=='active' else None
        c.execute('''INSERT INTO users (user_id, status, plan, expire_date, target_lang, target_name, lang_a, lang_a_name, created_at)
                     VALUES (%s,%s,%s,%s,'ZH-HANT','繁體中文',%s,%s,%s)
                     ON CONFLICT (user_id) DO NOTHING''',
                  (uid, status, plan, expire, lang[0], lang[1],
                   (tw_now - timedelta(days=random.randint(0,14))).strftime('%Y-%m-%d %H:%M:%S')))

    # 塞測試群組（3個）
    group_plans = [('active','pro'),('active','basic'),('inactive','basic')]
    for i in range(1, 4):
        gid = 'TEST_GROUP_' + str(i)
        gs, gp = group_plans[i-1]
        expire = (tw_now + timedelta(days=random.randint(5,25))).strftime('%Y-%m-%d') if gs=='active' else None
        c.execute('''INSERT INTO groups (group_id, status, plan, expire_date, lang_a, lang_a_name, lang_b, lang_b_name)
                     VALUES (%s,%s,%s,%s,'ZH-HANT','繁體中文','ID','印尼文')
                     ON CONFLICT (group_id) DO NOTHING''',
                  (gid, gs, gp, expire))

    # 塞翻譯歷史（近14天，每天10~30筆，各種語言方向，各種時段）
    directions = [
        '繁體中文 → 印尼文','印尼文 → 繁體中文',
        '繁體中文 → 越南文','越南文 → 繁體中文',
        '繁體中文 → 英文','英文 → 繁體中文',
        '繁體中文 → 泰文','泰文 → 繁體中文',
        '繁體中文 → 日文',
    ]
    owners = ['TEST_USER_'+str(i) for i in range(1,11)] + ['TEST_GROUP_1','TEST_GROUP_2']
    for day in range(14):
        base_date = tw_now - timedelta(days=day)
        count = random.randint(10, 30)
        for _ in range(count):
            hour = random.choices(range(24), weights=[
                1,1,1,1,1,2,4,8,10,10,10,9,8,9,10,10,9,8,6,5,4,3,2,1
            ])[0]
            minute = random.randint(0, 59)
            created = base_date.replace(hour=hour, minute=minute, second=random.randint(0,59))
            # 轉回 UTC 存入
            utc_created = created - timedelta(hours=8)
            direction = random.choice(directions)
            owner = random.choice(owners)
            c.execute('''INSERT INTO translation_history (owner_id, original, translated, direction, created_at)
                         VALUES (%s,%s,%s,%s,%s)''',
                      (owner, '測試原文', '測試譯文', direction, utc_created.strftime('%Y-%m-%d %H:%M:%S')))

    # 塞付款記錄（5筆）
    pay_plans = [
        ('monthly', 199), ('yearly', 1590), ('monthly', 199),
        ('trial', 49), ('pro', 499)
    ]
    for i, (plan, amt) in enumerate(pay_plans):
        uid = 'TEST_USER_' + str(i+1)
        paid_at = (tw_now - timedelta(days=random.randint(0,10))).strftime('%Y-%m-%d %H:%M:%S')
        c.execute('''INSERT INTO payments (user_id, amount, plan, payment_date, status, note)
                     VALUES (%s,%s,%s,%s,'success','test')''',
                  (uid, amt, plan, paid_at))

    # 塞今日免費用量
    today_str = tw_now.strftime('%Y-%m-%d')
    for i in range(1, 6):
        uid = 'TEST_USER_' + str(i)
        cnt = random.randint(1, 15)
        c.execute('''INSERT INTO daily_usage (user_id, use_date, count) VALUES (%s,%s,%s) ON CONFLICT (user_id, use_date) DO UPDATE SET count=EXCLUDED.count''',
                  (uid, today_str, cnt))

    conn.commit()
    conn.close()
    log_admin_action('seed_test_data', 'dashboard', '')
    return jsonify({'success': True, 'message': '測試資料已塞入，請重新整理儀表板查看'})


@app.route('/admin/clear-test-data', methods=['POST'])
def admin_clear_test_data():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'CLEAR_TEST_DATA':
        return jsonify({'error': '請確認 CLEAR_TEST_DATA 才能清除測試資料'}), 400
    conn = get_db()
    c = conn.cursor()
    # 刪除所有 TEST_ 開頭的測試資料
    c.execute("DELETE FROM users WHERE user_id LIKE 'TEST_%'")
    c.execute("DELETE FROM groups WHERE group_id LIKE 'TEST_%'")
    c.execute("DELETE FROM translation_history WHERE owner_id LIKE 'TEST_%'")
    c.execute("DELETE FROM payments WHERE note='test'")
    c.execute("DELETE FROM daily_usage WHERE user_id LIKE 'TEST_%'")
    conn.commit()
    conn.close()
    log_admin_action('clear_test_data', 'dashboard', '')
    return jsonify({'success': True, 'message': '測試資料已全部清除'})


@app.route('/admin/reset-test-stage', methods=['POST'])
def admin_reset_test_stage():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'RESET_TEST_STAGE_ALL':
        return jsonify({'error': '請確認 RESET_TEST_STAGE_ALL 才能清除全部測試階段資料'}), 400

    conn = get_db()
    c = conn.cursor()
    tables = [
        'referral_records',
        'referral_codes',
        'translation_ratings',
        'group_dnd',
        'group_multilang',
        'confirm_replies',
        'confirm_requests',
        'saved_phrases',
        'daily_usage',
        'translation_history',
        'payments',
        'blacklist',
        'crm_notes',
        'groups',
        'users',
    ]
    deleted = {}
    for table in tables:
        c.execute('DELETE FROM ' + table)
        deleted[table] = c.rowcount
    conn.commit()
    conn.close()
    log_admin_action('reset_test_stage', 'dashboard', 'all users/groups/payments/referrals cleared')
    return jsonify({
        'success': True,
        'message': '測試階段資料已歸零：所有 users、groups、付款、用量、翻譯紀錄、推薦紀錄已清除',
        'deleted': deleted,
    })


@app.route('/admin/ratings', methods=['GET'])
def admin_ratings():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    # 總體統計
    c.execute('SELECT COUNT(*), SUM(rating) FROM translation_ratings')
    row = c.fetchone()
    total = row[0] or 0
    good = int(row[1] or 0)
    bad = total - good
    rate = round(good / total * 100, 1) if total > 0 else 0
    # 最近30筆
    c.execute('''SELECT owner_id, original_text, translated_text, rating, created_at
        FROM translation_ratings ORDER BY created_at DESC LIMIT 30''')
    recent = [{'owner_id': r[0], 'original': r[1], 'translated': r[2],
               'rating': r[3], 'created_at': r[4]} for r in c.fetchall()]
    # 每日統計（近14天）
    c.execute('''SELECT DATE(created_at) as d, SUM(rating), COUNT(*)
        FROM translation_ratings
        WHERE created_at::timestamp >= NOW() - INTERVAL '14 days'
        GROUP BY d ORDER BY d''')
    daily = [{'date': r[0], 'good': int(r[1] or 0), 'total': r[2]} for r in c.fetchall()]
    conn.close()
    return jsonify({'total': total, 'good': good, 'bad': bad, 'rate': rate,
                    'recent': recent, 'daily': daily})


def get_broadcast_user_ids(target):
    target = (target or 'all').strip()
    today_tw = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d')
    seven_days_ago_tw = (datetime.utcnow() + timedelta(hours=8) - timedelta(days=7)).strftime('%Y-%m-%d')
    conn = get_db()
    c = conn.cursor()
    if target == 'free':
        c.execute('''
            SELECT u.user_id
            FROM users u
            WHERE u.user_id NOT LIKE 'TEST_%'
              AND (u.status = 'free' OR COALESCE(u.plan, '') IN ('', 'none', 'free'))
              AND NOT EXISTS (
                SELECT 1 FROM payments p
                WHERE p.user_id = u.user_id AND COALESCE(p.status, 'success') = 'success'
              )
            ORDER BY u.created_at DESC NULLS LAST
        ''')
    elif target == 'expired':
        c.execute('''
            SELECT u.user_id
            FROM users u
            WHERE u.user_id NOT LIKE 'TEST_%'
              AND (
                u.status = 'inactive'
                OR (NULLIF(u.expire_date, '') IS NOT NULL AND u.expire_date < %s)
              )
              AND EXISTS (
                SELECT 1 FROM payments p
                WHERE p.user_id = u.user_id AND COALESCE(p.status, 'success') = 'success'
              )
            ORDER BY u.expire_date DESC NULLS LAST
        ''', (today_tw,))
    elif target == 'no_renew':
        c.execute('''
            SELECT u.user_id
            FROM users u
            WHERE u.user_id NOT LIKE 'TEST_%'
              AND NULLIF(u.expire_date, '') IS NOT NULL
              AND u.expire_date < %s
              AND EXISTS (
                SELECT 1 FROM payments p
                WHERE p.user_id = u.user_id AND COALESCE(p.status, 'success') = 'success'
              )
            ORDER BY u.expire_date DESC NULLS LAST
        ''', (seven_days_ago_tw,))
    else:
        c.execute('''
            SELECT user_id
            FROM users
            WHERE user_id NOT LIKE 'TEST_%'
            ORDER BY created_at DESC NULLS LAST
        ''')
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows if r and r[0]]


@app.route('/admin/broadcast-list', methods=['GET'])
def admin_broadcast_list():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    target = request.args.get('target', 'all')
    if target not in ('all', 'free', 'expired', 'no_renew'):
        return jsonify({'error': '不支援的發送對象'}), 400
    user_ids = get_broadcast_user_ids(target)
    return jsonify({
        'success': True,
        'target': target,
        'count': len(user_ids),
        'users': user_ids[:500],
        'truncated': len(user_ids) > 500
    })


@app.route('/admin/broadcast-send', methods=['POST'])
def admin_broadcast_send():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    target = data.get('target', 'all')
    message = (data.get('message') or '').strip()
    if data.get('confirm') != 'SEND_BROADCAST':
        return jsonify({'error': '請確認 SEND_BROADCAST 才能群發訊息'}), 400
    try:
        expected_count = int(data.get('expected_count') or 0)
    except (TypeError, ValueError):
        return jsonify({'error': '預期人數格式錯誤'}), 400
    if target not in ('all', 'free', 'expired', 'no_renew'):
        return jsonify({'error': '不支援的發送對象'}), 400
    if not message:
        return jsonify({'error': '訊息內容不可為空'}), 400
    if len(message) > 1000:
        return jsonify({'error': '訊息內容超過 1000 字'}), 400
    user_ids = get_broadcast_user_ids(target)
    if expected_count and expected_count != len(user_ids):
        return jsonify({'error': '名單人數已變動，請重新預覽後再發送'}), 409
    if len(user_ids) > 500:
        return jsonify({'error': '單次群發上限 500 人，請縮小名單'}), 400
    sent = 0
    failed = 0
    for user_id in user_ids:
        try:
            line_bot_api.push_message(user_id, TextSendMessage(text=message))
            sent += 1
        except Exception as e:
            failed += 1
            print('[broadcast_send] failed:', user_id, e)
        time.sleep(0.05)
    log_admin_action('broadcast_send', target, 'sent=' + str(sent) + ', failed=' + str(failed) + ', chars=' + str(len(message)))
    return jsonify({'success': True, 'target': target, 'total': len(user_ids), 'sent': sent, 'failed': failed})


@app.route('/admin/crm-note', methods=['POST'])
def admin_crm_note():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({'error': '缺少資料'}), 400
    target_type = (data.get('type') or '').strip()
    target_id = (data.get('id') or '').strip()
    tag = (data.get('tag') or '').strip()
    note = (data.get('note') or '').strip()
    if not target_type or not target_id:
        return jsonify({'error': '缺少 type 或 id'}), 400
    if target_type not in ('user', 'group'):
        return jsonify({'error': 'type 只能是 user 或 group'}), 400
    if len(tag) > 50:
        return jsonify({'error': '標籤不可超過 50 字'}), 400
    if len(note) > 1000:
        return jsonify({'error': '備註不可超過 1000 字'}), 400
    conn = get_db()
    c = conn.cursor()
    try:
        if target_type == 'user':
            # 確保欄位存在
            try:
                c.execute('ALTER TABLE users ADD COLUMN crm_tag TEXT DEFAULT ""')
                c.execute('ALTER TABLE users ADD COLUMN crm_note TEXT DEFAULT ""')
            except:
                pass
            c.execute('UPDATE users SET crm_tag=%s, crm_note=%s WHERE user_id=%s',
                      (tag, note, target_id))
        elif target_type == 'group':
            try:
                c.execute('ALTER TABLE groups ADD COLUMN crm_tag TEXT DEFAULT ""')
                c.execute('ALTER TABLE groups ADD COLUMN crm_note TEXT DEFAULT ""')
            except:
                pass
            c.execute('UPDATE groups SET crm_tag=%s, crm_note=%s WHERE group_id=%s',
                      (tag, note, target_id))
        if c.rowcount == 0:
            conn.rollback()
            conn.close()
            return jsonify({'error': '找不到此' + ('用戶' if target_type == 'user' else '群組')}), 404
        conn.commit()
        conn.close()
        log_admin_action('crm_note_update', target_id, 'type=' + target_type + ', tag=' + tag)
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500




@app.route('/track/pixel', methods=['GET'])
def track_pixel():
    """像素追蹤（GET 方式，完全不受 CORS 限制）"""
    if not check_crawler('/track/pixel'):
        from flask import Response
        gif = base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')
        return Response(gif, mimetype='image/gif')
    try:
        page = request.args.get('p', 'unknown')[:100]
        referrer = request.args.get('r', '')[:200]
        ua = request.headers.get('User-Agent', '')[:200]
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip:
            ip = ip.split(',')[0].strip()[:50]
        tw_now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db()
        cu = conn.cursor()
        cu.execute(
            "INSERT INTO page_views (page, referrer, ua, ip, created_at) VALUES (%s, %s, %s, %s, %s)",
            (page, referrer, ua, ip, tw_now)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print('[track_pixel] error:', e)
    # 回傳 1x1 透明 GIF
    import base64
    gif = base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')
    from flask import Response
    resp = Response(gif, mimetype='image/gif')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

@app.route('/track', methods=['POST'])
def track_page():
    """網頁瀏覽追蹤（由靜態網頁呼叫）"""
    if not check_crawler('/track'):
        resp = jsonify({'ok': False})
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp, 429
    try:
        data = request.get_json(silent=True) or {}
        page = data.get('page', 'unknown')[:100]
        referrer = data.get('referrer', '')[:200]
        ua = request.headers.get('User-Agent', '')[:200]
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip:
            ip = ip.split(',')[0].strip()[:50]
        tw_now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO page_views (page, referrer, ua, ip, created_at) VALUES (%s, %s, %s, %s, %s)",
            (page, referrer, ua, ip, tw_now)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print('[track] error:', e)
    resp = jsonify({'ok': True})
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

@app.route('/track', methods=['OPTIONS'])
def track_options():
    resp = jsonify({})
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp

@app.route('/admin/page-views', methods=['GET'])
def admin_page_views():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    conn = get_db()
    c = conn.cursor()
    tw_today = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d')

    # 各頁面今日 / 近7日 / 總計
    pages = ['index', 'blog', 'blog-foreign-worker-communication', 'blog-foreign-worker-safety-law']
    result = {}
    for p in pages:
        c.execute("SELECT COUNT(*) FROM page_views WHERE page=%s AND created_at >= %s", (p, tw_today))
        today = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM page_views WHERE page=%s AND created_at::timestamp >= NOW() - INTERVAL '7 days'", (p,))
        week = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM page_views WHERE page=%s", (p,))
        total = c.fetchone()[0]
        result[p] = {'today': today, 'week': week, 'total': total}

    # 近14天每日趨勢（全站）
    c.execute("""
        SELECT DATE(created_at::timestamp) as d, page, COUNT(*) as cnt
        FROM page_views
        WHERE created_at::timestamp >= NOW() - INTERVAL '14 days'
        GROUP BY d, page
        ORDER BY d
    """)
    rows = c.fetchall()
    trend = {}
    for d, page, cnt in rows:
        ds = str(d)
        if ds not in trend:
            trend[ds] = {}
        trend[ds][page] = cnt

    # 來源分析（referrer top10）
    c.execute("""
        SELECT referrer, COUNT(*) as cnt
        FROM page_views
        WHERE referrer != '' AND referrer IS NOT NULL
        GROUP BY referrer
        ORDER BY cnt DESC
        LIMIT 10
    """)
    referrers = [{'referrer': r[0], 'count': r[1]} for r in c.fetchall()]

    # 今日每小時分佈
    c.execute("""
        SELECT EXTRACT(HOUR FROM created_at::timestamp)::INTEGER as h, COUNT(*) as cnt
        FROM page_views
        WHERE created_at >= %s
        GROUP BY h ORDER BY h
    """, (tw_today,))
    hour_data = {str(h): 0 for h in range(24)}
    for h, cnt in c.fetchall():
        hour_data[str(int(h))] = cnt

    conn.close()
    return jsonify({
        'pages': result,
        'trend': trend,
        'referrers': referrers,
        'hour_data': hour_data,
        'tw_today': tw_today,
    })


@app.route('/admin/clear-page-views', methods=['POST'])
def admin_clear_page_views():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'DELETE_PAGE_VIEWS':
        return jsonify({'error': '請輸入 DELETE_PAGE_VIEWS 才能清空瀏覽紀錄'}), 400
    conn = get_db()
    cu = conn.cursor()
    cu.execute("DELETE FROM page_views")
    conn.commit()
    conn.close()
    log_admin_action('clear_page_views', 'traffic', '')
    return jsonify({'ok': True, 'msg': '瀏覽紀錄已清空'})

@app.route('/admin/clear-all-data', methods=['POST'])
def admin_clear_all_data():
    """清空所有數據（翻譯歷史、用量、付款記錄）— 上線前測試清理用"""
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'DELETE':
        return jsonify({'error': '請輸入 DELETE 才能清空正式數據'}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM translation_history")
    c.execute("DELETE FROM daily_usage")
    c.execute("DELETE FROM payments")
    c.execute("DELETE FROM users WHERE user_id LIKE 'TEST_%'")
    c.execute("DELETE FROM groups WHERE group_id LIKE 'TEST_%'")
    c.execute("DELETE FROM confirm_requests")
    c.execute("DELETE FROM confirm_replies")
    conn.commit()
    conn.close()
    log_admin_action('clear_all_data', 'dashboard', 'translation_history,daily_usage,payments,test_users,test_groups,confirm_requests')
    return jsonify({'success': True, 'message': '所有數據已清空（用戶帳號保留，翻譯記錄、用量、付款記錄已清除）'})


@app.route('/admin/test-crawler', methods=['POST'])
def admin_test_crawler():
    if not is_admin_token_valid():
        return jsonify({'error': '無權限'}), 403
    try:
        tw_now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        msg = (
            '🧪 爬蟲防護測試\n'
            '時間：' + tw_now + '\n'
            'IP：TEST-127.0.0.1\n'
            '1分鐘請求數：31\n'
            '攻擊入口：/track/pixel\n'
            '說明：網站瀏覽追蹤像素\n→ 對方可能在掃描你的流量系統\n\n'
            '✅ 防護系統運作正常！\n\n'
            '─────────────────\n'
            '📋 你的所有入口：\n'
            '/track/pixel → 流量追蹤像素\n'
            '/track → 流量追蹤(POST)\n'
            '/webhook → LINE Bot\n'
            '/admin → 後台管理\n'
            '/ecpay/notify → 付款回調\n'
            '/ecpay/return → 付款結果\n'
            '/pay → 付款頁面\n'
            '─────────────────'
        )
        line_bot_api.push_message(ADMIN_LINE_ID, TextSendMessage(text=msg))
        return jsonify({'success': True, 'msg': 'LINE 通知已發送，請確認是否收到'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin')
def admin_page():
    if not check_admin_ip():
        return jsonify({'error': '存取被拒絕'}), 403
    with open('admin.html', 'r', encoding='utf-8') as f:
        return f.read()


@app.route('/privacy')
def privacy_page():
    with open('privacy.html', 'r', encoding='utf-8') as f:
        return f.read()


@app.route('/terms')
def terms_page():
    with open('terms.html', 'r', encoding='utf-8') as f:
        return f.read()


@app.route('/refund')
def refund_page():
    with open('refund.html', 'r', encoding='utf-8') as f:
        return f.read()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

