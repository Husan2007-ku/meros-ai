"""
MEROS AI — Backend API
Flask + SQLite | JWT Auth | REST API
"""

from flask import Flask, request, jsonify, g, send_from_directory
from functools import wraps
import sqlite3
import hashlib
import hmac
from werkzeug.security import generate_password_hash, check_password_hash
import json
import uuid
import datetime
import jwt
import os
import re

def verify_password(stored_hash, plain_password):
    """Backward-compatible check: new/updated accounts use salted pbkdf2
    hashes (werkzeug), legacy accounts still have unsalted sha256 hashes
    from before this fix -- both are verified so no one is locked out."""
    if stored_hash and (stored_hash.startswith('pbkdf2:') or stored_hash.startswith('scrypt:')):
        return check_password_hash(stored_hash, plain_password)
    return stored_hash == hashlib.sha256(plain_password.encode()).hexdigest()


# --- Field-level encryption for sensitive ID data (passport number, series, PINFL) ---
from cryptography.fernet import Fernet, InvalidToken

_ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not _ENCRYPTION_KEY:
    # Dev-only fallback so the app still boots locally without config -- NOT safe for
    # production. Render deployment must set ENCRYPTION_KEY (see .env.example / README).
    _ENCRYPTION_KEY = 'jK71u9y4v0Q6z2A8b3C5d7E9f1G3h5J7k9L1m3N5p7Q='
    print("WARNING: ENCRYPTION_KEY not set -- using an insecure dev default. "
          "Set ENCRYPTION_KEY in production (Render env vars).")
_fernet = Fernet(_ENCRYPTION_KEY.encode() if isinstance(_ENCRYPTION_KEY, str) else _ENCRYPTION_KEY)

def encrypt_field(value):
    if value is None or value == '':
        return value
    return _fernet.encrypt(str(value).encode()).decode()

def decrypt_field(value):
    """Backward-compatible: rows written before this fix hold plaintext, so a failed
    decrypt just returns the original value instead of erroring out."""
    if value is None or value == '':
        return value
    try:
        return _fernet.decrypt(value.encode()).decode()
    except (InvalidToken, ValueError, Exception):
        return value

# --- AI Family Coach: Claude (primary) with OpenAI fallback (real LLM calls) ---
import requests

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')
ANTHROPIC_MODEL = os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-5')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
OPENAI_MODEL = os.environ.get('OPENAI_MODEL', 'gpt-4o-mini')

def _build_coach_prompt(focus_area, category_scores, labels, lang):
    focus_label = labels.get(focus_area, focus_area)
    scores_desc = ', '.join(
        f"{labels.get(k, k)}: {v}%" for k, v in category_scores.items() if v is not None)
    return (
        "Sen MEROS AI ilovasining oilaviy wellbeing yordamchisisan. "
        "Foydalanuvchi 5 yo'nalishli o'z-o'zini baholash testini topshirdi.\n"
        f"Natijalar: {scores_desc}.\n"
        f"Eng ko'p e'tibor talab qiladigan yo'nalish: {focus_label}.\n\n"
        "Shu yo'nalish bo'yicha 2-3 jumlali, iliq va amaliy maslahat yoz.\n"
        "QAT'IY QOIDALAR: tashxis qo'yma; professional psixolog yoki mutaxassis o'rnini "
        "bosma; manbasiz statistika yoki foiz keltirma; ajrashish yoki alohida yashashni "
        "tavsiya qilma; agar zo'ravonlik yoki jiddiy xavf alomatlari sezilsa, albatta "
        "mutaxassisga murojaat qilishni tavsiya qil. Javobni o'zbek tilida yoz."
    )

def _try_claude(prompt):
    if not ANTHROPIC_API_KEY:
        return None, "ANTHROPIC_API_KEY o'rnatilmagan"
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15,
        )
        data = resp.json()
        if resp.status_code != 200:
            return None, (data.get('error') or {}).get('message', 'Claude xatosi')
        text = data['content'][0]['text']
        return text.strip(), None
    except Exception as e:
        return None, f"Claude vaqtincha ishlamayapti ({e.__class__.__name__})"

def _try_openai(prompt):
    if not OPENAI_API_KEY:
        return None, "OPENAI_API_KEY o'rnatilmagan"
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": OPENAI_MODEL,
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15,
        )
        data = resp.json()
        if resp.status_code != 200:
            return None, (data.get('error') or {}).get('message', 'OpenAI xatosi')
        text = data['choices'][0]['message']['content']
        return text.strip(), None
    except Exception as e:
        return None, f"OpenAI vaqtincha ishlamayapti ({e.__class__.__name__})"

def generate_ai_coach_insight(focus_area, category_scores, labels, lang):
    """Claude birinchi urinadi; ishlamasa OpenAI'ga fallback qiladi. Ikkalasi ham
    muvaffaqiyatsiz bo'lsa, foydalanuvchiga tushunarli xato qaytaradi (crash bermaydi)."""
    prompt = _build_coach_prompt(focus_area, category_scores, labels, lang)

    text, error1 = _try_claude(prompt)
    if text:
        return text, None

    text, error2 = _try_openai(prompt)
    if text:
        return text, None

    return None, f"AI xizmatlari hozircha javob bermayapti (Claude: {error1}; OpenAI: {error2})"


FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'meros-ai-secret-2026-dev')
app.config['MAX_CONTENT_LENGTH'] = 12 * 1024 * 1024  # 12MB hard cap (covers our largest media type + headers)
DATA_DIR = os.environ.get('DATA_DIR', '/data' if os.path.exists('/data') else os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, 'meros.db')

# ─── DB ─────────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript("""
    PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;

    CREATE TABLE IF NOT EXISTS users (
        id          TEXT PRIMARY KEY,
        phone       TEXT UNIQUE NOT NULL,
        full_name   TEXT NOT NULL,
        birth_date  TEXT,
        gender      TEXT,
        password_hash TEXT NOT NULL,
        family_id   TEXT,
        role        TEXT DEFAULT 'adult',
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS families (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        created_by  TEXT NOT NULL,
        invite_code TEXT UNIQUE,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS family_members (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        user_id     TEXT,
        name        TEXT NOT NULL,
        birth_date  TEXT,
        gender      TEXT,
        role        TEXT NOT NULL,
        avatar_color TEXT DEFAULT '#1A56A0',
        avatar_url  TEXT,
        status      TEXT DEFAULT 'active',
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS health_records (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        member_id   TEXT NOT NULL,
        record_type TEXT NOT NULL,
        title       TEXT NOT NULL,
        value       TEXT,
        unit        TEXT,
        date        TEXT NOT NULL,
        notes       TEXT,
        status      TEXT DEFAULT 'normal',
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS vaccines (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        member_id   TEXT NOT NULL,
        name        TEXT NOT NULL,
        dose_number INTEGER DEFAULT 1,
        scheduled_date TEXT NOT NULL,
        done_date   TEXT,
        status      TEXT DEFAULT 'scheduled',
        location    TEXT,
        notes       TEXT,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS albums (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        creator_id  TEXT NOT NULL,
        name        TEXT NOT NULL,
        emoji       TEXT DEFAULT '📁',
        color       TEXT DEFAULT '#DBEAFE',
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS memories (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        uploader_id TEXT NOT NULL,
        album_id    TEXT,
        title       TEXT,
        description TEXT,
        media_type  TEXT DEFAULT 'photo',
        media_url   TEXT,
        emoji       TEXT DEFAULT '📷',
        color       TEXT DEFAULT '#DBEAFE',
        taken_at    TEXT NOT NULL,
        location    TEXT,
        tags        TEXT DEFAULT '[]',
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS time_capsules (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        creator_id  TEXT NOT NULL,
        title       TEXT NOT NULL,
        message     TEXT NOT NULL,
        recipient   TEXT NOT NULL,
        open_date   TEXT NOT NULL,
        is_opened   INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS warmth_logs (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        happiness   INTEGER NOT NULL,
        supported   INTEGER NOT NULL,
        avg_score   REAL NOT NULL,
        log_date    TEXT NOT NULL,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        creator_id  TEXT,
        type        TEXT NOT NULL,
        title       TEXT NOT NULL,
        body        TEXT NOT NULL,
        reminder_date TEXT,
        severity    TEXT DEFAULT 'info',
        is_read     INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS otp_codes (
        phone       TEXT PRIMARY KEY,
        code        TEXT NOT NULL,
        expires_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS compatibility_tests (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        partner_name TEXT,
        answers     TEXT NOT NULL,
        scores      TEXT NOT NULL,
        overall_score INTEGER NOT NULL,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS messages (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        sender_id   TEXT NOT NULL,
        channel     TEXT DEFAULT 'family',
        body        TEXT NOT NULL,
        kind        TEXT DEFAULT 'text',
        media_url   TEXT,
        is_read     INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS passport_data (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        member_id   TEXT NOT NULL,
        full_name   TEXT,
        passport_series TEXT,
        passport_number TEXT,
        birth_date  TEXT,
        birth_place TEXT,
        issued_by   TEXT,
        issued_date TEXT,
        expiry_date TEXT,
        pinfl       TEXT,
        created_at  TEXT DEFAULT (datetime('now')),
        updated_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS important_dates (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        creator_id  TEXT NOT NULL,
        title       TEXT NOT NULL,
        date        TEXT NOT NULL,
        type        TEXT DEFAULT 'custom',
        recurring   INTEGER DEFAULT 1,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS family_assessments (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        answers     TEXT NOT NULL,
        category_scores TEXT NOT NULL,
        focus_area  TEXT,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS coach_insights (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        assessment_id TEXT,
        focus_area  TEXT,
        insight_text TEXT NOT NULL,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS daily_checkins (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        checkin_date TEXT NOT NULL,
        question_id TEXT,
        question_text TEXT,
        answer_text TEXT,
        task_id     TEXT,
        task_text   TEXT,
        task_done   INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now')),
        UNIQUE(family_id, user_id, checkin_date)
    );

    CREATE TABLE IF NOT EXISTS conflict_topics (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        topic_key   TEXT NOT NULL,
        status      TEXT NOT NULL,
        updated_at  TEXT DEFAULT (datetime('now')),
        UNIQUE(family_id, user_id, topic_key)
    );
    """)
    db.commit()

    # Migration: add invite_code column if it doesn't exist (for databases created before this feature)
    cols = [row[1] for row in db.execute("PRAGMA table_info(families)").fetchall()]
    if 'invite_code' not in cols:
        db.execute("ALTER TABLE families ADD COLUMN invite_code TEXT")
        db.commit()

    # Backfill: ensure existing families (created before this feature) have a code
    families_without_code = db.execute("SELECT id FROM families WHERE invite_code IS NULL").fetchall()
    for fam in families_without_code:
        new_code = generate_invite_code()
        db.execute("UPDATE families SET invite_code=? WHERE id=?", (new_code, fam['id']))
    if families_without_code:
        db.commit()

    # Migration: add album_id column to memories if it doesn't exist
    mem_cols = [row[1] for row in db.execute("PRAGMA table_info(memories)").fetchall()]
    if 'album_id' not in mem_cols:
        db.execute("ALTER TABLE memories ADD COLUMN album_id TEXT")
        db.commit()

    # Migration: add media_url column to messages if it doesn't exist
    msg_cols = [row[1] for row in db.execute("PRAGMA table_info(messages)").fetchall()]
    if 'media_url' not in msg_cols:
        db.execute("ALTER TABLE messages ADD COLUMN media_url TEXT")
        db.commit()

    # Migration: add avatar_url column to family_members if it doesn't exist
    fm_cols = [row[1] for row in db.execute("PRAGMA table_info(family_members)").fetchall()]
    if 'avatar_url' not in fm_cols:
        db.execute("ALTER TABLE family_members ADD COLUMN avatar_url TEXT")
        db.commit()
    if 'status' not in fm_cols:
        db.execute("ALTER TABLE family_members ADD COLUMN status TEXT DEFAULT 'active'")
        db.execute("UPDATE family_members SET status='active' WHERE status IS NULL")
        db.commit()

    # Migration: add creator_id and reminder_date columns to alerts if missing
    alert_cols = [row[1] for row in db.execute("PRAGMA table_info(alerts)").fetchall()]
    if 'creator_id' not in alert_cols:
        db.execute("ALTER TABLE alerts ADD COLUMN creator_id TEXT")
        db.commit()
    if 'reminder_date' not in alert_cols:
        db.execute("ALTER TABLE alerts ADD COLUMN reminder_date TEXT")
        db.commit()

    # Migration: add channel column to messages if it doesn't exist (default existing rows to 'family')
    msg_cols2 = [row[1] for row in db.execute("PRAGMA table_info(messages)").fetchall()]
    if 'channel' not in msg_cols2:
        db.execute("ALTER TABLE messages ADD COLUMN channel TEXT DEFAULT 'family'")
        db.execute("UPDATE messages SET channel='family' WHERE channel IS NULL")
        db.commit()

    # Migration: add role and birth_date columns to users if missing
    user_cols = [row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()]
    if 'role' not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'adult'")
        db.execute("UPDATE users SET role='adult' WHERE role IS NULL")
        db.commit()
    if 'birth_date' not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN birth_date TEXT")
        db.commit()

    # Seed demo data
    _seed_demo(db)
    db.close()

def _seed_demo(db):
    existing = db.execute("SELECT id FROM users WHERE phone='+998901234567'").fetchone()
    if existing:
        return

    fam_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    spouse_id = str(uuid.uuid4())

    pw = generate_password_hash("demo123")

    db.execute("INSERT INTO families(id,name,created_by,invite_code) VALUES (?,?,?,?)",
               (fam_id, "Malikov oilasi", user_id, "MEROS01"))

    db.execute("""INSERT INTO users VALUES (?,?,?,?,?,?,?,?,datetime('now'))""",
               (user_id, '+998901234567', 'Malikov Husan',
                '1990-03-15', 'male', pw, fam_id, 'adult'))
    db.execute("""INSERT INTO users VALUES (?,?,?,?,?,?,?,?,datetime('now'))""",
               (spouse_id, '+998907654321', 'Malikova Zulfiya',
                '1993-07-22', 'female', pw, fam_id, 'adult'))

    aziz_id = str(uuid.uuid4())
    lola_id = str(uuid.uuid4())

    members = [
        (str(uuid.uuid4()), fam_id, user_id,   'Husan',  '1990-03-15', 'male',   'parent',  '#1A78C2'),
        (str(uuid.uuid4()), fam_id, spouse_id,  'Zulfiya','1993-07-22', 'female', 'parent',  '#C2185B'),
        (aziz_id,           fam_id, None,        'Aziz',  '2017-05-12', 'male',   'child',   '#2D7A4F'),
        (lola_id,           fam_id, None,        'Lola',  '2021-02-08', 'female', 'child',   '#7B2D8B'),
    ]
    for m in members:
        db.execute("""INSERT INTO family_members
            (id,family_id,user_id,name,birth_date,gender,role,avatar_color,created_at)
            VALUES (?,?,?,?,?,?,?,?,datetime('now'))""", m)

    today = datetime.date.today().isoformat()
    in30 = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    past  = (datetime.date.today() - datetime.timedelta(days=400)).isoformat()
    past2 = (datetime.date.today() - datetime.timedelta(days=200)).isoformat()

    vaccines = [
        (str(uuid.uuid4()), fam_id, lola_id, 'BCG (Sil kasalligi)', 1, '2021-03-15', '2021-03-15', 'done', 'Yunusobod 3-poliklinikasi', None),
        (str(uuid.uuid4()), fam_id, lola_id, 'Gepatit B (1-doza)',  1, '2021-03-15', '2021-03-15', 'done', 'Yunusobod 3-poliklinikasi', None),
        (str(uuid.uuid4()), fam_id, lola_id, 'Polio (4-doza)',      4, today,         None,          'scheduled', 'Yunusobod 3-poliklinikasi', '14:00 da'),
        (str(uuid.uuid4()), fam_id, lola_id, 'MMR (2-doza)',        2, '2024-04-01',  None,          'overdue', None, None),
        (str(uuid.uuid4()), fam_id, lola_id, 'Gripp (mavsumiy)',    1, '2025-10-01',  None,          'scheduled', None, None),
        (str(uuid.uuid4()), fam_id, aziz_id, 'BCG (Sil kasalligi)', 1, '2017-06-01', '2017-06-01', 'done', None, None),
        (str(uuid.uuid4()), fam_id, aziz_id, 'Gepatit B (3-doza)', 3, '2017-09-01', '2017-09-01', 'done', None, None),
    ]
    for v in vaccines:
        db.execute("INSERT INTO vaccines VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))", v)

    health = [
        (str(uuid.uuid4()), fam_id, lola_id, 'measurement', "Bo'y", '102', 'sm', past2, None, 'normal'),
        (str(uuid.uuid4()), fam_id, lola_id, 'measurement', 'Vazn',  '16.2','kg', past2, None, 'normal'),
        (str(uuid.uuid4()), fam_id, aziz_id, 'measurement', "Bo'y", '128', 'sm', past2, None, 'normal'),
        (str(uuid.uuid4()), fam_id, aziz_id, 'measurement', 'Vazn',  '27',  'kg', past2, None, 'normal'),
    ]
    for h in health:
        db.execute("INSERT INTO health_records VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))", h)

    memories_data = [
        (str(uuid.uuid4()), fam_id, user_id, "Yoz ta'tili", "Dengiz bo'yida", 'photo', None, '🏖️', '#DBEAFE', '2025-07-15', 'Antaliya', '["oila","yoz"]'),
        (str(uuid.uuid4()), fam_id, user_id, "Azizning tug'ilgan kuni", "8 yosh!", 'photo', None, '🎂', '#DCF5E7', '2025-05-12', 'Toshkent', '["Aziz","bayram"]'),
        (str(uuid.uuid4()), fam_id, user_id, "Navro'z", "Oila bilan", 'photo', None, '🌸', '#FEF3DC', '2025-03-21', 'Toshkent', '["Navro\'z"]'),
        (str(uuid.uuid4()), fam_id, user_id, "Lola tug'ilganda", "Birinchi kun", 'photo', None, '👶', '#EDE9FE', '2021-02-08', 'Toshkent shifoxona', '["Lola"]'),
        (str(uuid.uuid4()), fam_id, user_id, "Aziz birinchi maktabga", None, 'photo', None, '🎓', '#FDECEA', '2024-09-01', 'Maktab', '["Aziz","maktab"]'),
        (str(uuid.uuid4()), fam_id, user_id, "Yangi uy", None, 'photo', None, '🏡', '#E1F5EE', '2023-06-10', 'Toshkent', '["uy"]'),
        (str(uuid.uuid4()), fam_id, user_id, "Nikoh kuni", "5 yil oldin", 'photo', None, '❤️', '#FEE2E2', '2019-07-15', 'Toshkent', '["nikoh"]'),
        (str(uuid.uuid4()), fam_id, user_id, "Lolaning birinchi qadamlari", None, 'photo', None, '🎠', '#F5F3FF', '2022-04-20', 'Uy', '["Lola"]'),
        (str(uuid.uuid4()), fam_id, user_id, "Bog'da", None, 'photo', None, '🌿', '#ECFDF5', '2025-04-10', "Bog'", '["oila"]'),
    ]
    for m in memories_data:
        db.execute("""INSERT INTO memories
            (id,family_id,uploader_id,title,description,media_type,media_url,emoji,color,taken_at,location,tags,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))""", m)

    open_date1 = f"{2017+18}-05-12"
    open_date2 = f"{2021+18}-02-08"
    capsules = [
        (str(uuid.uuid4()), fam_id, user_id, "Azizga 18 yoshda", "O'g'lim, bu xatni 18 yoshingda o'qiyapsanmi? Sen hali 8 yoshdasan va...", 'Aziz', open_date1, 0),
        (str(uuid.uuid4()), fam_id, user_id, "Lolaga 18 yoshda", "Qizim Lola, sen dunyo uchun eng go'zal sovg'asan...", 'Lola', open_date2, 0),
    ]
    for c in capsules:
        db.execute("INSERT INTO time_capsules VALUES (?,?,?,?,?,?,?,?,datetime('now'))", c)

    # Warmth last 7 days
    scores = [3,4,4,5,4,5]
    for i, sc in enumerate(scores):
        day = (datetime.date.today() - datetime.timedelta(days=6-i)).isoformat()
        db.execute("INSERT INTO warmth_logs VALUES (?,?,?,?,?,?,?,datetime('now'))",
                   (str(uuid.uuid4()), fam_id, user_id, sc, sc, sc, day))

    alerts_data = [
        (str(uuid.uuid4()), fam_id, 'vaccine',  "Emlash bugun!", "Lolaning Polio (4-doza) emlashi bugun 14:00 da", 'warning', 0),
        (str(uuid.uuid4()), fam_id, 'vaccine',  "Kechiktirilgan emlash", "Lolaning MMR (2-doza) emlashi kechiktirildi", 'danger', 0),
        (str(uuid.uuid4()), fam_id, 'screen',   "Oila vaqti", "Bugun 3 soatdan beri hamma telefonda", 'info', 0),
    ]
    for a in alerts_data:
        db.execute("""INSERT INTO alerts
            (id,family_id,type,title,body,severity,is_read,created_at)
            VALUES (?,?,?,?,?,?,?,datetime('now'))""", a)

    # Important dates
    important_dates = [
        (str(uuid.uuid4()), fam_id, user_id, 'Nikoh kuni', '2019-07-15', 'wedding'),
        (str(uuid.uuid4()), fam_id, user_id, 'Birinchi uchrashuv', '2017-03-08', 'anniversary'),
    ]
    for d in important_dates:
        db.execute(
            "INSERT INTO important_dates(id,family_id,creator_id,title,date,type,recurring) VALUES(?,?,?,?,?,?,1)", d)

    db.commit()

# ─── AUTH HELPERS ────────────────────────────────────────────────────────────

def generate_invite_code():
    """Generate a short, human-friendly invite code like 'M7K2A9'."""
    import random
    import string
    alphabet = string.ascii_uppercase + string.digits
    alphabet = alphabet.replace('0', '').replace('O', '').replace('1', '').replace('I', '')  # avoid confusion
    return ''.join(random.choices(alphabet, k=6))

def make_token(user_id, family_id):
    payload = {
        'sub': user_id,
        'fam': family_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Token kerak'}), 401
        token = auth[7:]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.user_id = data['sub']
            g.family_id = data['fam']
        except Exception:
            return jsonify({'error': 'Token yaroqsiz'}), 401
        # Determine if this account belongs to a minor (under 16) for guardian-mode restrictions
        db = get_db()
        user_row = db.execute("SELECT birth_date FROM users WHERE id=?", (g.user_id,)).fetchone()
        g.is_minor = False
        if user_row and user_row['birth_date']:
            try:
                age = datetime.date.today().year - int(user_row['birth_date'][:4])
                g.is_minor = age < 16
            except Exception:
                g.is_minor = False
        return f(*args, **kwargs)
    return decorated

def require_adult(f):
    """Blocks an endpoint entirely for accounts belonging to a minor (<16). Use after @require_auth."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if getattr(g, 'is_minor', False):
            return jsonify({'ok': False, 'error': 'Bu bolim faqat kattalar uchun', 'restricted': True}), 403
        return f(*args, **kwargs)
    return decorated

def ok(data=None, **kw):
    res = {'ok': True}
    if data is not None:
        res['data'] = data
    res.update(kw)
    return jsonify(res)

def err(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code

def row_to_dict(row):
    if row is None:
        return None
    return dict(row)

def rows_to_list(rows):
    return [dict(r) for r in rows]

# ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

@app.route('/api/auth/send-otp', methods=['POST'])
def send_otp():
    phone = (request.json or {}).get('phone', '').strip()
    if not re.match(r'^\+998\d{9}$', phone):
        return err("Telefon raqami noto'g'ri. Format: +998901234567")
    code = "123456"  # Demo: real proyektda SMS yuboriladi
    expires = (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).isoformat()
    db = get_db()
    db.execute("INSERT OR REPLACE INTO otp_codes VALUES (?,?,?)", (phone, code, expires))
    db.commit()
    return ok({'message': f'OTP {phone} ga yuborildi (demo: 123456)'})

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    body = request.json or {}
    phone = body.get('phone', '').strip()
    code  = body.get('code', '').strip()
    db = get_db()
    row = db.execute("SELECT * FROM otp_codes WHERE phone=?", (phone,)).fetchone()
    if not row or row['code'] != code:
        return err('OTP noto\'g\'ri')
    if row['expires_at'] < datetime.datetime.utcnow().isoformat():
        return err('OTP muddati tugagan')
    db.execute("DELETE FROM otp_codes WHERE phone=?", (phone,))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
    if user:
        token = make_token(user['id'], user['family_id'])
        return ok({'token': token, 'user': row_to_dict(user), 'is_new': False})
    return ok({'phone': phone, 'is_new': True})

@app.route('/api/auth/register', methods=['POST'])
def register():
    body = request.json or {}
    phone     = body.get('phone', '').strip()
    full_name = body.get('full_name', '').strip()
    password  = body.get('password', '').strip()
    birth_date= body.get('birth_date', '')
    gender    = body.get('gender', 'male')
    invite_code = body.get('invite_code', '').strip().upper()

    if not all([phone, full_name, password, birth_date]):
        return err("Telefon, ism, parol va tug'ilgan sana majburiy")

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE phone=?", (phone,)).fetchone()
    if existing:
        return err('Bu raqam allaqachon ro\'yxatdan o\'tgan')

    # Determine age-based role automatically — minors get a restricted 'child' member role
    try:
        age = datetime.date.today().year - int(birth_date[:4])
    except Exception:
        return err("Tug'ilgan sana noto'g'ri formatda")
    is_minor = age < 16
    member_role = 'child' if is_minor else 'parent'

    # Minors must join an existing family via invite code — they cannot start a new family
    if is_minor and not invite_code:
        return err("16 yoshdan kichik foydalanuvchilar faqat taklif kodi orqali oilaga qo'shilishi mumkin")

    user_id = str(uuid.uuid4())
    pw_hash = generate_password_hash(password)

    # If an invite code is provided, join that existing family instead of creating a new one
    fam_id = None
    if invite_code:
        fam_row = db.execute("SELECT id FROM families WHERE invite_code=?", (invite_code,)).fetchone()
        if not fam_row:
            return err("Taklif kodi topilmadi. Iltimos qaytadan tekshiring.")
        fam_id = fam_row['id']
    else:
        fam_id = str(uuid.uuid4())
        new_invite_code = generate_invite_code()
        db.execute("INSERT INTO families(id,name,created_by,invite_code) VALUES (?,?,?,?)",
                   (fam_id, f"{full_name} oilasi", user_id, new_invite_code))

    db.execute("""INSERT INTO users(id,phone,full_name,birth_date,gender,password_hash,family_id,role)
                  VALUES(?,?,?,?,?,?,?,?)""",
               (user_id, phone, full_name, birth_date, gender, pw_hash, fam_id,
                'minor' if is_minor else 'adult'))

    db.execute("""INSERT INTO family_members(id,family_id,user_id,name,birth_date,gender,role,avatar_color)
                  VALUES(?,?,?,?,?,?,?,?)""",
               (str(uuid.uuid4()), fam_id, user_id, full_name, birth_date, gender, member_role,
                '#C2185B' if gender == 'female' else '#1A78C2'))
    db.commit()

    token = make_token(user_id, fam_id)
    return ok({'token': token, 'user_id': user_id, 'family_id': fam_id, 'is_minor': is_minor},
               message="Muvaffaqiyatli ro'yxatdan o'tdingiz"), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    body = request.json or {}
    phone    = body.get('phone', '').strip()
    password = body.get('password', '').strip()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
    if not user or not verify_password(user['password_hash'], password):
        return err("Telefon yoki parol noto'g'ri", 401)
    try:
        age = datetime.date.today().year - int((user['birth_date'] or '2000')[:4])
        is_minor = age < 16
    except Exception:
        is_minor = False
    # Update role if not set correctly (migration safety)
    if is_minor and user['role'] != 'minor':
        db.execute("UPDATE users SET role='minor' WHERE id=?", (user['id'],))
        db.commit()
    token = make_token(user['id'], user['family_id'])
    return ok({'token': token, 'user': row_to_dict(user), 'is_minor': is_minor})

@app.route('/api/family/invite-code', methods=['GET'])
@require_auth
def get_invite_code():
    db = get_db()
    fam = db.execute("SELECT invite_code FROM families WHERE id=?", (g.family_id,)).fetchone()
    code = fam['invite_code'] if fam and fam['invite_code'] else None
    if not code:
        code = generate_invite_code()
        db.execute("UPDATE families SET invite_code=? WHERE id=?", (code, g.family_id))
        db.commit()
    return ok({'invite_code': code})

# ─── FAMILY ──────────────────────────────────────────────────────────────────

@app.route('/api/family', methods=['GET'])
@require_auth
def get_family():
    db = get_db()
    family  = db.execute("SELECT * FROM families WHERE id=?", (g.family_id,)).fetchone()
    members = db.execute(
        "SELECT * FROM family_members WHERE family_id=? AND status != 'removed' ORDER BY created_at ASC",
        (g.family_id,)).fetchall()
    me = db.execute("SELECT id, phone, full_name, birth_date, gender FROM users WHERE id=?", (g.user_id,)).fetchone()
    return ok({'family': row_to_dict(family), 'members': rows_to_list(members), 'me': row_to_dict(me)})

@app.route('/api/profile', methods=['PATCH'])
@require_auth
def update_profile():
    body = request.json or {}
    full_name = (body.get('full_name') or '').strip()
    phone     = (body.get('phone') or '').strip()
    birth_date= body.get('birth_date', '')
    gender    = body.get('gender', '')

    if not full_name:
        return err("Ism bo'sh bo'lmasligi kerak")
    if not re.match(r'^\+998\d{9}$', phone):
        return err("Telefon raqami noto'g'ri. Format: +998901234567")

    db = get_db()

    # If phone changed, make sure it's not taken by someone else
    existing = db.execute("SELECT id FROM users WHERE phone=? AND id!=?", (phone, g.user_id)).fetchone()
    if existing:
        return err("Bu telefon raqami boshqa hisobda band")

    db.execute(
        "UPDATE users SET full_name=?, phone=?, birth_date=?, gender=? WHERE id=?",
        (full_name, phone, birth_date, gender, g.user_id)
    )
    # Keep the corresponding family_members row in sync (name shown across the app)
    db.execute(
        "UPDATE family_members SET name=?, birth_date=?, gender=? WHERE user_id=? AND family_id=?",
        (full_name, birth_date, gender, g.user_id, g.family_id)
    )
    # If this user created the family, keep the family display name in sync too
    family = db.execute("SELECT created_by FROM families WHERE id=?", (g.family_id,)).fetchone()
    if family and family['created_by'] == g.user_id:
        new_family_name = f"{full_name} oilasi"
        db.execute("UPDATE families SET name=? WHERE id=?", (new_family_name, g.family_id))
    db.commit()

    user = db.execute("SELECT id, phone, full_name, birth_date, gender FROM users WHERE id=?", (g.user_id,)).fetchone()
    return ok(row_to_dict(user))

@app.route('/api/profile/password', methods=['PATCH'])
@require_auth
def change_password():
    body = request.json or {}
    current_pw = (body.get('current_password') or '').strip()
    new_pw     = (body.get('new_password') or '').strip()

    if not current_pw or not new_pw:
        return err('Joriy va yangi parol majburiy')
    if len(new_pw) < 6:
        return err("Yangi parol kamida 6 belgidan iborat bo'lishi kerak")

    db = get_db()
    user = db.execute("SELECT password_hash FROM users WHERE id=?", (g.user_id,)).fetchone()
    if not user or not verify_password(user['password_hash'], current_pw):
        return err("Joriy parol noto'g'ri")

    new_hash = generate_password_hash(new_pw)
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, g.user_id))
    db.commit()
    return ok({'message': "Parol muvaffaqiyatli o'zgartirildi"})

@app.route('/api/family/members', methods=['POST'])
@require_auth
def add_member():
    body = request.json or {}
    required = ['name', 'birth_date', 'gender', 'role']
    if not all(body.get(k) for k in required):
        return err('name, birth_date, gender, role majburiy')
    colors = {'male': '#1A78C2', 'female': '#C2185B'}
    color = colors.get(body['gender'], '#2D7A4F')
    mid = str(uuid.uuid4())
    db = get_db()
    db.execute("""INSERT INTO family_members(id,family_id,user_id,name,birth_date,gender,role,avatar_color)
                  VALUES(?,?,NULL,?,?,?,?,?)""",
               (mid, g.family_id, body['name'], body['birth_date'], body['gender'], body['role'], color))
    db.commit()
    member = db.execute("SELECT * FROM family_members WHERE id=?", (mid,)).fetchone()
    return ok(row_to_dict(member)), 201

MAX_AVATAR_BYTES = 1_500_000  # ~1.1MB after base64 overhead, plenty for a small square photo

@app.route('/api/family/members/<member_id>/avatar', methods=['PATCH'])
@require_auth
def update_member_avatar(member_id):
    body = request.json or {}
    avatar_url = body.get('avatar_url')
    if not avatar_url:
        return err("Rasm topilmadi")
    if len(avatar_url) > MAX_AVATAR_BYTES:
        return err("Rasm hajmi juda katta")
    db = get_db()
    member = db.execute(
        "SELECT id FROM family_members WHERE id=? AND family_id=?", (member_id, g.family_id)
    ).fetchone()
    if not member:
        return err("A'zo topilmadi", 404)
    db.execute("UPDATE family_members SET avatar_url=? WHERE id=?", (avatar_url, member_id))
    db.commit()
    row = db.execute("SELECT * FROM family_members WHERE id=?", (member_id,)).fetchone()
    return ok(row_to_dict(row))

@app.route('/api/family/members/<member_id>/remove', methods=['PATCH'])
@require_auth
def remove_member(member_id):
    """Remove a member from active family (they won't appear in lists but tree preserves them)."""
    db = get_db()
    member = db.execute(
        "SELECT id, user_id FROM family_members WHERE id=? AND family_id=?",
        (member_id, g.family_id)).fetchone()
    if not member:
        return err("A'zo topilmadi", 404)
    db.execute("UPDATE family_members SET status='removed' WHERE id=?", (member_id,))
    db.commit()
    return ok({'message': "A'zo oiladan chiqarildi"})

@app.route('/api/family/members/<member_id>/deceased', methods=['PATCH'])
@require_auth
def mark_deceased(member_id):
    """Mark member as deceased — shown in family tree with special styling but not in active lists."""
    body = request.json or {}
    db = get_db()
    member = db.execute(
        "SELECT id FROM family_members WHERE id=? AND family_id=?",
        (member_id, g.family_id)).fetchone()
    if not member:
        return err("A'zo topilmadi", 404)
    db.execute("UPDATE family_members SET status='deceased' WHERE id=?", (member_id,))
    db.commit()
    return ok({'message': "Xotirada saqlanadi"})



@app.route('/api/health/vaccines', methods=['GET'])
@require_auth
def get_vaccines():
    member_id = request.args.get('member_id')
    db = get_db()
    if member_id:
        rows = db.execute("SELECT * FROM vaccines WHERE family_id=? AND member_id=? ORDER BY scheduled_date",
                          (g.family_id, member_id)).fetchall()
    else:
        rows = db.execute("SELECT v.*, m.name as member_name FROM vaccines v JOIN family_members m ON v.member_id=m.id WHERE v.family_id=? ORDER BY v.scheduled_date",
                          (g.family_id,)).fetchall()
    # Auto-mark overdue
    today = datetime.date.today().isoformat()
    result = []
    for r in rows:
        d = dict(r)
        if d['status'] == 'scheduled' and d['scheduled_date'] < today:
            d['status'] = 'overdue'
        result.append(d)
    return ok(result)

@app.route('/api/health/vaccines', methods=['POST'])
@require_auth
def add_vaccine():
    body = request.json or {}
    required = ['member_id', 'name', 'scheduled_date']
    if not all(body.get(k) for k in required):
        return err('member_id, name, scheduled_date majburiy')
    vid = str(uuid.uuid4())
    db = get_db()
    db.execute("""INSERT INTO vaccines(id,family_id,member_id,name,dose_number,scheduled_date,status,location,notes)
                  VALUES(?,?,?,?,?,?,'scheduled',?,?)""",
               (vid, g.family_id, body['member_id'], body['name'],
                body.get('dose_number', 1), body['scheduled_date'],
                body.get('location'), body.get('notes')))
    db.commit()
    row = db.execute("SELECT * FROM vaccines WHERE id=?", (vid,)).fetchone()
    return ok(row_to_dict(row)), 201

@app.route('/api/health/vaccines/<vid>/complete', methods=['PATCH'])
@require_auth
def complete_vaccine(vid):
    today = datetime.date.today().isoformat()
    db = get_db()
    db.execute("UPDATE vaccines SET status='done', done_date=? WHERE id=? AND family_id=?",
               (today, vid, g.family_id))
    db.commit()
    return ok({'message': 'Emlash bajarildi deb belgilandi'})

@app.route('/api/health/records', methods=['GET'])
@require_auth
def get_health_records():
    member_id = request.args.get('member_id')
    db = get_db()
    if member_id:
        rows = db.execute("SELECT * FROM health_records WHERE family_id=? AND member_id=? ORDER BY date DESC",
                          (g.family_id, member_id)).fetchall()
    else:
        rows = db.execute("SELECT * FROM health_records WHERE family_id=? ORDER BY date DESC",
                          (g.family_id,)).fetchall()
    return ok(rows_to_list(rows))

@app.route('/api/health/records', methods=['POST'])
@require_auth
def add_health_record():
    body = request.json or {}
    required = ['member_id', 'record_type', 'title', 'date']
    if not all(body.get(k) for k in required):
        return err('member_id, record_type, title, date majburiy')
    rid = str(uuid.uuid4())
    db = get_db()
    db.execute("""INSERT INTO health_records(id,family_id,member_id,record_type,title,value,unit,date,notes,status)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""",
               (rid, g.family_id, body['member_id'], body['record_type'], body['title'],
                body.get('value'), body.get('unit'), body['date'],
                body.get('notes'), body.get('status','normal')))
    db.commit()
    row = db.execute("SELECT * FROM health_records WHERE id=?", (rid,)).fetchone()
    return ok(row_to_dict(row)), 201

# ─── ALBUMS ──────────────────────────────────────────────────────────────────

@app.route('/api/albums', methods=['GET'])
@require_auth
def get_albums():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM albums WHERE family_id=? ORDER BY created_at DESC", (g.family_id,)
    ).fetchall()
    albums = rows_to_list(rows)
    for a in albums:
        cnt = db.execute(
            "SELECT COUNT(*) as cnt FROM memories WHERE family_id=? AND album_id=?",
            (g.family_id, a['id'])
        ).fetchone()['cnt']
        a['memory_count'] = cnt
    return ok(albums)

@app.route('/api/albums', methods=['POST'])
@require_auth
def create_album():
    body = request.json or {}
    name = (body.get('name') or '').strip()
    if not name:
        return err("Albom nomi bo'sh bo'lmasligi kerak")
    aid = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT INTO albums(id,family_id,creator_id,name,emoji,color) VALUES(?,?,?,?,?,?)",
        (aid, g.family_id, g.user_id, name, body.get('emoji', '📁'), body.get('color', '#DBEAFE'))
    )
    db.commit()
    row = db.execute("SELECT * FROM albums WHERE id=?", (aid,)).fetchone()
    d = row_to_dict(row)
    d['memory_count'] = 0
    return ok(d), 201

@app.route('/api/albums/<aid>', methods=['DELETE'])
@require_auth
def delete_album(aid):
    db = get_db()
    # Memories in this album become un-albumed, not deleted
    db.execute("UPDATE memories SET album_id=NULL WHERE album_id=? AND family_id=?", (aid, g.family_id))
    db.execute("DELETE FROM albums WHERE id=? AND family_id=?", (aid, g.family_id))
    db.commit()
    return ok({'message': "O'chirildi"})

# ─── MEMORIES ────────────────────────────────────────────────────────────────

MAX_MEDIA_BYTES = {
    'photo': 2_000_000,   # ~1.5MB after base64 overhead
    'video': 8_000_000,   # ~6MB after base64 overhead — short clips only
    'audio': 4_000_000,   # ~3MB after base64 overhead
}

@app.route('/api/memories', methods=['GET'])
@require_auth
def get_memories():
    year     = request.args.get('year')
    album_id = request.args.get('album_id')
    limit    = int(request.args.get('limit', 50))
    db = get_db()
    query = "SELECT * FROM memories WHERE family_id=?"
    params = [g.family_id]
    if year:
        query += " AND strftime('%Y',taken_at)=?"
        params.append(year)
    if album_id:
        query += " AND album_id=?"
        params.append(album_id)
    query += " ORDER BY taken_at DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d['tags'] = json.loads(d.get('tags') or '[]')
        except Exception:
            d['tags'] = []
        result.append(d)
    return ok(result)

@app.route('/api/memories', methods=['POST'])
@require_auth
def add_memory():
    body = request.json or {}
    required = ['taken_at']
    if not all(body.get(k) for k in required):
        return err('taken_at majburiy')
    media_type = body.get('media_type', 'photo')
    media_url = body.get('media_url')
    max_bytes = MAX_MEDIA_BYTES.get(media_type, 2_000_000)
    if media_url and len(media_url) > max_bytes:
        kind_label = {'photo': 'Rasm', 'video': 'Video', 'audio': 'Audio'}.get(media_type, 'Fayl')
        return err(f"{kind_label} hajmi juda katta. Iltimos, qisqaroq/kichikroq fayl tanlang")
    mid = str(uuid.uuid4())
    tags = json.dumps(body.get('tags', []))
    db = get_db()
    db.execute("""INSERT INTO memories(id,family_id,uploader_id,album_id,title,description,media_type,media_url,emoji,color,taken_at,location,tags)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (mid, g.family_id, g.user_id, body.get('album_id'),
                body.get('title'), body.get('description'),
                media_type, media_url,
                body.get('emoji','📷'), body.get('color','#DBEAFE'),
                body['taken_at'], body.get('location'), tags))
    db.commit()
    row = db.execute("SELECT * FROM memories WHERE id=?", (mid,)).fetchone()
    d = dict(row)
    try: d['tags'] = json.loads(d.get('tags') or '[]')
    except: d['tags'] = []
    return ok(d), 201

@app.route('/api/memories/<mid>', methods=['DELETE'])
@require_auth
def delete_memory(mid):
    db = get_db()
    db.execute("DELETE FROM memories WHERE id=? AND family_id=?", (mid, g.family_id))
    db.commit()
    return ok({'message': 'O\'chirildi'})

# ─── TIME CAPSULES ───────────────────────────────────────────────────────────

@app.route('/api/capsules', methods=['GET'])
@require_auth
def get_capsules():
    db = get_db()
    today = datetime.date.today().isoformat()
    rows = db.execute("SELECT * FROM time_capsules WHERE family_id=? ORDER BY open_date",
                      (g.family_id,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d['can_open'] = d['open_date'] <= today and not d['is_opened']
        if d['is_opened'] or d['open_date'] > today:
            d['message'] = None  # hide until open date
        result.append(d)
    return ok(result)

@app.route('/api/capsules', methods=['POST'])
@require_auth
def create_capsule():
    body = request.json or {}
    required = ['title', 'message', 'recipient', 'open_date']
    if not all(body.get(k) for k in required):
        return err('title, message, recipient, open_date majburiy')
    cid = str(uuid.uuid4())
    db = get_db()
    db.execute("INSERT INTO time_capsules(id,family_id,creator_id,title,message,recipient,open_date) VALUES(?,?,?,?,?,?,?)",
               (cid, g.family_id, g.user_id, body['title'], body['message'],
                body['recipient'], body['open_date']))
    db.commit()
    row = db.execute("SELECT * FROM time_capsules WHERE id=?", (cid,)).fetchone()
    return ok(row_to_dict(row)), 201

@app.route('/api/capsules/<cid>/open', methods=['PATCH'])
@require_auth
def open_capsule(cid):
    db = get_db()
    today = datetime.date.today().isoformat()
    row = db.execute("SELECT * FROM time_capsules WHERE id=? AND family_id=?",
                     (cid, g.family_id)).fetchone()
    if not row:
        return err('Topilmadi', 404)
    if row['open_date'] > today:
        return err(f"Bu kapsula {row['open_date']} da ochiladi")
    db.execute("UPDATE time_capsules SET is_opened=1 WHERE id=?", (cid,))
    db.commit()
    return ok(row_to_dict(db.execute("SELECT * FROM time_capsules WHERE id=?", (cid,)).fetchone()))

# ─── WARMTH ──────────────────────────────────────────────────────────────────

@app.route('/api/warmth', methods=['GET'])
@require_auth
@require_adult
def get_warmth():
    db = get_db()
    rows = db.execute("""
        SELECT * FROM warmth_logs
        WHERE family_id=? ORDER BY log_date DESC LIMIT 30
    """, (g.family_id,)).fetchall()
    avg7 = db.execute("""
        SELECT AVG(avg_score) as avg FROM warmth_logs
        WHERE family_id=? AND log_date >= date('now','-7 days')
    """, (g.family_id,)).fetchone()
    streak = db.execute("""
        SELECT COUNT(*) as cnt FROM warmth_logs
        WHERE family_id=? AND log_date >= date('now','-30 days')
    """, (g.family_id,)).fetchone()
    return ok({
        'logs': rows_to_list(rows),
        'avg_7_days': round(avg7['avg'] or 0, 1),
        'streak_days': streak['cnt']
    })

@app.route('/api/warmth', methods=['POST'])
@require_auth
@require_adult
def log_warmth():
    body = request.json or {}
    happiness = body.get('happiness')
    supported = body.get('supported')
    if happiness is None or supported is None:
        return err('happiness va supported majburiy (1-5)')
    if not (1 <= int(happiness) <= 5 and 1 <= int(supported) <= 5):
        return err('Qiymatlar 1-5 oralig\'ida bo\'lishi kerak')
    today = datetime.date.today().isoformat()
    avg = (int(happiness) + int(supported)) / 2
    db = get_db()
    existing = db.execute("SELECT id FROM warmth_logs WHERE family_id=? AND user_id=? AND log_date=?",
                          (g.family_id, g.user_id, today)).fetchone()
    if existing:
        db.execute("UPDATE warmth_logs SET happiness=?, supported=?, avg_score=? WHERE id=?",
                   (happiness, supported, avg, existing['id']))
    else:
        db.execute("INSERT INTO warmth_logs(id,family_id,user_id,happiness,supported,avg_score,log_date) VALUES(?,?,?,?,?,?,?)",
                   (str(uuid.uuid4()), g.family_id, g.user_id, happiness, supported, avg, today))
    db.commit()
    warning = None
    if avg < 3:
        low_count = db.execute("""
            SELECT COUNT(*) as cnt FROM warmth_logs
            WHERE family_id=? AND avg_score < 3 AND log_date >= date('now','-14 days')
        """, (g.family_id,)).fetchone()['cnt']
        if low_count >= 5:
            warning = "So'nggi 2 hafta davomida ball past. Oila psixologi bilan 30 daqiqalik bepul maslahat olishni tavsiya qilamiz."
    return ok({'avg': avg, 'warning': warning})

# ─── ALERTS ──────────────────────────────────────────────────────────────────

@app.route('/api/alerts', methods=['GET'])
@require_auth
def get_alerts():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM alerts WHERE family_id=? ORDER BY created_at DESC LIMIT 50",
        (g.family_id,)).fetchall()
    unread = db.execute(
        "SELECT COUNT(*) as cnt FROM alerts WHERE family_id=? AND is_read=0",
        (g.family_id,)).fetchone()['cnt']
    return ok({'alerts': rows_to_list(rows), 'unread': unread})

@app.route('/api/alerts', methods=['POST'])
@require_auth
def create_alert():
    body = request.json or {}
    title = (body.get('title') or '').strip()
    alert_body = (body.get('body') or '').strip()
    reminder_date = body.get('reminder_date', '')
    if not title:
        return err("Sarlavha bo'sh bo'lmasligi kerak")
    aid = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT INTO alerts(id,family_id,creator_id,type,title,body,reminder_date,severity) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (aid, g.family_id, g.user_id, 'manual', title, alert_body, reminder_date, body.get('severity', 'info'))
    )
    db.commit()
    row = db.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    return ok(row_to_dict(row)), 201

@app.route('/api/alerts/<aid>', methods=['DELETE'])
@require_auth
def delete_alert(aid):
    db = get_db()
    db.execute("DELETE FROM alerts WHERE id=? AND family_id=?", (aid, g.family_id))
    db.commit()
    return ok({'message': "O'chirildi"})

@app.route('/api/alerts/<aid>/read', methods=['PATCH'])
@require_auth
def mark_read(aid):
    db = get_db()
    db.execute("UPDATE alerts SET is_read=1 WHERE id=? AND family_id=?", (aid, g.family_id))
    db.commit()
    return ok({'message': 'O\'qildi'})

# ─── DASHBOARD ───────────────────────────────────────────────────────────────

@app.route('/api/dashboard', methods=['GET'])
@require_auth
def get_dashboard():
    db = get_db()
    today = datetime.date.today().isoformat()

    family  = row_to_dict(db.execute("SELECT * FROM families WHERE id=?", (g.family_id,)).fetchone())
    members = rows_to_list(db.execute("SELECT * FROM family_members WHERE family_id=?", (g.family_id,)).fetchall())

    today_vaccines = rows_to_list(db.execute(
        "SELECT v.*, m.name as member_name FROM vaccines v JOIN family_members m ON v.member_id=m.id "
        "WHERE v.family_id=? AND v.scheduled_date=? AND v.status='scheduled'",
        (g.family_id, today)).fetchall())

    overdue_vaccines = db.execute(
        "SELECT COUNT(*) as cnt FROM vaccines WHERE family_id=? AND status='overdue'",
        (g.family_id,)).fetchone()['cnt']

    recent_memories = rows_to_list(db.execute(
        "SELECT * FROM memories WHERE family_id=? ORDER BY taken_at DESC LIMIT 3",
        (g.family_id,)).fetchall())

    warmth = db.execute(
        "SELECT AVG(avg_score) as avg FROM warmth_logs WHERE family_id=? AND log_date >= date('now','-7 days')",
        (g.family_id,)).fetchone()

    unread_alerts = db.execute(
        "SELECT COUNT(*) as cnt FROM alerts WHERE family_id=? AND is_read=0",
        (g.family_id,)).fetchone()['cnt']

    memory_count = db.execute(
        "SELECT COUNT(*) as cnt FROM memories WHERE family_id=?",
        (g.family_id,)).fetchone()['cnt']

    today_logged = db.execute(
        "SELECT id FROM warmth_logs WHERE family_id=? AND user_id=? AND log_date=?",
        (g.family_id, g.user_id, today)).fetchone()

    return ok({
        'family': family,
        'members': members,
        'today_vaccines': today_vaccines,
        'overdue_vaccines': overdue_vaccines,
        'recent_memories': recent_memories,
        'warmth_avg_7days': round(warmth['avg'] or 0, 1),
        'unread_alerts': unread_alerts,
        'memory_count': memory_count,
        'warmth_logged_today': bool(today_logged)
    })

# ─── COMPATIBILITY TEST ─────────────────────────────────────────────────────

COMPAT_QUESTIONS = {
    'uz': {
        'values': [
            {'id': 'v1', 'text': 'Diniy va milliy qadriyatlar oilada qanchalik muhim?'},
            {'id': 'v2', 'text': "Farzandlarni qaysi til(lar)da tarbiyalashni xohlaysiz?"},
            {'id': 'v3', 'text': "Kattalarga (ota-ona, qarindosh) hurmat va g'amxorlik darajasi qanday bo'lishi kerak?"},
        ],
        'expectations': [
            {'id': 'e1', 'text': 'Turmush boshlanganidan keyin qayerda yashashni xohlaysiz?'},
            {'id': 'e2', 'text': "Ikkalangiz ham ishlashni davom ettirasizmi, yoki biringiz uyda qoladimi?"},
            {'id': 'e3', 'text': "Bo'sh vaqtni qanday o'tkazishni afzal ko'rasiz — birga sayohat, uyda, do'stlar bilanmi?"},
        ],
        'communication': [
            {'id': 'c1', 'text': 'Janjal chiqsa, qanday yondashasiz — darrov gaplashish kerakmi, yoki vaqt kerakmi?'},
            {'id': 'c2', 'text': 'Moliyaviy masalalarni qanchalik ochiq muhokama qilish kerak?'},
            {'id': 'c3', 'text': "Bir-biringizga his-tuyg'ularni qanday bildirasiz?"},
        ],
        'parenting': [
            {'id': 'p1', 'text': 'Bola tarbiyasida qattiqqo\'llik va erkinlik nisbati qanday bo\'lishi kerak?'},
            {'id': 'p2', 'text': "Nechta farzand ko'rishni xohlaysiz?"},
            {'id': 'p3', 'text': "Bolaning ta'limi (xususiy/davlat maktab) qanday bo'lishi kerak?"},
        ],
        'finance': [
            {'id': 'f1', 'text': "Oilaviy byudjetni kim boshqarishi kerak — birgalikda, yoki biri?"},
            {'id': 'f2', 'text': "Jamg'arma va katta xaridlar uchun qanday yondashuv kerak?"},
            {'id': 'f3', 'text': "Qarindoshlarga moliyaviy yordam berish masalasida fikringiz qanday?"},
        ],
    },
    'ru': {
        'values': [
            {'id': 'v1', 'text': 'Насколько важны религиозные и национальные ценности в семье?'},
            {'id': 'v2', 'text': 'На каком языке(ах) вы хотите воспитывать детей?'},
            {'id': 'v3', 'text': 'Каким должен быть уровень уважения и заботы о старших (родителях, родственниках)?'},
        ],
        'expectations': [
            {'id': 'e1', 'text': 'Где вы хотите жить после начала семейной жизни?'},
            {'id': 'e2', 'text': 'Будете ли вы оба работать, или один из вас останется дома?'},
            {'id': 'e3', 'text': 'Как вы предпочитаете проводить свободное время — путешествия вместе, дома, с друзьями?'},
        ],
        'communication': [
            {'id': 'c1', 'text': 'Как вы подходите к конфликтам — нужно сразу говорить или нужно время?'},
            {'id': 'c2', 'text': 'Насколько открыто нужно обсуждать финансовые вопросы?'},
            {'id': 'c3', 'text': 'Как вы выражаете чувства друг другу?'},
        ],
        'parenting': [
            {'id': 'p1', 'text': 'Каким должно быть соотношение строгости и свободы в воспитании детей?'},
            {'id': 'p2', 'text': 'Сколько детей вы хотите иметь?'},
            {'id': 'p3', 'text': 'Каким должно быть образование ребёнка (частная/государственная школа)?'},
        ],
        'finance': [
            {'id': 'f1', 'text': 'Кто должен управлять семейным бюджетом — вместе или один из вас?'},
            {'id': 'f2', 'text': 'Какой подход нужен к накоплениям и крупным покупкам?'},
            {'id': 'f3', 'text': 'Как вы относитесь к финансовой помощи родственникам?'},
        ],
    },
    'en': {
        'values': [
            {'id': 'v1', 'text': 'How important are religious and national values in the family?'},
            {'id': 'v2', 'text': 'In which language(s) do you want to raise your children?'},
            {'id': 'v3', 'text': 'What level of respect and care for elders (parents, relatives) should there be?'},
        ],
        'expectations': [
            {'id': 'e1', 'text': 'Where do you want to live after starting family life?'},
            {'id': 'e2', 'text': 'Will you both continue working, or will one of you stay home?'},
            {'id': 'e3', 'text': 'How do you prefer to spend free time — traveling together, at home, with friends?'},
        ],
        'communication': [
            {'id': 'c1', 'text': 'How do you approach conflict — talk right away, or need time first?'},
            {'id': 'c2', 'text': 'How openly should financial matters be discussed?'},
            {'id': 'c3', 'text': 'How do you express feelings to each other?'},
        ],
        'parenting': [
            {'id': 'p1', 'text': 'What balance of strictness and freedom should there be in raising children?'},
            {'id': 'p2', 'text': 'How many children do you want to have?'},
            {'id': 'p3', 'text': "What should the child's education look like (private/public school)?"},
        ],
        'finance': [
            {'id': 'f1', 'text': 'Who should manage the family budget — together, or one of you?'},
            {'id': 'f2', 'text': 'What approach is needed for savings and big purchases?'},
            {'id': 'f3', 'text': 'How do you feel about giving financial help to relatives?'},
        ],
    },
}

BLOCK_LABELS = {
    'uz': {'values':'Qadriyatlar','expectations':'Kutilishlar','communication':'Muloqot uslubi','parenting':'Bola tarbiyasi','finance':'Moliyaviy munosabat'},
    'ru': {'values':'Ценности','expectations':'Ожидания','communication':'Стиль общения','parenting':'Воспитание детей','finance':'Финансовые отношения'},
    'en': {'values':'Values','expectations':'Expectations','communication':'Communication style','parenting':'Parenting','finance':'Financial approach'},
}

# --- FAMILY ASSESSMENT QUESTION BANK ---
ASSESSMENT_QUESTIONS = {
    'uz': {
        'communication': [
            {'id': 'co1', 'text': "Fikringizni oila a'zolaringizga ochiq aytasizmi, yoki ko'pincha ichingizda saqlaysizmi?"},
            {'id': 'co2', 'text': "Muhim mavzularni muhokama qilish uchun yetarli vaqt topa olasizmi?"},
            {'id': 'co3', 'text': "Suhbat paytida bir-biringizni tinglaysizmi, yoki ko'proq gapirasizmi?"},
        ],
        'conflict': [
            {'id': 'cf1', 'text': "Nizo chiqqanda, muammoni hal qilishga harakat qilasizmi, yoki tortishuv uzoq davom etadimi?"},
            {'id': 'cf2', 'text': "Kelishmovchilikdan keyin yarashish qanchalik tez sodir bo'ladi?"},
            {'id': 'cf3', 'text': "Nizo paytida ovozingizni ko'tarasizmi, yoki bosiqlikni saqlaysizmi?"},
        ],
        'connection': [
            {'id': 'cn1', 'text': "Oila bilan birga o'tkazadigan sifatli vaqtingiz yetarlimi?"},
            {'id': 'cn2', 'text': "Bir-biringizga qadrlanayotganingizni his qildirasizmi?"},
            {'id': 'cn3', 'text': "Kunlik hayotda bir-biringiz bilan qanchalik yaqinsiz?"},
        ],
        'parenting': [
            {'id': 'pr1', 'text': "Bola tarbiyasi bo'yicha qarorlarni birgalikda qabul qilasizmi?"},
            {'id': 'pr2', 'text': "Farzandingiz bilan kuniga qancha sifatli vaqt o'tkazasiz?"},
            {'id': 'pr3', 'text': "Tarbiya usullari borasida farzandingiz oldida kelishmovchilik ko'rsatasizmi?"},
        ],
        'finance': [
            {'id': 'fn1', 'text': "Oilaviy xarajatlar rejasi bormi va unga amal qilinadimi?"},
            {'id': 'fn2', 'text': "Moliyaviy qarorlarni birgalikda muhokama qilasizmi?"},
            {'id': 'fn3', 'text': "Kutilmagan xarajatlar uchun jamg'arma bormi?"},
        ],
    },
    'ru': {
        'communication': [
            {'id': 'co1', 'text': 'Открыто ли вы делитесь мнением с членами семьи, или чаще держите в себе?'},
            {'id': 'co2', 'text': 'Хватает ли времени на обсуждение важных тем?'},
            {'id': 'co3', 'text': 'Слушаете ли вы друг друга во время разговора, или больше говорите сами?'},
        ],
        'conflict': [
            {'id': 'cf1', 'text': 'Когда возникает спор, пытаетесь ли вы решить проблему, или спор затягивается надолго?'},
            {'id': 'cf2', 'text': 'Как быстро происходит примирение после разногласия?'},
            {'id': 'cf3', 'text': 'Повышаете ли вы голос во время конфликта, или сохраняете спокойствие?'},
        ],
        'connection': [
            {'id': 'cn1', 'text': 'Достаточно ли качественного времени вы проводите с семьёй?'},
            {'id': 'cn2', 'text': 'Чувствуете ли вы, что цените друг друга?'},
            {'id': 'cn3', 'text': 'Насколько вы близки друг с другом в повседневной жизни?'},
        ],
        'parenting': [
            {'id': 'pr1', 'text': 'Принимаете ли вы решения о воспитании детей совместно?'},
            {'id': 'pr2', 'text': 'Сколько качественного времени в день вы проводите с ребёнком?'},
            {'id': 'pr3', 'text': 'Бывают ли разногласия по методам воспитания при ребёнке?'},
        ],
        'finance': [
            {'id': 'fn1', 'text': 'Есть ли план семейных расходов и соблюдается ли он?'},
            {'id': 'fn2', 'text': 'Обсуждаете ли вы финансовые решения совместно?'},
            {'id': 'fn3', 'text': 'Есть ли накопления на непредвиденные расходы?'},
        ],
    },
    'en': {
        'communication': [
            {'id': 'co1', 'text': 'Do you share your thoughts openly with family, or keep them to yourself?'},
            {'id': 'co2', 'text': 'Do you find enough time to discuss important topics?'},
            {'id': 'co3', 'text': 'Do you listen to each other during conversations, or mostly talk?'},
        ],
        'conflict': [
            {'id': 'cf1', 'text': 'When a conflict arises, do you try to resolve it, or does the argument drag on?'},
            {'id': 'cf2', 'text': 'How quickly do you reconcile after a disagreement?'},
            {'id': 'cf3', 'text': 'Do you raise your voice during conflict, or stay calm?'},
        ],
        'connection': [
            {'id': 'cn1', 'text': 'Do you get enough quality time together as a family?'},
            {'id': 'cn2', 'text': 'Do you feel appreciated by each other?'},
            {'id': 'cn3', 'text': 'How close do you feel to each other in daily life?'},
        ],
        'parenting': [
            {'id': 'pr1', 'text': 'Do you make parenting decisions together?'},
            {'id': 'pr2', 'text': 'How much quality time do you spend with your child daily?'},
            {'id': 'pr3', 'text': 'Do you disagree on parenting methods in front of your child?'},
        ],
        'finance': [
            {'id': 'fn1', 'text': 'Do you have a family spending plan, and do you follow it?'},
            {'id': 'fn2', 'text': 'Do you discuss financial decisions together?'},
            {'id': 'fn3', 'text': 'Do you have savings for unexpected expenses?'},
        ],
    },
}

ASSESSMENT_LABELS = {
    'uz': {'communication': 'Muloqot', 'conflict': 'Nizo boshqaruvi', 'connection': "Yaqinlik/bog'lanish", 'parenting': 'Bola tarbiyasi', 'finance': 'Moliya'},
    'ru': {'communication': 'Общение', 'conflict': 'Управление конфликтом', 'connection': 'Близость/связь', 'parenting': 'Воспитание детей', 'finance': 'Финансы'},
    'en': {'communication': 'Communication', 'conflict': 'Conflict handling', 'connection': 'Connection', 'parenting': 'Parenting', 'finance': 'Finance'},
}

# --- DAILY 10: kunlik 10 daqiqalik oila/juftlik rasmi (savol + kichik vazifa) ---
DAILY10_QUESTIONS = {
    'uz': [
        {'id': 'dq1', 'text': 'Bugun nimani qadrladingiz?'},
        {'id': 'dq2', 'text': 'Bugun sherigingizga qanday yordam berdingiz?'},
        {'id': 'dq3', 'text': 'Bugun oilangizda eng yaxshi lahza qaysi edi?'},
        {'id': 'dq4', 'text': 'Bugun kimdir sizni kuldirdimi?'},
        {'id': 'dq5', 'text': 'Bugun nimadan minnatdorsiz?'},
        {'id': 'dq6', 'text': 'Bugun sherigingiz bilan qanday suhbatlashdingiz?'},
        {'id': 'dq7', 'text': "Bugun farzandingiz bilan qanday vaqt o'tkazdingiz?"},
        {'id': 'dq8', 'text': "Bugun o'zingizni qanday his qildingiz?"},
        {'id': 'dq9', 'text': 'Bugun oilangiz uchun nima qilishga ulgurmadingiz?'},
        {'id': 'dq10', 'text': 'Bugun kimga rahmat aytishni xohlaysiz?'},
        {'id': 'dq11', 'text': 'Bugun eng katta qiyinchilik nima edi?'},
        {'id': 'dq12', 'text': "Bugun o'zingiz haqingizda nimani angladingiz?"},
        {'id': 'dq13', 'text': 'Bugun oilangiz bilan qanday reja tuzdingiz?'},
        {'id': 'dq14', 'text': 'Bugun eng yaxshi qaror qanday edi?'},
    ],
    'ru': [
        {'id': 'dq1', 'text': 'Что вы сегодня оценили?'},
        {'id': 'dq2', 'text': 'Как вы сегодня помогли партнёру?'},
        {'id': 'dq3', 'text': 'Какой момент сегодня был лучшим в семье?'},
        {'id': 'dq4', 'text': 'Кто-то сегодня рассмешил вас?'},
        {'id': 'dq5', 'text': 'За что вы сегодня благодарны?'},
        {'id': 'dq6', 'text': 'О чём вы говорили с партнёром сегодня?'},
        {'id': 'dq7', 'text': 'Как вы провели время с ребёнком сегодня?'},
        {'id': 'dq8', 'text': 'Как вы себя сегодня чувствовали?'},
        {'id': 'dq9', 'text': 'Что вы не успели сделать для семьи сегодня?'},
        {'id': 'dq10', 'text': 'Кого вы хотите сегодня поблагодарить?'},
        {'id': 'dq11', 'text': 'Какая была самая большая трудность сегодня?'},
        {'id': 'dq12', 'text': 'Что вы поняли о себе сегодня?'},
        {'id': 'dq13', 'text': 'Какие планы вы построили с семьёй сегодня?'},
        {'id': 'dq14', 'text': 'Каким было лучшее решение сегодня?'},
    ],
    'en': [
        {'id': 'dq1', 'text': 'What did you appreciate today?'},
        {'id': 'dq2', 'text': 'How did you help your partner today?'},
        {'id': 'dq3', 'text': 'What was the best family moment today?'},
        {'id': 'dq4', 'text': 'Did someone make you laugh today?'},
        {'id': 'dq5', 'text': 'What are you grateful for today?'},
        {'id': 'dq6', 'text': 'What did you talk about with your partner today?'},
        {'id': 'dq7', 'text': 'How did you spend time with your child today?'},
        {'id': 'dq8', 'text': 'How did you feel today?'},
        {'id': 'dq9', "text": "What didn't you get to do for your family today?"},
        {'id': 'dq10', 'text': 'Who do you want to thank today?'},
        {'id': 'dq11', 'text': 'What was the biggest challenge today?'},
        {'id': 'dq12', 'text': 'What did you learn about yourself today?'},
        {'id': 'dq13', 'text': 'What plans did you make with your family today?'},
        {'id': 'dq14', 'text': 'What was the best decision today?'},
    ],
}

DAILY10_TASKS = {
    'uz': [
        {'id': 'dt1', 'text': 'Sherigingizga bitta chin dildan iltifot ayting'},
        {'id': 'dt2', 'text': "Farzandingiz bilan 10 daqiqa telefon qo'ymasdan gaplashing"},
        {'id': 'dt3', 'text': 'Bugun kechqurun ovqatni birga tayyorlang'},
        {'id': 'dt4', 'text': 'Sherigingizga "Rahmat" deb ayting — sababini aytib'},
        {'id': 'dt5', 'text': 'Bugun bir marta quchoqlashib qo\'ying'},
        {'id': 'dt6', 'text': 'Oila a\'zolaringizdan biriga qadimgi xotirani eslating'},
        {'id': 'dt7', 'text': "Bugun telefonlarni yig'ib, 15 daqiqa faqat gaplashing"},
        {'id': 'dt8', 'text': "Sherigingizga kichik sovg'a tayyorlang (kartochka bo'lsa ham)"},
        {'id': 'dt9', 'text': 'Farzandingizga bugun nimani yaxshi qilganini ayting'},
        {'id': 'dt10', 'text': 'Bugun kimgadir yordam bering, hech narsa kutmasdan'},
        {'id': 'dt11', 'text': 'Sherigingiz bilan birga sayr qiling (hatto 10 daqiqa)'},
        {'id': 'dt12', 'text': 'Bugun kechqurun ekransiz vaqt o\'tkazing'},
        {'id': 'dt13', 'text': "Oila a'zosiga xat yoki xabar yozing"},
        {'id': 'dt14', 'text': 'Bugun bir marta "Men seni yaxshi ko\'raman" deb ayting'},
    ],
    'ru': [
        {'id': 'dt1', 'text': 'Сделайте партнёру искренний комплимент'},
        {'id': 'dt2', 'text': 'Поговорите с ребёнком 10 минут без телефона'},
        {'id': 'dt3', 'text': 'Приготовьте ужин вместе сегодня вечером'},
        {'id': 'dt4', 'text': 'Скажите партнёру "Спасибо" — и объясните за что'},
        {'id': 'dt5', 'text': 'Обнимитесь хотя бы раз сегодня'},
        {'id': 'dt6', 'text': 'Напомните члену семьи о старом добром воспоминании'},
        {'id': 'dt7', 'text': 'Уберите телефоны и поговорите 15 минут'},
        {'id': 'dt8', 'text': 'Приготовьте партнёру небольшой сюрприз'},
        {'id': 'dt9', 'text': 'Скажите ребёнку, что он сегодня сделал хорошо'},
        {'id': 'dt10', 'text': 'Помогите кому-то сегодня, не ожидая ничего взамен'},
        {'id': 'dt11', 'text': 'Прогуляйтесь вместе с партнёром (хотя бы 10 минут)'},
        {'id': 'dt12', 'text': 'Проведите сегодня вечер без экранов'},
        {'id': 'dt13', 'text': 'Напишите письмо или сообщение члену семьи'},
        {'id': 'dt14', 'text': 'Скажите один раз сегодня "Я тебя люблю"'},
    ],
    'en': [
        {'id': 'dt1', 'text': 'Give your partner a genuine compliment'},
        {'id': 'dt2', 'text': 'Talk to your child for 10 minutes, phone-free'},
        {'id': 'dt3', 'text': 'Cook dinner together tonight'},
        {'id': 'dt4', 'text': 'Tell your partner "Thank you" — and say why'},
        {'id': 'dt5', 'text': 'Hug at least once today'},
        {'id': 'dt6', 'text': 'Remind a family member of a good old memory'},
        {'id': 'dt7', 'text': 'Put phones away and talk for 15 minutes'},
        {'id': 'dt8', 'text': 'Prepare a small surprise for your partner'},
        {'id': 'dt9', 'text': 'Tell your child what they did well today'},
        {'id': 'dt10', 'text': 'Help someone today expecting nothing back'},
        {'id': 'dt11', 'text': 'Take a walk together (even 10 minutes)'},
        {'id': 'dt12', 'text': 'Have a screen-free evening tonight'},
        {'id': 'dt13', 'text': 'Write a letter or message to a family member'},
        {'id': 'dt14', 'text': 'Say "I love you" once today'},
    ],
}

# --- CONFLICT MODE: muhim mavzular bo'yicha holat + 3 daqiqalik tinchlanish mashqi ---
CONFLICT_TOPICS = {
    'uz': [
        {'key': 'values', 'label': 'Qadriyatlar'},
        {'key': 'finance', 'label': 'Moliya'},
        {'key': 'children', 'label': 'Bolalar'},
        {'key': 'living', 'label': 'Turmush tarzi'},
        {'key': 'boundaries', 'label': 'Chegaralar'},
        {'key': 'conflict_handling', 'label': 'Nizo boshqaruvi'},
    ],
    'ru': [
        {'key': 'values', 'label': 'Ценности'},
        {'key': 'finance', 'label': 'Финансы'},
        {'key': 'children', 'label': 'Дети'},
        {'key': 'living', 'label': 'Образ жизни'},
        {'key': 'boundaries', 'label': 'Границы'},
        {'key': 'conflict_handling', 'label': 'Разрешение конфликтов'},
    ],
    'en': [
        {'key': 'values', 'label': 'Values'},
        {'key': 'finance', 'label': 'Finance'},
        {'key': 'children', 'label': 'Children'},
        {'key': 'living', 'label': 'Lifestyle'},
        {'key': 'boundaries', 'label': 'Boundaries'},
        {'key': 'conflict_handling', 'label': 'Conflict handling'},
    ],
}
CONFLICT_TOPIC_KEYS = {t['key'] for t in CONFLICT_TOPICS['uz']}
CONFLICT_STATUSES = {'agreement', 'needs_talk'}

def _pick_daily(pool, date_str, salt=0):
    """Deterministic rotation: same day -> same item for everyone (no randomness, no DB lookup)."""
    idx = (int(date_str.replace('-', '')) + salt) % len(pool)
    return pool[idx]

def _daily10_streak(db, family_id):
    """Consecutive days (up to and including today, if already checked in) with at least
    one check-in for this family. Mirrors a simple habit-streak counter."""
    rows = db.execute("SELECT DISTINCT checkin_date FROM daily_checkins WHERE family_id=?", (family_id,)).fetchall()
    dates = {r['checkin_date'] for r in rows}
    day = datetime.date.today()
    if day.isoformat() not in dates:
        day = day - datetime.timedelta(days=1)
    streak = 0
    while day.isoformat() in dates:
        streak += 1
        day -= datetime.timedelta(days=1)
    return streak

@app.route('/api/compatibility/questions', methods=['GET'])
@require_auth
@require_adult
def get_compat_questions():
    lang = request.args.get('lang', 'uz')
    if lang not in COMPAT_QUESTIONS:
        lang = 'uz'
    return ok({'blocks': COMPAT_QUESTIONS[lang], 'labels': BLOCK_LABELS[lang]})

@app.route('/api/compatibility/submit', methods=['POST'])
@require_auth
@require_adult
def submit_compat_test():
    body = request.json or {}
    answers = body.get('answers')  # {question_id: 1-5}
    partner_name = body.get('partner_name', '')
    lang = body.get('lang', 'uz')
    if lang not in COMPAT_QUESTIONS:
        lang = 'uz'
    if not answers or not isinstance(answers, dict):
        return err('answers majburiy')

    # Compute per-block score: average of (5 - abs(diff implied)) — since this is a single-person
    # self-assessment demo, we simulate alignment by scoring how confidently answered (closer to
    # consistent mid-high range = more clarity = better readiness signal).
    block_scores = {}
    for block, questions in COMPAT_QUESTIONS[lang].items():
        vals = [answers.get(q['id']) for q in questions if answers.get(q['id']) is not None]
        if not vals:
            block_scores[block] = 0
            continue
        vals = [int(v) for v in vals]
        avg = sum(vals) / len(vals)
        block_scores[block] = round(avg / 5 * 100)

    overall = round(sum(block_scores.values()) / len(block_scores)) if block_scores else 0

    tid = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT INTO compatibility_tests(id,family_id,user_id,partner_name,answers,scores,overall_score) VALUES(?,?,?,?,?,?,?)",
        (tid, g.family_id, g.user_id, partner_name, json.dumps(answers), json.dumps(block_scores), overall)
    )
    db.commit()

    return ok({
        'id': tid,
        'overall_score': overall,
        'block_scores': block_scores,
        'labels': BLOCK_LABELS[lang],
    }), 201

@app.route('/api/compatibility/history', methods=['GET'])
@require_auth
def get_compat_history():
    db = get_db()
    rows = db.execute(
        "SELECT id,partner_name,overall_score,scores,created_at FROM compatibility_tests WHERE family_id=? ORDER BY created_at DESC",
        (g.family_id,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d['scores'] = json.loads(d['scores'])
        except Exception:
            d['scores'] = {}
        result.append(d)
    return ok(result)

# --- FAMILY ASSESSMENT ---

@app.route('/api/assessments/questions', methods=['GET'])
@require_auth
@require_adult
def get_assessment_questions():
    lang = request.args.get('lang', 'uz')
    if lang not in ASSESSMENT_QUESTIONS:
        lang = 'uz'
    return ok({'categories': ASSESSMENT_QUESTIONS[lang], 'labels': ASSESSMENT_LABELS[lang]})

@app.route('/api/assessments', methods=['POST'])
@require_auth
@require_adult
def submit_assessment():
    body = request.json or {}
    answers = body.get('answers')  # {question_id: 1-5}
    lang = body.get('lang', 'uz')
    if lang not in ASSESSMENT_QUESTIONS:
        lang = 'uz'
    if not answers or not isinstance(answers, dict):
        return err('answers majburiy')

    # Score each category 0-100 (avg of 1-5 answers / 5 * 100). This is NOT a diagnosis --
    # it only flags which category deserves attention (lowest score = focus_area).
    category_scores = {}
    for category, questions in ASSESSMENT_QUESTIONS[lang].items():
        vals = [answers.get(q['id']) for q in questions if answers.get(q['id']) is not None]
        if not vals:
            category_scores[category] = None
            continue
        vals = [int(v) for v in vals]
        avg = sum(vals) / len(vals)
        category_scores[category] = round(avg / 5 * 100)

    scored = {k: v for k, v in category_scores.items() if v is not None}
    if not scored:
        return err('kamida bitta savolga javob bering')
    focus_area = min(scored, key=scored.get)

    aid = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT INTO family_assessments(id,family_id,user_id,answers,category_scores,focus_area) VALUES(?,?,?,?,?,?)",
        (aid, g.family_id, g.user_id, json.dumps(answers), json.dumps(category_scores), focus_area)
    )
    db.commit()

    return ok({
        'id': aid,
        'category_scores': category_scores,
        'focus_area': focus_area,
        'labels': ASSESSMENT_LABELS[lang],
    }), 201

@app.route('/api/assessments/history', methods=['GET'])
@require_auth
def get_assessment_history():
    db = get_db()
    rows = db.execute(
        "SELECT id,category_scores,focus_area,created_at FROM family_assessments WHERE family_id=? ORDER BY created_at DESC",
        (g.family_id,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d['category_scores'] = json.loads(d['category_scores'])
        except Exception:
            d['category_scores'] = {}
        result.append(d)
    return ok(result)

@app.route('/api/assessments/<aid>/insight', methods=['POST'])
@require_auth
@require_adult
def get_assessment_insight(aid):
    db = get_db()
    row = db.execute(
        "SELECT * FROM family_assessments WHERE id=? AND family_id=?",
        (aid, g.family_id)).fetchone()
    if not row:
        return err("Baholash topilmadi", 404)

    lang = (request.json or {}).get('lang', 'uz')
    if lang not in ASSESSMENT_LABELS:
        lang = 'uz'
    labels = ASSESSMENT_LABELS[lang]
    try:
        category_scores = json.loads(row['category_scores'])
    except Exception:
        category_scores = {}

    text, error = generate_ai_coach_insight(row['focus_area'], category_scores, labels, lang)
    if error:
        return err(error, 503)

    iid = str(uuid.uuid4())
    db.execute(
        "INSERT INTO coach_insights(id,family_id,user_id,assessment_id,focus_area,insight_text) VALUES(?,?,?,?,?,?)",
        (iid, g.family_id, g.user_id, aid, row['focus_area'], text))
    db.commit()

    return ok({'insight': text})

# --- FAMILY ASSESSMENT END ---

# --- DAILY 10 ---

@app.route('/api/daily10/today', methods=['GET'])
@require_auth
@require_adult
def get_daily10_today():
    lang = request.args.get('lang', 'uz')
    if lang not in DAILY10_QUESTIONS:
        lang = 'uz'
    today = datetime.date.today().isoformat()
    question = _pick_daily(DAILY10_QUESTIONS[lang], today, salt=0)
    task = _pick_daily(DAILY10_TASKS[lang], today, salt=7)

    db = get_db()
    row = db.execute(
        "SELECT * FROM daily_checkins WHERE family_id=? AND user_id=? AND checkin_date=?",
        (g.family_id, g.user_id, today)).fetchone()

    return ok({
        'date': today,
        'day_number': _daily10_streak(db, g.family_id),
        'question': question,
        'task': task,
        'answered_today': bool(row and row['answer_text']),
        'task_done_today': bool(row and row['task_done']),
        'answer_text': row['answer_text'] if row else None,
    })

@app.route('/api/daily10/answer', methods=['POST'])
@require_auth
@require_adult
def submit_daily10_answer():
    body = request.json or {}
    answer_text = (body.get('answer_text') or '').strip()
    lang = body.get('lang', 'uz')
    if lang not in DAILY10_QUESTIONS:
        lang = 'uz'
    if not answer_text:
        return err("Javob bo'sh bo'lmasligi kerak")

    today = datetime.date.today().isoformat()
    question = _pick_daily(DAILY10_QUESTIONS[lang], today, salt=0)
    db = get_db()
    existing = db.execute(
        "SELECT id FROM daily_checkins WHERE family_id=? AND user_id=? AND checkin_date=?",
        (g.family_id, g.user_id, today)).fetchone()
    if existing:
        db.execute(
            "UPDATE daily_checkins SET question_id=?, question_text=?, answer_text=? WHERE id=?",
            (question['id'], question['text'], answer_text, existing['id']))
    else:
        db.execute(
            "INSERT INTO daily_checkins(id,family_id,user_id,checkin_date,question_id,question_text,answer_text) "
            "VALUES(?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), g.family_id, g.user_id, today, question['id'], question['text'], answer_text))
    db.commit()
    return ok({'day_number': _daily10_streak(db, g.family_id)})

@app.route('/api/daily10/task', methods=['PATCH'])
@require_auth
@require_adult
def toggle_daily10_task():
    body = request.json or {}
    done = bool(body.get('done', True))
    lang = body.get('lang', 'uz')
    if lang not in DAILY10_TASKS:
        lang = 'uz'

    today = datetime.date.today().isoformat()
    task = _pick_daily(DAILY10_TASKS[lang], today, salt=7)
    db = get_db()
    existing = db.execute(
        "SELECT id FROM daily_checkins WHERE family_id=? AND user_id=? AND checkin_date=?",
        (g.family_id, g.user_id, today)).fetchone()
    if existing:
        db.execute("UPDATE daily_checkins SET task_id=?, task_text=?, task_done=? WHERE id=?",
                   (task['id'], task['text'], int(done), existing['id']))
    else:
        db.execute(
            "INSERT INTO daily_checkins(id,family_id,user_id,checkin_date,task_id,task_text,task_done) "
            "VALUES(?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), g.family_id, g.user_id, today, task['id'], task['text'], int(done)))
    db.commit()
    return ok({'day_number': _daily10_streak(db, g.family_id)})

@app.route('/api/daily10/history', methods=['GET'])
@require_auth
def get_daily10_history():
    db = get_db()
    rows = db.execute(
        "SELECT checkin_date,question_text,answer_text,task_text,task_done FROM daily_checkins "
        "WHERE family_id=? ORDER BY checkin_date DESC LIMIT 14",
        (g.family_id,)).fetchall()
    return ok(rows_to_list(rows))

# --- DAILY 10 END ---

# --- CONFLICT MODE ---

@app.route('/api/conflict/topics', methods=['GET'])
@require_auth
@require_adult
def get_conflict_topics():
    lang = request.args.get('lang', 'uz')
    if lang not in CONFLICT_TOPICS:
        lang = 'uz'
    db = get_db()
    rows = db.execute(
        "SELECT topic_key, status FROM conflict_topics WHERE family_id=? AND user_id=?",
        (g.family_id, g.user_id)).fetchall()
    statuses = {r['topic_key']: r['status'] for r in rows}
    topics = [{**topic, 'status': statuses.get(topic['key'])} for topic in CONFLICT_TOPICS[lang]]
    agreed = sum(1 for t in topics if t['status'] == 'agreement')
    return ok({'topics': topics, 'agreed_count': agreed, 'total': len(topics)})

@app.route('/api/conflict/topics/<topic_key>', methods=['PATCH'])
@require_auth
@require_adult
def set_conflict_topic(topic_key):
    if topic_key not in CONFLICT_TOPIC_KEYS:
        return err("Noma'lum mavzu")
    body = request.json or {}
    status = body.get('status')
    if status not in CONFLICT_STATUSES:
        return err("status 'agreement' yoki 'needs_talk' bo'lishi kerak")

    db = get_db()
    existing = db.execute(
        "SELECT id FROM conflict_topics WHERE family_id=? AND user_id=? AND topic_key=?",
        (g.family_id, g.user_id, topic_key)).fetchone()
    if existing:
        db.execute("UPDATE conflict_topics SET status=?, updated_at=datetime('now') WHERE id=?",
                   (status, existing['id']))
    else:
        db.execute(
            "INSERT INTO conflict_topics(id,family_id,user_id,topic_key,status) VALUES(?,?,?,?,?)",
            (str(uuid.uuid4()), g.family_id, g.user_id, topic_key, status))
    db.commit()
    return ok({'topic_key': topic_key, 'status': status})

# --- CONFLICT MODE END ---

# ─── MESSAGES (FAMILY, COUPLE, DIRECT) ───────────────────────────────────────

def validate_channel(channel, user_id, family_id, is_minor, db):
    """Validate and normalize channel. Returns (channel, error_msg)."""
    if channel in ('family', 'couple'):
        if channel == 'couple' and is_minor:
            return None, "Bu bo'lim faqat kattalar uchun"
        return channel, None
    if channel and channel.startswith('direct:'):
        other_id = channel[7:]
        if not other_id:
            return None, "Noto'g'ri kanal"
        # Verify other user is in same family
        member = db.execute(
            "SELECT id FROM family_members WHERE family_id=? AND user_id=?",
            (family_id, other_id)).fetchone()
        if not member:
            return None, "Bu foydalanuvchi oilangizda emas"
        # Normalize so that direct:A→B and direct:B→A use same channel key
        sorted_ids = sorted([user_id, other_id])
        return f"direct:{sorted_ids[0]}:{sorted_ids[1]}", None
    return 'family', None

@app.route('/api/messages', methods=['GET'])
@require_auth
def get_messages():
    channel_raw = request.args.get('channel', 'family')
    db = get_db()
    channel, err_msg = validate_channel(channel_raw, g.user_id, g.family_id, g.is_minor, db)
    if err_msg:
        return err(err_msg, 403)
    rows = db.execute(
        "SELECT m.*, u.full_name as sender_name FROM messages m "
        "JOIN users u ON m.sender_id = u.id "
        "WHERE m.family_id=? AND m.channel=? ORDER BY m.created_at ASC LIMIT 100",
        (g.family_id, channel)).fetchall()
    db.execute("UPDATE messages SET is_read=1 WHERE family_id=? AND channel=? AND sender_id!=?",
               (g.family_id, channel, g.user_id))
    db.commit()
    return ok(rows_to_list(rows))

MAX_CHAT_MEDIA_BYTES = {
    'photo': 2_000_000,
    'video': 8_000_000,
    'audio': 4_000_000,
}

@app.route('/api/messages', methods=['POST'])
@require_auth
def send_message():
    body = request.json or {}
    text = (body.get('body') or '').strip()
    kind = body.get('kind', 'text')
    media_url = body.get('media_url')
    channel_raw = body.get('channel', 'family')
    db = get_db()
    channel, err_msg = validate_channel(channel_raw, g.user_id, g.family_id, g.is_minor, db)
    if err_msg:
        return err(err_msg, 403)
    if kind == 'text' and not text:
        return err('Xabar matni bo\'sh bo\'lmasligi kerak')
    if kind != 'text' and not media_url:
        return err('Media fayl topilmadi')
    if len(text) > 1000:
        return err('Xabar juda uzun (max 1000 belgi)')
    if media_url:
        max_bytes = MAX_CHAT_MEDIA_BYTES.get(kind, 2_000_000)
        if len(media_url) > max_bytes:
            kind_label = {'photo': 'Rasm', 'video': 'Video', 'audio': 'Ovozli xabar'}.get(kind, 'Fayl')
            return err(f"{kind_label} hajmi juda katta")
    mid = str(uuid.uuid4())
    db.execute("INSERT INTO messages(id,family_id,sender_id,channel,body,kind,media_url) VALUES(?,?,?,?,?,?,?)",
               (mid, g.family_id, g.user_id, channel, text, kind, media_url))
    db.commit()
    row = db.execute(
        "SELECT m.*, u.full_name as sender_name FROM messages m "
        "JOIN users u ON m.sender_id = u.id WHERE m.id=?", (mid,)).fetchone()
    return ok(row_to_dict(row)), 201

@app.route('/api/messages/unread-count', methods=['GET'])
@require_auth
def unread_message_count():
    db = get_db()
    family_cnt = db.execute(
        "SELECT COUNT(*) as cnt FROM messages WHERE family_id=? AND channel='family' AND sender_id!=? AND is_read=0",
        (g.family_id, g.user_id)).fetchone()['cnt']
    couple_cnt = db.execute(
        "SELECT COUNT(*) as cnt FROM messages WHERE family_id=? AND channel='couple' AND sender_id!=? AND is_read=0",
        (g.family_id, g.user_id)).fetchone()['cnt']
    direct_cnt = db.execute(
        "SELECT COUNT(*) as cnt FROM messages WHERE family_id=? AND channel LIKE 'direct:%' "
        "AND (channel LIKE ?||'%' OR channel LIKE '%:'||?) AND sender_id!=? AND is_read=0",
        (g.family_id, f"direct:{g.user_id}", g.user_id, g.user_id)).fetchone()['cnt']
    return ok({'unread': family_cnt + couple_cnt + direct_cnt,
               'family': family_cnt, 'couple': couple_cnt, 'direct': direct_cnt})

# ─── PASSPORT DATA ───────────────────────────────────────────────────────────

@app.route('/api/passport/<member_id>', methods=['GET'])
@require_auth
@require_adult
def get_passport(member_id):
    db = get_db()
    row = db.execute(
        "SELECT * FROM passport_data WHERE family_id=? AND member_id=?",
        (g.family_id, member_id)).fetchone()
    d = row_to_dict(row)
    if d:
        for f in ('passport_series', 'passport_number', 'pinfl'):
            d[f] = decrypt_field(d.get(f))
    return ok(d)

@app.route('/api/passport/<member_id>', methods=['PUT'])
@require_auth
@require_adult
def save_passport(member_id):
    body = request.json or {}
    db = get_db()
    # Verify member belongs to this family
    member = db.execute(
        "SELECT id FROM family_members WHERE id=? AND family_id=?",
        (member_id, g.family_id)).fetchone()
    if not member:
        return err("A'zo topilmadi", 404)
    existing = db.execute(
        "SELECT id FROM passport_data WHERE family_id=? AND member_id=?",
        (g.family_id, member_id)).fetchone()
    fields = ['full_name', 'passport_series', 'passport_number', 'birth_date',
              'birth_place', 'issued_by', 'issued_date', 'expiry_date', 'pinfl']
    encrypted_fields = {'passport_series', 'passport_number', 'pinfl'}

    def field_value(f):
        v = body.get(f, '')
        return encrypt_field(v) if f in encrypted_fields else v

    if existing:
        set_clause = ', '.join(f"{f}=?" for f in fields) + ", updated_at=datetime('now')"
        values = [field_value(f) for f in fields] + [existing['id']]
        db.execute(f"UPDATE passport_data SET {set_clause} WHERE id=?", values)
    else:
        pid = str(uuid.uuid4())
        cols = ', '.join(fields)
        placeholders = ', '.join('?' for _ in fields)
        values = [pid, g.family_id, member_id] + [field_value(f) for f in fields]
        db.execute(
            f"INSERT INTO passport_data(id,family_id,member_id,{cols}) VALUES(?,?,?,{placeholders})",
            values)
    db.commit()
    row = db.execute(
        "SELECT * FROM passport_data WHERE family_id=? AND member_id=?",
        (g.family_id, member_id)).fetchone()
    d = row_to_dict(row)
    for f in ('passport_series', 'passport_number', 'pinfl'):
        d[f] = decrypt_field(d.get(f))
    return ok(d)

# ─── IMPORTANT DATES ─────────────────────────────────────────────────────────

@app.route('/api/important-dates', methods=['GET'])
@require_auth
def get_important_dates():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM important_dates WHERE family_id=? ORDER BY date ASC",
        (g.family_id,)).fetchall()
    today = datetime.date.today()
    result = []
    for r in rows:
        d = row_to_dict(r)
        try:
            date_parts = r['date'].split('-')
            event_date = datetime.date(today.year, int(date_parts[1]), int(date_parts[2]))
            if event_date < today:
                event_date = datetime.date(today.year + 1, int(date_parts[1]), int(date_parts[2]))
            d['days_left'] = (event_date - today).days
            d['is_today'] = d['days_left'] == 0
            years = today.year - int(date_parts[0])
            d['years'] = years
        except Exception:
            d['days_left'] = None
            d['is_today'] = False
            d['years'] = None
        result.append(d)
    result.sort(key=lambda x: x['days_left'] if x['days_left'] is not None else 9999)
    return ok(result)

@app.route('/api/important-dates', methods=['POST'])
@require_auth
def add_important_date():
    body = request.json or {}
    title = (body.get('title') or '').strip()
    date = (body.get('date') or '').strip()
    if not title or not date:
        return err('Sarlavha va sana majburiy')
    did = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT INTO important_dates(id,family_id,creator_id,title,date,type,recurring) VALUES(?,?,?,?,?,?,?)",
        (did, g.family_id, g.user_id, title, date, body.get('type', 'custom'), 1))
    db.commit()
    row = db.execute("SELECT * FROM important_dates WHERE id=?", (did,)).fetchone()
    return ok(row_to_dict(row)), 201

@app.route('/api/important-dates/<did>', methods=['DELETE'])
@require_auth
def delete_important_date(did):
    db = get_db()
    db.execute("DELETE FROM important_dates WHERE id=? AND family_id=?", (did, g.family_id))
    db.commit()
    return ok({'message': "O'chirildi"})

# ─── BIRTHDAYS ───────────────────────────────────────────────────────────────

@app.route('/api/birthdays/check', methods=['POST'])
@require_auth
def check_birthdays():
    db = get_db()
    today = datetime.date.today()
    today_md = f"{today.month:02d}-{today.day:02d}"
    members = db.execute("SELECT * FROM family_members WHERE family_id=?", (g.family_id,)).fetchall()
    sent = []
    for m in members:
        if not m['birth_date']:
            continue
        try:
            bday_md = m['birth_date'][5:]
        except Exception:
            continue
        if bday_md != today_md:
            continue
        existing = db.execute(
            "SELECT id FROM messages WHERE family_id=? AND channel='family' AND body LIKE ? AND DATE(created_at)=?",
            (g.family_id, f"%{m['name']}%", str(today))
        ).fetchone()
        if existing:
            continue
        if m['user_id'] == g.user_id:
            continue
        try:
            age = today.year - int(m['birth_date'][:4])
        except Exception:
            age = None
        age_str = f" {age} yosh" if age else ""
        msg_body = f"🎂 Bugun {m['name']}ning tug'ilgan kuni!{age_str} Tabriklaymiz! 🎉"
        mid = str(uuid.uuid4())
        db.execute("INSERT INTO messages(id,family_id,sender_id,channel,body,kind) VALUES(?,?,?,?,?,?)",
                   (mid, g.family_id, g.user_id, 'family', msg_body, 'birthday'))
        sent.append({'name': m['name'], 'age': age})
    if sent:
        db.commit()
    return ok({'sent': sent, 'today': str(today)})

@app.route('/api/birthdays/upcoming', methods=['GET'])
@require_auth
def upcoming_birthdays():
    db = get_db()
    members = db.execute(
        "SELECT name, birth_date, role FROM family_members WHERE family_id=? AND birth_date IS NOT NULL",
        (g.family_id,)).fetchall()
    today = datetime.date.today()
    upcoming = []
    for m in members:
        try:
            bday = datetime.date(today.year, int(m['birth_date'][5:7]), int(m['birth_date'][8:10]))
            if bday < today:
                bday = datetime.date(today.year + 1, bday.month, bday.day)
            days_left = (bday - today).days
            if days_left <= 30:
                age = today.year - int(m['birth_date'][:4])
                upcoming.append({'name': m['name'], 'birth_date': m['birth_date'],
                                 'days_left': days_left, 'age_turning': age, 'is_today': days_left == 0})
        except Exception:
            continue
    upcoming.sort(key=lambda x: x['days_left'])
    return ok(upcoming)

# ─── MISC ────────────────────────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(e):
    return err("Yuborilgan fayl juda katta. Iltimos, kichikroq fayl tanlang", 413)

@app.route('/api/health', methods=['GET'])
def health_check():
    return ok({'service': 'MEROS AI Backend', 'version': '1.0.0', 'status': 'running'})

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path and os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
    return response

@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options(path):
    return '', 204

# Initialize DB on import too (so gunicorn / WSGI servers also seed it)
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    print(f"✓ MEROS AI Backend ishga tushdi → http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=True)