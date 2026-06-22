"""
MEROS AI — Backend API
Flask + SQLite | JWT Auth | REST API
"""

from flask import Flask, request, jsonify, g, send_from_directory
from functools import wraps
import sqlite3
import hashlib
import hmac
import json
import uuid
import datetime
import jwt
import os
import re

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'meros-ai-secret-2026-dev')
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4MB max request size
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

    CREATE TABLE IF NOT EXISTS memories (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        uploader_id TEXT NOT NULL,
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
        type        TEXT NOT NULL,
        title       TEXT NOT NULL,
        body        TEXT NOT NULL,
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
        body        TEXT NOT NULL,
        kind        TEXT DEFAULT 'text',
        is_read     INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now'))
    );
    """)
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

    pw = hashlib.sha256("demo123".encode()).hexdigest()

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
        db.execute("INSERT INTO family_members VALUES (?,?,?,?,?,?,?,?,datetime('now'))", m)

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
        db.execute("INSERT INTO memories VALUES (?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))", m)

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
        db.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,datetime('now'))", a)

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

    if not all([phone, full_name, password]):
        return err('Telefon, ism va parol majburiy')

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE phone=?", (phone,)).fetchone()
    if existing:
        return err('Bu raqam allaqachon ro\'yxatdan o\'tgan')

    user_id = str(uuid.uuid4())
    pw_hash = hashlib.sha256(password.encode()).hexdigest()

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
                  VALUES(?,?,?,?,?,?,?,'adult')""",
               (user_id, phone, full_name, birth_date, gender, pw_hash, fam_id))

    db.execute("""INSERT INTO family_members(id,family_id,user_id,name,birth_date,gender,role,avatar_color)
                  VALUES(?,?,?,?,?,?,'parent',?)""",
               (str(uuid.uuid4()), fam_id, user_id, full_name, birth_date, gender,
                '#C2185B' if gender == 'female' else '#1A78C2'))
    db.commit()

    token = make_token(user_id, fam_id)
    return ok({'token': token, 'user_id': user_id, 'family_id': fam_id}, message="Muvaffaqiyatli ro'yxatdan o'tdingiz"), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    body = request.json or {}
    phone    = body.get('phone', '').strip()
    password = body.get('password', '').strip()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if not user or user['password_hash'] != pw_hash:
        return err("Telefon yoki parol noto'g'ri", 401)
    token = make_token(user['id'], user['family_id'])
    return ok({'token': token, 'user': row_to_dict(user)})

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
    members = db.execute("SELECT * FROM family_members WHERE family_id=?", (g.family_id,)).fetchall()
    return ok({'family': row_to_dict(family), 'members': rows_to_list(members)})

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

# ─── HEALTH ──────────────────────────────────────────────────────────────────

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

# ─── MEMORIES ────────────────────────────────────────────────────────────────

@app.route('/api/memories', methods=['GET'])
@require_auth
def get_memories():
    year  = request.args.get('year')
    limit = int(request.args.get('limit', 50))
    db = get_db()
    if year:
        rows = db.execute(
            "SELECT * FROM memories WHERE family_id=? AND strftime('%Y',taken_at)=? ORDER BY taken_at DESC LIMIT ?",
            (g.family_id, year, limit)).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM memories WHERE family_id=? ORDER BY taken_at DESC LIMIT ?",
            (g.family_id, limit)).fetchall()
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
    media_url = body.get('media_url')
    if media_url and len(media_url) > 2_000_000:  # ~1.5MB after base64 overhead
        return err("Rasm hajmi juda katta. Iltimos, kichikroq rasm tanlang")
    mid = str(uuid.uuid4())
    tags = json.dumps(body.get('tags', []))
    db = get_db()
    db.execute("""INSERT INTO memories(id,family_id,uploader_id,title,description,media_type,media_url,emoji,color,taken_at,location,tags)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
               (mid, g.family_id, g.user_id,
                body.get('title'), body.get('description'),
                body.get('media_type','photo'), media_url,
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
        "SELECT * FROM alerts WHERE family_id=? ORDER BY created_at DESC LIMIT 20",
        (g.family_id,)).fetchall()
    unread = db.execute(
        "SELECT COUNT(*) as cnt FROM alerts WHERE family_id=? AND is_read=0",
        (g.family_id,)).fetchone()['cnt']
    return ok({'alerts': rows_to_list(rows), 'unread': unread})

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

@app.route('/api/compatibility/questions', methods=['GET'])
@require_auth
def get_compat_questions():
    lang = request.args.get('lang', 'uz')
    if lang not in COMPAT_QUESTIONS:
        lang = 'uz'
    return ok({'blocks': COMPAT_QUESTIONS[lang], 'labels': BLOCK_LABELS[lang]})

@app.route('/api/compatibility/submit', methods=['POST'])
@require_auth
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

# ─── MESSAGES (COUPLE CHAT) ─────────────────────────────────────────────────

@app.route('/api/messages', methods=['GET'])
@require_auth
def get_messages():
    db = get_db()
    rows = db.execute(
        "SELECT m.*, u.full_name as sender_name FROM messages m "
        "JOIN users u ON m.sender_id = u.id "
        "WHERE m.family_id=? ORDER BY m.created_at ASC LIMIT 100",
        (g.family_id,)).fetchall()
    # Mark messages from others as read
    db.execute("UPDATE messages SET is_read=1 WHERE family_id=? AND sender_id!=?",
               (g.family_id, g.user_id))
    db.commit()
    return ok(rows_to_list(rows))

@app.route('/api/messages', methods=['POST'])
@require_auth
def send_message():
    body = request.json or {}
    text = (body.get('body') or '').strip()
    kind = body.get('kind', 'text')
    if not text:
        return err('Xabar matni bo\'sh bo\'lmasligi kerak')
    if len(text) > 1000:
        return err('Xabar juda uzun (max 1000 belgi)')
    mid = str(uuid.uuid4())
    db = get_db()
    db.execute("INSERT INTO messages(id,family_id,sender_id,body,kind) VALUES(?,?,?,?,?)",
               (mid, g.family_id, g.user_id, text, kind))
    db.commit()
    row = db.execute(
        "SELECT m.*, u.full_name as sender_name FROM messages m "
        "JOIN users u ON m.sender_id = u.id WHERE m.id=?", (mid,)).fetchone()
    return ok(row_to_dict(row)), 201

@app.route('/api/messages/unread-count', methods=['GET'])
@require_auth
def unread_message_count():
    db = get_db()
    cnt = db.execute(
        "SELECT COUNT(*) as cnt FROM messages WHERE family_id=? AND sender_id!=? AND is_read=0",
        (g.family_id, g.user_id)).fetchone()['cnt']
    return ok({'unread': cnt})

# ─── MISC ────────────────────────────────────────────────────────────────────

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