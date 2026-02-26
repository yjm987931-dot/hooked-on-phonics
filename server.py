#!/usr/bin/env python3
"""
Hooked on Phonics - Flask 서버
포트 7777, 학생/선생님 인증, 진도 추적
CD 없이도 내장 데이터로 작동
"""
import os, json, hashlib, secrets, sqlite3
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='static', static_url_path='/static')

# Persistent secret key (세션 유지를 위해 파일에 저장)
_sk_file = Path(__file__).parent / 'data' / '.secret_key'
if _sk_file.exists():
    app.secret_key = _sk_file.read_text()
else:
    _sk_file.parent.mkdir(parents=True, exist_ok=True)
    _key = secrets.token_hex(32)
    _sk_file.write_text(_key)
    app.secret_key = _key

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / 'data'
DB_PATH = DATA_DIR / 'phonics.db'


# ===== Database =====
def get_db():
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    return db


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            activity TEXT NOT NULL,
            word TEXT DEFAULT '',
            correct INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0,
            score INTEGER DEFAULT 0,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    ''')
    existing = db.execute("SELECT id FROM users WHERE role='teacher'").fetchone()
    if not existing:
        pw = hashlib.sha256('teacher1234'.encode()).hexdigest()
        db.execute(
            "INSERT INTO users (username, password_hash, name, role) VALUES (?, ?, ?, ?)",
            ('teacher', pw, '선생님', 'teacher')
        )
        db.commit()
    db.close()


def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# ===== Auth Decorators =====
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다'}), 401
        return f(*args, **kwargs)
    return decorated


def teacher_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'teacher':
            return jsonify({'error': '선생님 권한이 필요합니다'}), 403
        return f(*args, **kwargs)
    return decorated


# ===== Routes =====
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    if not user or user['password_hash'] != hash_pw(password):
        return jsonify({'error': '아이디 또는 비밀번호가 틀립니다'}), 401
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['name'] = user['name']
    session['role'] = user['role']
    return jsonify({
        'id': user['id'], 'username': user['username'],
        'name': user['name'], 'role': user['role']
    })


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/me')
def me():
    if 'user_id' not in session:
        return jsonify({'logged_in': False})
    return jsonify({
        'logged_in': True, 'id': session['user_id'],
        'username': session['username'], 'name': session['name'],
        'role': session['role']
    })


# ===== Teacher: Student Management =====
@app.route('/api/students', methods=['GET'])
@teacher_required
def list_students():
    db = get_db()
    students = db.execute(
        "SELECT id, username, name, created_at FROM users WHERE role='student' ORDER BY name"
    ).fetchall()
    result = []
    for s in students:
        prog = db.execute(
            "SELECT activity, SUM(correct) as correct, SUM(total) as total, "
            "COUNT(*) as sessions FROM progress WHERE user_id=? GROUP BY activity",
            (s['id'],)
        ).fetchall()
        last = db.execute(
            "SELECT completed_at FROM progress WHERE user_id=? "
            "ORDER BY completed_at DESC LIMIT 1", (s['id'],)
        ).fetchone()
        result.append({
            'id': s['id'], 'username': s['username'],
            'name': s['name'], 'created_at': s['created_at'],
            'last_active': last['completed_at'] if last else None,
            'progress': [dict(p) for p in prog]
        })
    db.close()
    return jsonify(result)


@app.route('/api/students', methods=['POST'])
@teacher_required
def add_student():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    name = data.get('name', '').strip()
    if not username or not password or not name:
        return jsonify({'error': '모든 필드를 입력해주세요'}), 400
    db = get_db()
    if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        db.close()
        return jsonify({'error': '이미 존재하는 아이디입니다'}), 400
    db.execute(
        "INSERT INTO users (username, password_hash, name, role) VALUES (?, ?, ?, 'student')",
        (username, hash_pw(password), name)
    )
    db.commit()
    sid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.close()
    return jsonify({'id': sid, 'username': username, 'name': name})


@app.route('/api/students/<int:sid>', methods=['DELETE'])
@teacher_required
def delete_student(sid):
    db = get_db()
    db.execute("DELETE FROM progress WHERE user_id=?", (sid,))
    db.execute("DELETE FROM users WHERE id=? AND role='student'", (sid,))
    db.commit()
    db.close()
    return jsonify({'ok': True})


@app.route('/api/students/<int:sid>/reset', methods=['POST'])
@teacher_required
def reset_student_password(sid):
    data = request.get_json(force=True, silent=True) or {}
    new_pw = data.get('password', '')
    if not new_pw:
        return jsonify({'error': '새 비밀번호를 입력해주세요'}), 400
    db = get_db()
    db.execute("UPDATE users SET password_hash=? WHERE id=? AND role='student'",
               (hash_pw(new_pw), sid))
    db.commit()
    db.close()
    return jsonify({'ok': True})


# ===== Progress =====
@app.route('/api/progress', methods=['GET'])
@login_required
def get_progress():
    uid = request.args.get('user_id', session['user_id'], type=int)
    if uid != session['user_id'] and session.get('role') != 'teacher':
        return jsonify({'error': '권한 없음'}), 403
    db = get_db()
    rows = db.execute(
        "SELECT activity, word, correct, total, score, completed_at "
        "FROM progress WHERE user_id=? ORDER BY completed_at DESC LIMIT 200",
        (uid,)
    ).fetchall()
    summary = db.execute(
        "SELECT activity, SUM(correct) as correct, SUM(total) as total, "
        "ROUND(AVG(score),1) as avg_score, COUNT(*) as sessions "
        "FROM progress WHERE user_id=? GROUP BY activity",
        (uid,)
    ).fetchall()
    db.close()
    return jsonify({
        'history': [dict(r) for r in rows],
        'summary': [dict(s) for s in summary]
    })


@app.route('/api/progress', methods=['POST'])
@login_required
def save_progress():
    data = request.get_json(force=True, silent=True) or {}
    db = get_db()
    db.execute(
        "INSERT INTO progress (user_id, activity, word, correct, total, score) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (session['user_id'], data.get('activity', ''), data.get('word', ''),
         data.get('correct', 0), data.get('total', 0), data.get('score', 0))
    )
    db.commit()
    db.close()
    return jsonify({'ok': True})


@app.route('/api/student/<int:sid>/progress')
@teacher_required
def student_progress(sid):
    db = get_db()
    student = db.execute("SELECT id, username, name FROM users WHERE id=?", (sid,)).fetchone()
    if not student:
        db.close()
        return jsonify({'error': '학생을 찾을 수 없습니다'}), 404
    rows = db.execute(
        "SELECT activity, word, correct, total, score, completed_at "
        "FROM progress WHERE user_id=? ORDER BY completed_at DESC",
        (sid,)
    ).fetchall()
    summary = db.execute(
        "SELECT activity, SUM(correct) as correct, SUM(total) as total, "
        "ROUND(AVG(score),1) as avg_score, COUNT(*) as sessions "
        "FROM progress WHERE user_id=? GROUP BY activity",
        (sid,)
    ).fetchall()
    db.close()
    return jsonify({
        'student': dict(student),
        'history': [dict(r) for r in rows],
        'summary': [dict(s) for s in summary]
    })


# ===== Data APIs =====
@app.route('/api/words')
@login_required
def get_words():
    wf = DATA_DIR / 'words.json'
    if wf.exists():
        return jsonify(json.loads(wf.read_text(encoding='utf-8')))
    return jsonify({})


@app.route('/api/assets')
@login_required
def get_assets():
    af = DATA_DIR / 'asset_index.json'
    if af.exists():
        return jsonify(json.loads(af.read_text(encoding='utf-8')))
    return jsonify({})


@app.route('/api/has-media')
def has_media():
    img_dir = BASE_DIR / 'static' / 'images'
    aud_dir = BASE_DIR / 'static' / 'audio'
    has_img = img_dir.exists() and any(img_dir.rglob('*.png'))
    has_aud = aud_dir.exists() and any(aud_dir.rglob('*.wav'))
    return jsonify({'images': has_img, 'audio': has_aud})


# ===== Password Change =====
@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json(force=True, silent=True) or {}
    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')
    if not new_pw:
        return jsonify({'error': '새 비밀번호를 입력해주세요'}), 400
    db = get_db()
    user = db.execute("SELECT password_hash FROM users WHERE id=?",
                      (session['user_id'],)).fetchone()
    if user['password_hash'] != hash_pw(old_pw):
        db.close()
        return jsonify({'error': '현재 비밀번호가 틀립니다'}), 400
    db.execute("UPDATE users SET password_hash=? WHERE id=?",
               (hash_pw(new_pw), session['user_id']))
    db.commit()
    db.close()
    return jsonify({'ok': True})


# 서버 시작 시 항상 DB 초기화 (WSGI + 직접 실행 모두 지원)
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7777))
    print("=" * 50)
    print("  Hooked on Phonics - 파닉스 학습 서버")
    print(f"  http://localhost:{port}")
    print("  선생님 계정: teacher / teacher1234")
    print("=" * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
