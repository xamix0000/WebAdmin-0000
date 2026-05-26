import sqlite3
from flask import session, request
from contextlib import contextmanager

@contextmanager
def get_db_connection():
    # Контекстный менеджер для безопасной работы с БД SQLite
    conn = sqlite3.connect('audit.db', timeout=10) # Таймаут спасет от блокировок
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
     with get_db_connection() as conn:
        """Инициализация локальной базы (sqlite) аудита 
        (аудит действий администраторов в панели)"""
        """The local audit base (sqlite) initialization
        (admin's action audit)"""
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, 
                    admin_user TEXT, 
                    action_type TEXT, 
                    target TEXT,
                    ip_address TEXT)''')
        try:
            c.execute("ALTER TABLE activity_log ADD COLUMN ip_address TEXT")
        except:
            pass    

def log_action(action_type, target):
    """Запись действия в журнал audit.db"""
    """Write things in file audit.db"""
    # Берём имя админа из Flask-сессии в противном случае System
    # Get the Admin name from Flask-session else System
    try:  
        admin = session.get('user', 'System')
        ip = request.headers.get('X-Real-IP', request.remote_addr) if request else 'Localhost'
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO activity_log (admin_user, action_type, target, ip_address) VALUES (?, ?, ?, ?)", 
                    (admin, action_type, target, ip))
    except Exception as e:
        # Логируем ошибку, но не прерываем основной поток
        # Error log, without ending the main thread
        print(f"[Logger] Ошибка записи лога: {e}")    