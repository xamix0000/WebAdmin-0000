from flask import Flask
from app.config import Config
from app.core.logger import init_db
from app.core.monitor import start_monitoring

def create_app():
    # Фабрика приложения: собирает Flask-приложение по частям
    # Application Factory: builds a Flask application piece by piece
    app = Flask(__name__)
    
    # Загружаем настройки из config.py (который берет их из .env)
    # Load settings from config.py (which takes them from .env)
    app.config.from_object(Config)

    # Инициализируем базу данных для логов (создаст audit.db, если её нет) и запуск потоков мониторинга
    # Initialize the database for logs (will create audit.db if it doesn't exist) and launching monitoring threads
    init_db()
    start_monitoring()


    # Регистрация Blueprint-ов
    from app.routes.auth import bp_auth
    from app.routes.dashboard import bp_dashboard
    from app.routes.users import bp_users
    from app.routes.shares import bp_shares
    
    app.register_blueprint(bp_auth)
    app.register_blueprint(bp_dashboard)
    app.register_blueprint(bp_users)
    app.register_blueprint(bp_shares)


    return app