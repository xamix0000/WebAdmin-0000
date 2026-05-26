from app import create_app

# Создаем экземпляр приложения
# Create an instance of the application
app = create_app()

if __name__ == '__main__':
    print("[SYSTEM] Запуск Web-сервера DIPLOM IAM...")
    # Запуск тестового сервера (для разработки). 
    # В продакшене этот блок игнорируется, так как Gunicorn вызывает app напрямую.
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, ssl_context=('/opt/webadmin/certs/server.crt', '/opt/webadmin/certs/server.key'))