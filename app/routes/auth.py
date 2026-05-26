from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.core.ad_client import run_ps
from app.core.logger import log_action
from app.config import Config

# Создаем Blueprint с именем 'auth'
bp_auth = Blueprint('auth', __name__)

@bp_auth.before_app_request
def require_login():
    # Запрещает доступ ко всем страницам без авторизации
    # Белый список маршрутов, доступных без авторизации
    # Denies access to all pages without authorization
    # Whitelist of routes accessible without authorization
    allowed_routes = ['auth.login', 'static']
    # request.endpoint содержит имя функции-обработчика текущего URL
    # request.endpoint contains the name of the handler function for the current URL
    if request.endpoint not in allowed_routes and 'user' not in session:
        # Если пользователь не залогинен - редирект на страницу входа
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('auth.login'))

@bp_auth.route('/login', methods=['GET', 'POST'])
# Обработка входа в панель 
# GET - показывает форму
# POST - проверяет учётные данные через ядро Windows (.NET) + проверяет права админа
# POST 
    #   1. Принимает логин/пароль из формы
    #   2. Экранирует ввод для защиты от инъекций
    #   3. Выполняет PowerShell-скрипт через WinRM
    #   4. Скрипт использует .NET-класс DirectoryEntry для LDAP-бинда к AD
    #   5. При успехе — проверяет членство в группах администраторов
    #   6. При подтверждении прав — создаёт сессию и перенаправляет на дашборд
# POST
    #   1. Accepts username/password from form
    #   2. Escapes input to prevent injection attacks
    #   3. Executes PowerShell script via WinRM
    #   4. Script uses .NET DirectoryEntry class for LDAP bind to AD
    #   5. On success — checks membership in admin groups
    #   6. On privilege confirmation — creates session and redirects to dashboard
# Processing panel login
# GET - displays the form
# POST - verifies credentials via the Windows kernel (.NET) + verifies admin rights
def login():
    # Аутентификация пользователя в Active Directory через LDAP-бинд
    # User authentication against Active Directory via LDAP bind
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # PowerShell использует одинарные кавычки для строк от иньекции в PS 
        # Двойная кавычка экранирует
        # Экранируем кавычки для безопасности PowerShell
        # PowerShell uses single quotes for strings to prevent injection into PS
        # Double quotes escape
        # Escaping quotes for PowerShell security
        safe_user = username.replace("'", "''")
        safe_pass = password.replace("'", "''")
        

# & {{ ... }} — выполняем код как изолированный скрипт-блок
# Это предотвращает утечку переменных ($entry, $groups) в глобальную сессию PowerShell
# & {{ ... }} — execute code as an isolated script block
# This prevents variable leakage ($entry, $groups) into the global PowerShell session

        ps_script = f"""& {{
            $isValid = $false
            $isAdmin = $false
            
            try {{
                    # Создаём объект DirectoryEntry — это ручка к записи в AD
                    # Параметры: путь к объекту, логин, пароль
                    # Create DirectoryEntry object — this is a handle to an AD object
                    # Parameters: object path, login, password
                $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://{Config.AD_SERVER_FQDN}", "{safe_user}@{Config.DOMAIN_SUFFIX}", "{safe_pass}")
                $bind = $entry.NativeObject
                $isValid = $true
            }} catch {{
                $isValid = $false
            }}
                    # Если аутентификация успешна — проверяем права администратора
            if ($isValid) {{
                $groups = Get-ADPrincipalGroupMembership -Identity '{safe_user}' | Select-Object -ExpandProperty Name
                if ($groups -contains 'Администраторы домена' -or $groups -contains 'Domain Admins') {{
                    $isAdmin = $true
                }}
            }}
            
            @{{ status = if($isValid){{'OK'}}else{{'INVALID'}}; isAdmin = $isAdmin }}
        }}"""
        # Вызываем обёртку run_ps()
        # Call the run_ps() wrapper
        data, err = run_ps(ps_script)
        
        if err:
            # Ошибка на уровне WinRM/сети/PS
            # Error at the WinRM/network/PS level
            flash(f"Ошибка связи с сервером авторизации.", "danger")
            flash(f"Системная ошибка: {err}", "danger")
            print(f"[КРИТИЧЕСКАЯ ОШИБКА АВТОРИЗАЦИИ]: {err}")
        else:
            # Извлекаем словарь из ответа run_ps возвращает (list, error)
            # Extract the dictionary from the response run_ps returns (list, error)
            res_dict = data[0] if isinstance(data, list) and len(data) > 0 else data
            # Проверяем логику успеха 
            # Checking the logic of success
            if isinstance(res_dict, dict) and res_dict.get('status') == 'OK':
                if res_dict.get('isAdmin'):
                    # Успешная авторизация
                    # Сохраняем логин в Flask-сессии (подписанный cookie)
                    # Successful authorization
                    # Saving the login in the Flask session (signed cookie)
                    session['user'] = username # Сохраняем сессию /\ Saving session
                    log_action('Вход в систему', f'Успешная авторизация ({username})') # Запись в журнал /\ Journal entry
                    return redirect(url_for('dashboard.home'))
                else:
                    flash("В доступе отказано: Требуются права Администратора домена.", "warning")
            else:
                flash("Неверный логин или пароль.", "danger")
                
    return render_template('login.html')

@bp_auth.route('/logout')
def logout():
    """Завершение сессии 
    session.pop() удаляет ключ user из подписанного cookie,
    браузер при следующем запросе не отправит 
    валидную сессию - require_login сработает"""
    """Terminating a session
    session.pop() removes the user key from the signed cookie.
    The browser will not send a valid session on the next request - 
    require_login will be triggered."""
    session.pop('user', None) # None = не кидать ошибку, если ключа нет /\ None = don't throw an error if there is no key
    return redirect(url_for('auth.login'))