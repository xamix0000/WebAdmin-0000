from flask import Blueprint, render_template, request, redirect, url_for, flash
import json
from app.core.ad_client import run_ps
from app.core.logger import log_action
from app.config import Config

bp_users = Blueprint('users', __name__)









# ПОЛЬЗОВАТЕЛИ
# USERS
@bp_users.route('/users')
def users_page():
    search = request.args.get('search', '').strip()
    if search: # Поиск имя или логин содержат подстроку /\ Search for name or login containing substring
        script = f"Get-ADUser -Filter \"Name -like '*{search}*' -or SamAccountName -like '*{search}*'\" -Properties Enabled | Select-Object Name, SamAccountName, Enabled"
    else: # Без поиска - все пользователи /\ Without searching - all users
        script = "Get-ADUser -Filter * -Properties Enabled | Select-Object Name, SamAccountName, Enabled"        
    users, error = run_ps(script) 
    # Фильтруем только успешные ответы (словари)
    # Filter only successful answers (dictionaries)
    users = [u for u in users if isinstance(u, dict)]
    return render_template('index.html', users=users, error=error, search=search)

@bp_users.route('/add_user', methods=['POST'])
def add_user():
    name = request.form.get('name')
    login = request.form.get('login')
    password = request.form.get('password')
    groups = request.form.getlist('groups') # Множественный выбор /\ # Multiple Choice
    # Флаги политик пароля
    # Password policy flags
    pwd_never_expires = bool(request.form.get('pwd_never_expires'))
    pwd_change_next = bool(request.form.get('pwd_change_next'))
    pwd_cannot_change = bool(request.form.get('pwd_cannot_change'))

    # Проверяем несовместимые комбинации до вызова AD
    # Check for incompatible combinations before calling AD
    if pwd_change_next and pwd_never_expires:
        flash("Конфликт: Нельзя требовать смену пароля, если срок его действия не ограничен.", "warning")
        return redirect(url_for('users_page'))
    if pwd_change_next and pwd_cannot_change:
        flash("Конфликт: Нельзя требовать смену пароля, если пользователю запрещено его менять.", "warning")
        return redirect(url_for('users_page'))

    # Конвертация булевых значений в синтаксис PowerShell
    # Converting Boolean Values ​​to PowerShell Syntax
    pwd_never_str = '$true' if pwd_never_expires else '$false'
    pwd_change_str = '$true' if pwd_change_next else '$false'
    pwd_cannot_str = '$true' if pwd_cannot_change else '$false'
    
    upn = f"{login}@{Config.DOMAIN_SUFFIX}" # Формирование UPN (User Principal Name) /\ Forming a UPN (User Principal Name)
    # Скрипт с откатом при ошибке
    # Script with rollback on error
    script = f"""
    # 1. Сначала проверяем, нет ли такого логина
    # 1. First, check if such a login exists.
    if (Get-ADUser -Filter "SamAccountName -eq '{login}'" -ErrorAction SilentlyContinue) {{
        throw "Логин '{login}' уже занят!"
    }}

    try {{
        # 2. Пытаемся создать пользователя
        # 2. Trying to create a user
        # ConvertTo-SecureString: 
        # конвертирует строку в защищённый объект для передачи в AD
        # ConvertTo-SecureString:
        # converts a string into a protected object for transfer to AD
        $secPass = ConvertTo-SecureString '{password}' -AsPlainText -Force
        New-ADUser -Name '{name}' -SamAccountName '{login}' -UserPrincipalName '{upn}' -AccountPassword $secPass -Enabled $true -PasswordNeverExpires {pwd_never_str} -ChangePasswordAtLogon {pwd_change_str}
        # Если задан флаг "не может менять пароль" — отдельный вызов
        # If the "cannot change password" flag is set - a separate call
        if ({pwd_cannot_str}) {{ Set-ADUser '{login}' -CannotChangePassword $true }}
    }} catch {{
        # 3. Если произошла ЛЮБАЯ ошибка (например, пароль не подошел), 
        # ищем, не успел ли создаться объект, и удаляем его мусор
        # 3. If ANY error occurs (for example, the password didn't work),
        # we check to see if the object was created yet and delete its garbage
        $trash = Get-ADUser -Filter "SamAccountName -eq '{login}'" -ErrorAction SilentlyContinue
        if ($trash) {{
            Remove-ADUser -Identity '{login}' -Confirm:$false
        }}
        # Пробрасываем ошибку дальше, чтобы её увидел админ в панели
        # Forward the error further so that the admin can see it in the panel
        throw $_.Exception.Message
    }}
    """
    
    _, err = run_ps(script) # Результат не нужен, только ошибка /\ # The result is not needed, only the error
    
    if err: # Ошибка создания - логируем попытку + показываем админу /\ # Creation error - log the attempt + show to the admin
        log_action('Ошибка создания', f'Попытка создать {login}')
        flash(f"Ошибка AD: {err}", "danger")
    else:
        for group in groups: # Успех - добавляем в выбранные группы (цикл) /\ # Success - add to selected groups (loop)
            run_ps(f"Add-ADGroupMember -Identity '{group}' -Members '{login}'")
        log_action('Создание юзера', f'Пользователь {login}')
        flash(f"Пользователь {name} успешно создан!", "success")
        
    return redirect(url_for('users.users_page'))

# Переключение статуса пользователя (вкл/выкл учётную запись)
# Switch user status (on/off account)
@bp_users.route('/toggle_user/<login>')
def toggle_user(login): # Получаем текущий статус /\ # Get the current status
    status_data, _ = run_ps(f"Get-ADUser -Identity '{login}' -Properties Enabled | Select-Object Enabled")
    if status_data: # Извлекаем булево значение /\ # Extract the boolean value
        is_enabled = status_data[0].get('Enabled') 
        # Вызываем противоположное действие 
        # Invoke the opposite action
        run_ps(f"Disable-ADAccount -Identity '{login}'" if is_enabled else f"Enable-ADAccount -Identity '{login}'")
        flash(f"Статус пользователя {login} изменен.", "info")
        log_action('Блокировка/Разблокировка', f'Пользователь {login}')
    return redirect(url_for('users.users_page'))

@bp_users.route('/delete_user/<login>')
def delete_user(login):
    # Удаление пользователя из Active Directory
    # Deleting a user from Active Directory
    _, err = run_ps(f"Remove-ADUser -Identity '{login}' -Confirm:$false")
    if err: flash(f"Ошибка удаления: {err}", "danger")
    else: 
        flash(f"Пользователь {login} удален.", "success")
        log_action('Удаление', f'Пользователь {login}') # Запись в журнал /\ Log entry
    return redirect(url_for('users.users_page'))

# ПРОФИЛЬ ЮЗЕРА
# USER PROFILE
# Страница профиля пользователя: данные + группы + действия
# User profile page: data + groups + actions
@bp_users.route('/user/<login>')
def user_profile(login):
    # Загружаем данные пользователя
    # Loading user data
    user_data, _ = run_ps(f"Get-ADUser -Identity '{login}' -Properties Enabled | Select-Object Name, SamAccountName, Enabled")
    if not user_data:
        flash("Пользователь не найден", "danger")
        return redirect(url_for('users.users_page'))
    user = user_data[0] if isinstance(user_data, list) else user_data

    # Загружаем группы
    # Loading groups
    user_groups, _ = run_ps(f"Get-ADPrincipalGroupMembership -Identity '{login}' | Select-Object Name")
    # all_groups, _ = run_ps("Get-ADGroup -Filter * | Select-Object Name")
    all_groups, _ = run_ps("Get-ADGroup -Filter * -Properties DistinguishedName | Where-Object { $_.DistinguishedName -notmatch 'CN=Builtin' } | Select-Object Name")
    
    return render_template('user_profile.html', user=user, user_groups=user_groups, all_groups=all_groups)

# Сброс пароля пользователя
# Reset user password
@bp_users.route('/user/<login>/reset_password', methods=['POST'])
def reset_password(login):
    new_pass = request.form.get('new_password')
    _, err = run_ps(f"Set-ADAccountPassword -Identity '{login}' -NewPassword (ConvertTo-SecureString '{new_pass}' -AsPlainText -Force) -Reset:$true")
    if err: flash(f"Ошибка сброса пароля: {err}", "danger")
    else: 
        flash("Пароль успешно изменен!", "success")
        log_action('Изменение', f'Пароль пользователя {login}')
    return redirect(url_for('users.user_profile', login=login))

# Добавление пользователя в группу
# Adding a user to a group
@bp_users.route('/user/<login>/add_group', methods=['POST'])
def user_add_group(login):
    group = request.form.get('group')
    _, err = run_ps(f"Add-ADGroupMember -Identity '{group}' -Members '{login}'")
    if err: flash(f"Ошибка: {err}", "danger")
    else: 
        flash(f"Пользователь добавлен в группу {group}", "success")
        log_action('Изменение', f'Пользователь добавлен в группу {login}')
    return redirect(url_for('users.user_profile', login=login))

# Удаление пользователя из группы
# Removing a user from a group
@bp_users.route('/user/<login>/remove_group/<group>')
def user_remove_group(login, group):
    _, err = run_ps(f"Remove-ADGroupMember -Identity '{group}' -Members '{login}' -Confirm:$false")
    if err: flash(f"Ошибка (возможно это основная группа): {err}", "danger")
    else: 
        flash(f"Пользователь удален из группы {group}", "success")
        log_action('Изменение', f'Пользователь удален из группы {login}')
    return redirect(url_for('users.user_profile', login=login))









# ГРУППЫ
# GROUPS
GROUP_CATEGORIES = {0: 'Distribution (Рассылка)', 1: 'Security (Безопасность)'}
GROUP_SCOPES = {0: 'Domain Local', 1: 'Global', 2: 'Universal'}

@bp_users.route('/groups')
def groups(): # Страница списка групп с поиском и фильтрацией /\ Group list page with search and filtering
    search = request.args.get('search', '').strip()
    # Формируем фильтр
    # Forming a filter
    filter_str = f"Name -like '*{search}*'" if search else "*"
    # Запрос с исключением встроенных групп
    # Query to exclude built-in groups
    groups_data, error = run_ps(f"Get-ADGroup -Filter \"{filter_str}\" -Properties DistinguishedName | Where-Object {{ $_.DistinguishedName -notmatch 'CN=Builtin' }} | Select-Object Name, GroupCategory, GroupScope")
    # Фильтруем только успешные ответы
    # Filter only successful responses
    groups_data =[g for g in groups_data if isinstance(g, dict)]
    
    # Преобразуем коды в человекочитаемый текст
    # Convert codes into human-readable text
    for g in groups_data:
        g['CategoryText'] = GROUP_CATEGORIES.get(g.get('GroupCategory'), 'Неизвестно')
        g['ScopeText'] = GROUP_SCOPES.get(g.get('GroupScope'), 'Неизвестно')
        
    return render_template('groups.html', groups=groups_data, error=error, search=search)

@bp_users.route('/add_group', methods=['POST'])
def add_group():
    group_name = request.form.get('group_name')
    _, err = run_ps(f"New-ADGroup -Name '{group_name}' -GroupCategory Security -GroupScope Global")
    if err: flash(f"Ошибка: {err}", "danger")
    else: 
        flash(f"Группа {group_name} создана", "success")
        log_action('Создание', f'Группа {group_name}')
    return redirect(url_for('users.groups'))

@bp_users.route('/delete_group/<name>')
def delete_group(name):
    _, err = run_ps(f"Remove-ADGroup -Identity '{name}' -Confirm:$false")
    if err: flash(f"Ошибка: {err}", "danger")
    else: 
        flash(f"Группа {name} удалена.", "success")
        log_action('Удаление', f'Группа {name}')
    return redirect(url_for('users.groups'))

@bp_users.route('/group/<name>')
def group_profile(name):
    members, _ = run_ps(f"Get-ADGroupMember -Identity '{name}' | Select-Object Name, SamAccountName, objectClass")
    all_users, _ = run_ps("Get-ADUser -Filter * | Select-Object Name, SamAccountName")
    return render_template('group_profile.html', group_name=name, members=members, all_users=all_users)

@bp_users.route('/group/<name>/add_member', methods=['POST'])
def group_add_member(name):
    login = request.form.get('login')
    _, err = run_ps(f"Add-ADGroupMember -Identity '{name}' -Members '{login}'")
    if err: flash(f"Ошибка: {err}", "danger")
    else: 
        flash("Участник добавлен!", "success")
        log_action('Изменение', f'Пользователь {login} добавлен в группу {name}')
    return redirect(url_for('users.group_profile', name=name))

@bp_users.route('/group/<name>/remove_member/<login>')
def group_remove_member(name, login):
    _, err = run_ps(f"Remove-ADGroupMember -Identity '{name}' -Members '{login}' -Confirm:$false")
    if err: flash(f"Ошибка: {err}", "danger")
    else: 
        flash("Участник удален из группы.", "success")
        log_action('Изменение', f'Пользователь {login} удален из группы {name}')
    return redirect(url_for('users.group_profile', name=name))

@bp_users.route('/api/groups')
def api_groups():
    groups_data, _ = run_ps("Get-ADGroup -Filter * -Properties DistinguishedName | Where-Object { $_.DistinguishedName -notmatch 'CN=Builtin' } | Select-Object Name")
    # Возвращаем простой список имён
    # Return a simple list of names
    groups_data, err = run_ps(script)
    
    if err:
        print(f"[API GROUPS ERROR]: {err}")
        return json.dumps([])
        
    if not groups_data:
        return json.dumps([])
    # Возвращаем простой список имён
    # Return a simple list of names    
    return json.dumps([g['Name'] for g in groups_data if isinstance(g, dict)])