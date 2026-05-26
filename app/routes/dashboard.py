from flask import Blueprint, render_template, request, Response, jsonify
import subprocess
import sqlite3
import csv
import io
import json
import socket
import re
from datetime import datetime, timezone
from app.core.ad_client import run_ps, parse_ms_date
from app.core.samba_mgr import get_samba_shares, get_dir_size
from app.core.monitor import SYSTEM_CACHE
from app.config import Config

bp_dashboard = Blueprint('dashboard', __name__)

def get_local_ip():
    """Определяет IP-адрес текущего сервера Debian,
    socket.getsockname() возвращает именно тот интерфейс, 
    через который сервер видит внешнюю сеть"""
    """Determines the IP address of the current Debian server.
    socket.getsockname() returns the exact interface
    through which the server sees the external network"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Фейковое подключение для определения маршрута
        # Fake connection to determine the route
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0] # Берём только IP /\ take only the IP
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

@bp_dashboard.route('/')
def home():
    """Главная страница с динамическими IP
    Передаёт в шаблон:
    ad_ip — адрес контроллера домена (из конфига)
    debian_ip — адрес текущего сервера (вычисляется динамически)"""
    """Main page with dynamic IPs
    Passes to the template:
    ad_ip — domain controller address (from config)
    debian_ip — current server address (dynamically calculated)"""
    return render_template('home.html', ad_ip=Config.AD_SERVER_FQDN, debian_ip=get_local_ip(), auth_method=Config.AUTH_METHOD.upper())

@bp_dashboard.route('/api/system_stats')
def api_system_stats():
    # Отдача данных для графиков
    # Data output for graphs
    return SYSTEM_CACHE

@bp_dashboard.route('/api/dashboard_data')
def api_dashboard_data():
    import shutil
    
    # 1. Чтение общего диска
    # 1. Reading a shared disk
    try:
        total, used, free = shutil.disk_usage('/srv/samba')
    except:
        total, used, free = 1, 0, 1 # Фейковые значения "заглушки", если диск недоступен /\ Fake "stub" values ​​if the disk is unavailable

    # 2. Логи активности
    # 2. Activity logs
    logs = []
    try:
        conn = sqlite3.connect('audit.db')
        c = conn.cursor()
        c.execute("SELECT datetime(timestamp, 'localtime'), admin_user, action_type, target FROM activity_log ORDER BY id DESC LIMIT 7")
        logs = [{'time': r[0], 'admin': r[1], 'action': r[2], 'target': r[3]} for r in c.fetchall()]
        conn.close()
    except: pass

    # 3. Активные сессии Samba
    # 3. Active Samba sessions
    try:
        smb_out = subprocess.check_output(['smbstatus', '-b'], text=True)
        active_sessions = len(smb_out.strip().split('\n')) - 4
        if active_sessions < 0: active_sessions = 0
    except: active_sessions = 0

    # 4. Взвешиваем папки (Считаем % от всего диска сервера)
    # 4. Weighing the folders (Сalculate the % of the entire server disk)
    share_stats = []
    for s in get_samba_shares():
        size_bytes = get_dir_size(s['path'])
        
        if size_bytes > 1024**3: 
            size_str = f"{round(size_bytes / (1024**3), 2)} GB"
        else: 
            size_str = f"{round(size_bytes / (1024**2), 2)} MB"
        
        # Процент = (размер папки / общий объем физического диска) * 100
        # Percentage = (folder size / total physical disk space) * 100
        percent = round((size_bytes / total) * 100, 1) if total > 1 else 0
        share_stats.append({'name': s['name'], 'size': size_str, 'bytes': size_bytes, 'percent': percent})
    # Сортируем от самых тяжелых к легким
    # Sort from heaviest to lightest
    share_stats.sort(key=lambda x: x['bytes'], reverse=True)

    # 5. Запрос юзеров
    # 5. User query
    users, _ = run_ps("Get-ADUser -Filter * | Select-Object SamAccountName")
    total_users = len([u for u in users if isinstance(u, dict)]) if users else 0

    storage_used_gb = round(used / (1024**3), 2)
    return {
        "kpi": {
            "users": total_users,
            "sessions": active_sessions,
            "shares": len(share_stats),
            "storage_tb": f"{storage_used_gb} GB"
        },
        "shares_list": share_stats,
        "logs": logs
    }

@bp_dashboard.route('/audit')
def audit():
    return render_template('audit.html')

@bp_dashboard.route('/export/audit/csv')
def export_audit_csv():
    # Генерация CSV-отчета об уязвимостях
    # Generate CSV vulnerability report
    script = "Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, PasswordNotRequired, PasswordNeverExpires, LockedOut | Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, PasswordNotRequired, PasswordNeverExpires, LockedOut"
    users, _ = run_ps(script)
    
    issues = []
    if users:
        users = [u for u in users if isinstance(u, dict)]
        now = datetime.now(timezone.utc)
        
        for u in users:
            if u.get('LockedOut'):
                issues.append([u.get('Name'), u.get('SamAccountName'), 'Учетка ЗАБЛОКИРОВАНА', 'ВНИМАНИЕ'])
            if u.get('PasswordNotRequired'):
                issues.append([u.get('Name'), u.get('SamAccountName'), 'Разрешен пустой пароль', 'КРИТИЧНО'])
            if u.get('PasswordNeverExpires'):
                issues.append([u.get('Name'), u.get('SamAccountName'), 'Пароль бессрочный', 'ВНИМАНИЕ'])

            logon = parse_ms_date(u.get('LastLogonDate'))
            if logon and (now - logon).days > 90:
                issues.append([u.get('Name'), u.get('SamAccountName'), f'Не входил {(now - logon).days} дней', 'ВНИМАНИЕ'])
                
            pwd = parse_ms_date(u.get('PasswordLastSet'))
            if pwd and (now - pwd).days > 180:
                issues.append([u.get('Name'), u.get('SamAccountName'), f'Пароль не менялся {(now - pwd).days} дней', 'ВНИМАНИЕ'])

    # Создаем виртуальный файл в оперативной памяти
    # Create a virtual file in RAM
    output = io.StringIO()
    # Добавляем BOM-маркер, чтобы Microsoft Excel правильно открывал русские буквы
    # Add a BOM marker so that Microsoft Excel correctly opens Russian letters
    output.write('\ufeff')
    
    writer = csv.writer(output, delimiter=';')
    # Пишем заголовок таблицы
    # Write the table header
    writer.writerow(['Имя пользователя', 'Логин', 'Описание уязвимости', 'Уровень угрозы'])
    # Пишем данные
    # Writing data
    writer.writerows(issues)

    # Отдаем файл браузеру с командой "Скачать"
    # Send the file to the browser with the "Download" command
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=Security_Audit_{timestamp}.csv"}
    )

@bp_dashboard.route('/topology')
def topology_page():
    return render_template('topology.html')

@bp_dashboard.route('/api/topology_data')
def api_topology_data():
    # Сбор данных о сессиях Samba в формате JSON для построения графа
    # Collect Samba session data in JSON format to build a graph
    nodes = [{"id": "samba_server", "label": "Samba Server\n(Debian 13)", "shape": "box", "color": "#dc3545", "font": {"color": "white"}}]
    edges = []
    
    try:
        # У Samba есть ключ -j для вывода статуса в JSON
        # Samba has a -j switch to output the status in JSON
        out = subprocess.check_output(['smbstatus', '-j'], text=True)
        smb_data = json.loads(out)
        
        clients = {}
        active_shares = set()
        
        # 1. Парсим клиентов (Сессии)
        # 1. Parsing clients (Sessions)
        for sess_id, sess_info in smb_data.get('sessions', {}).items():
            machine = sess_info.get('remote_machine', 'Unknown')
            user = sess_info.get('username', 'Unknown')
            
            # Ищем протокол по всем возможным ключам разных версий Samba
            # Search for the protocol using all possible keys of different versions of Samba
            proto = sess_info.get('protocol_version') or sess_info.get('protocol') or sess_info.get('session_dialect') or 'SMB'
            
            client_id = f"client_{machine}"
            if client_id not in clients:
                nodes.append({
                    "id": client_id, 
                    "label": f"💻 Клиент\nIP: {machine}\nЮзер: {user}", 
                    "shape": "ellipse", 
                    "color": "#0dcaf0"
                })
                clients[client_id] = proto # Запоминаем точный протокол /\ Remember the exact protocol
                
        # 2. Парсим подключения к папкам (Tcons)
        # 2. Parsing folder connections (Tcons)
        for tcon_id, tcon_info in smb_data.get('tcons', {}).items():
            machine = tcon_info.get('machine', 'Unknown')
            share = tcon_info.get('service', 'Unknown')
            
            # Пропускаем скрытые системные шары (IPC$)
            # Skipping hidden system shares (IPC$)
            if share == 'IPC$': continue
                
            share_id = f"share_{share}"
            
            # Добавляем узел шары (если еще не добавили)
            # Add the share node (if haven't added it yet)
            if share_id not in active_shares:
                nodes.append({
                    "id": share_id, 
                    "label": f"📁 Папка\n[{share}]", 
                    "shape": "database", 
                    "color": "#ffc107"
                })
                active_shares.add(share_id)
                
                # Соединяем Сервер -> Шара
                # Connect Server -> Share
                edges.append({"from": "samba_server", "to": share_id, "color": "#475569", "dashes": True})
                
            # Соединяем Клиент -> Шара
            # Connect Client -> Share
            client_id = f"client_{machine}"
            proto = clients.get(client_id, "SMB")
            edges.append({
                "from": client_id, 
                "to": share_id, 
                "label": proto, # Подписываем стрелку версией протокола (например, SMB3_11) /\ Sign the arrow with the protocol version (for example, SMB3_11)
                "color": "#20c997",
                "arrows": "to",
                "font": {"color": "#fff", "strokeWidth": 0, "align": "middle"}
            })
            
    except Exception as e:
        print(f"Ошибка парсинга smbstatus: {e}")
        # Если никого нет, возвращаем только сервер
        # If there is no one, return only the server
        pass

    return {"nodes": nodes, "edges": edges}

@bp_dashboard.route('/api/services_status')
def api_services_status():
    # Получает вывод systemctl status для служб Samba
    # Gets the output of systemctl status for Samba services
    try:
        # Запрашиваем статус трех служб, обрезаем до 15 строк каждую, чтобы не перегружать экран
        # Request the status of three services, cutting each to 15 lines to avoid overloading the screen
        result = subprocess.check_output(
            ["systemctl", "status", "smbd", "nmbd", "winbind", "--lines=10"], 
            stderr=subprocess.STDOUT, text=True
        )
        return {"output": result}
    except subprocess.CalledProcessError as e:
        # Если служба упала, systemctl возвращает ошибку, но текст все равно нужен
        # If the service crashes, systemctl returns an error, but the text is still needed
        return {"output": e.output}
    except Exception as e:
        return {"output": f"Внутренняя ошибка: {str(e)}"}

@bp_dashboard.route('/api/service_restart/<svc_name>', methods=['POST'])
def api_service_restart(svc_name):
    # Перезапуск конкретной службы
    # Restart a specific service
    allowed_services = ['smbd', 'nmbd', 'winbind', 'samba-ad-dc']
    if svc_name not in allowed_services and svc_name != 'all':
        return {"status": "error", "msg": "Недопустимая служба"}
    try:
        if svc_name == 'all':
            subprocess.run(["systemctl", "restart", "smbd", "nmbd", "winbind"], check=True)
        else:
            subprocess.run(["systemctl", "restart", svc_name], check=True)
        return {"status": "success", "msg": "Команда выполнена"}
    except Exception as e:
        return {"status": "error", "msg": str(e)}

@bp_dashboard.route('/api/execute_command', methods=['POST'])
def api_execute_command():
    # Web-Терминал для Debian, Windows CMD и Windows PowerShell
    # Web Terminal for Debian, Windows CMD and Windows PowerShell
    data = request.json
    target = data.get('target')
    command = data.get('command')
    
    if not command:
        return {"status": "error", "output": "Команда не может быть пустой"}
        
    try:
        if target == 'debian':
            # Выполнение локально в Bash (с таймаутом 15 сек, чтобы не повесить сервер)
            # Execute locally in Bash (with a 15-second timeout to avoid crashing the server)
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
            output = result.stdout if result.returncode == 0 else result.stderr
            if not output: output = "Команда выполнена (нет вывода)"
            return {"status": "success" if result.returncode == 0 else "error", "output": output.strip()}
            
        elif target in ['win_ps', 'win_cmd']:
            import winrm
            # Выполнение на Windows через WinRM (сырой вывод)
            # Execution on Windows via WinRM (raw output)
            session = winrm.Session(Config.AD_SERVER, auth=(Config.DOMAIN_USER, Config.PASSWORD), transport=Config.AUTH_METHOD)
            
            if target == 'win_ps':
                result = session.run_ps(command)
            else:
                result = session.run_cmd(command)
                
            output = result.std_out.decode('cp866' if target == 'win_cmd' else 'utf-8', errors='ignore').strip()
            err_output = result.std_err.decode('cp866' if target == 'win_cmd' else 'utf-8', errors='ignore').strip()
            
            final_out = output if result.status_code == 0 else err_output
            if not final_out: final_out = "Команда выполнена (нет вывода)"
            
            return {"status": "success" if result.status_code == 0 else "error", "output": final_out}
        else:
            return {"status": "error", "output": "Неизвестный целевой хост"}
            
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": "Превышено время ожидания (15 сек). Процесс убит."}
    except Exception as e:
        return {"status": "error", "output": str(e)}

@bp_dashboard.route('/help')
def help_page():
    return render_template('help.html')

@bp_dashboard.route('/api/audit_data')
def api_audit_data():
    """API для асинхронного обновления дашборда"""
    import shutil
    
    # 1. Расчет места на диске в ГБ и %
    # 1. Calculating disk space in GB and %
    try:
        total, used, free = shutil.disk_usage('/srv/samba')
        disk_percent = round((used / total) * 100, 1)
        total_gb = round(total / (1024**3), 2)
        used_gb = round(used / (1024**3), 2)
    except:
        disk_percent, total_gb, used_gb = 0, 0, 0

    # 2. Взвешиваем каждую шару Samba
    # 2. Weigh each Samba ball
    share_stats =[]
    for s in get_samba_shares():
        size_bytes = get_dir_size(s['path'])
        # Если больше гигабайта — пишем GB, иначе MB
        # If it's more than a gigabyte, write GB, otherwise MB
        if size_bytes > 1024**3:
            size_str = f"{round(size_bytes / (1024**3), 2)} GB"
        else:
            size_str = f"{round(size_bytes / (1024**2), 2)} MB"
        share_stats.append({'name': s['name'], 'size': size_str, 'bytes': size_bytes})
    
    # Сортируем шары от тяжелых к легким
    # Sort the balls from heavy to light
    share_stats.sort(key=lambda x: x['bytes'], reverse=True)

    # 3. Запрос ИБ-данных из Windows
    # 3. Requesting information security data from Windows
    ps_script = "Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, PasswordNotRequired, PasswordNeverExpires, LockedOut | Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, PasswordNotRequired, PasswordNeverExpires, LockedOut"
    users, err = run_ps(ps_script)
    
    if err: return {"error": f"Ошибка: {err}"}
    if not users: return {"error": "Нет данных"}
    # Фильтруем только успешные ответы
    # Filter only successful responses
    users =[u for u in users if isinstance(u, dict)]
    
    # Загружаем список администраторов (для проверки количества)
    # Loading the list of administrators (to check the number)
    admins, admin_err = run_ps("Get-ADGroupMember -Identity 'Администраторы домена' | Select-Object SamAccountName")
    if admin_err: admins, _ = run_ps("Get-ADGroupMember -Identity 'Domain Admins' | Select-Object SamAccountName")
    admin_count = len([a for a in admins if isinstance(a, dict)]) if admins else 0

    # Инициализация статистики
    # Initialize statistics
    stats = {'total': len(users), 'active': 0, 'disabled': 0, 'locked': 0, 
             'disk_percent': disk_percent, 'used_gb': used_gb, 'total_gb': total_gb}
    issues =[] # Список найденных проблем /\ List of problems found
    now = datetime.now(timezone.utc)

    for u in users: # Цикл анализа каждого пользователя /\ Analysis cycle for each user
        if u.get('Enabled'): stats['active'] += 1 # Считаем активных/неактивных /\ Counting active/inactive
        else: stats['disabled'] += 1

        if u.get('LockedOut'):
            stats['locked'] += 1
            issues.append({'user': u.get('Name'), 'login': u.get('SamAccountName'), 'issue': 'Учетка ЗАБЛОКИРОВАНА', 'severity': 'danger'})
        if u.get('PasswordNotRequired'):
            issues.append({'user': u.get('Name'), 'login': u.get('SamAccountName'), 'issue': 'Разрешен пустой пароль', 'severity': 'danger'})
        if u.get('PasswordNeverExpires'):
            issues.append({'user': u.get('Name'), 'login': u.get('SamAccountName'), 'issue': 'Пароль бессрочный', 'severity': 'warning'})

        logon = parse_ms_date(u.get('LastLogonDate'))
        if logon and (now - logon).days > 90:
            issues.append({'user': u.get('Name'), 'login': u.get('SamAccountName'), 'issue': f'Не входил {(now - logon).days} дней', 'severity': 'warning'})

        pwd = parse_ms_date(u.get('PasswordLastSet'))
        if pwd and (now - pwd).days > 180:
            issues.append({'user': u.get('Name'), 'login': u.get('SamAccountName'), 'issue': f'Пароль не менялся {(now - pwd).days} дней', 'severity': 'warning'})

    if admin_count > 2:
        issues.insert(0, {'user': 'СИСТЕМА', 'login': 'Домен', 'issue': f'Слишком много админов ({admin_count}). Нарушение Zero Trust.', 'severity': 'danger'})

    return {"stats": stats, "issues": issues, "shares": share_stats}

@bp_dashboard.route('/health')
def health():
    return jsonify(
        status='OK',
        timestamp=datetime.now(timezone.utc).isoformat(),
        version='1.0.0',
        auth_module=Config.AUTH_METHOD.upper()
    ), 200