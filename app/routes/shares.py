from flask import Blueprint, render_template, request, redirect, url_for, flash
import os
import subprocess
import shutil
from app.core.ad_client import run_ps
from app.core.samba_mgr import get_samba_shares
from app.core.logger import log_action

bp_shares = Blueprint('shares', __name__)

@bp_shares.route('/shares')
def shares_page():
    # Получаем список шар из конфига
    # Get a list of shares from the config
    smb_shares = get_samba_shares()
    # Получаем группы из AD для выпадающего списка (кому дать доступ)
    # Get groups from AD for the drop-down list (who to grant access to)
    groups_data, _ = run_ps("Get-ADGroup -Filter * -Properties DistinguishedName | Where-Object { $_.DistinguishedName -notmatch 'CN=Builtin' } | Select-Object Name")
    all_groups =[g for g in groups_data if isinstance(g, dict)] if groups_data else[]
    # Получаем пользователей для выпадающего списка
    # Get users for the drop-down list
    users_data, _ = run_ps("Get-ADUser -Filter * | Select-Object SamAccountName, Name")
    all_users =[u for u in users_data if isinstance(u, dict)] if users_data else[]
    
    
    return render_template('shares.html', shares=smb_shares, all_groups=groups_data, all_users=users_data)

@bp_shares.route('/add_share', methods=['POST'])
def add_share():
    share_name = request.form.get('share_name').strip()
    folder_path = request.form.get('folder_path').strip()
    
    # Списки для разделения прав
    # Lists for separating rights
    ro_groups = request.form.getlist('ro_groups') 
    ro_users = request.form.getlist('ro_users')
    rw_groups = request.form.getlist('rw_groups') 
    rw_users = request.form.getlist('rw_users')
    is_hidden = bool(request.form.get('is_hidden'))
    allowed_ips = request.form.get('allowed_ips', '').strip()

    try:
        # === ВАЛИДАЦИЯ ===
        # === VALIDATION ===
        # Запрещаем расшаривать корень
        # Prohibit root sharing
        if os.path.normpath(folder_path) == '/srv/samba':
            flash("Ошибка: Запрещено открывать сетевой доступ к корневой системной директории /srv/samba!", "danger")
            return redirect(url_for('shares.shares_page'))

        if os.path.normpath(folder_path) == '/srv':
            flash("Ошибка: Запрещено открывать сетевой доступ к корневой системной директории /srv!", "danger")
            return redirect(url_for('shares.shares_page'))

        if os.path.normpath(folder_path) == '/':
            flash("Ошибка: Запрещено открывать сетевой доступ к корневой системной директории /!", "danger")
            return redirect(url_for('shares.shares_page'))

        existing_shares = get_samba_shares()
        if any(s['name'].lower() == share_name.lower() for s in existing_shares):
            flash(f"Ошибка: Сетевой ресурс с именем [{share_name}] уже существует!", "danger")
            return redirect(url_for('shares.shares_page'))
            
        abs_new_path = os.path.abspath(folder_path)
        if any(os.path.abspath(s['path']) == abs_new_path for s in existing_shares if s['path']):
            flash(f"Ошибка: Путь {folder_path} уже привязан к другой сетевой папке!", "danger")
            return redirect(url_for('shares.shares_page'))

        # 1. Создаем папку и локальную группу
        # 1. Create a folder and a local group
        os.makedirs(folder_path, exist_ok=True)
        local_group = f"smb_{share_name.lower().replace(' ', '_')}"
        subprocess.run(["groupadd", "-f", local_group], check=False)
        subprocess.run(["chown", "-R", f"root:{local_group}", folder_path], check=True)
        subprocess.run(["chmod", "-R", "2770", folder_path], check=True)

        # 2. Формируем списки доступа
        # В valid_users (имеют доступ) добавляем ВСЕХ: и тех кто читает, и тех кто пишет
        # 2. Create access lists
        # Add EVERYONE to valid_users (those who have access): both those who read and those who write
        all_groups = list(set(ro_groups + rw_groups))
        all_users = list(set(ro_users + rw_users))

        # valid_list = [f'@"{g}"' for g in all_groups] + [f'"{u}"' for u in all_users]
        # valid_str = ", ".join(valid_list)
        # В write_list добавляем ТОЛЬКО тех, кому можно писать
        # Add ONLY those who can write to the write_list
        # write_list = [f'@"{g}"' for g in rw_groups] + [f'"{u}"' for u in rw_users]
        # write_str = ", ".join(write_list)
        
        valid_str = ", ".join([f'@"{g}"' for g in all_groups] + [f'"{u}"' for u in all_users])
        write_str = ", ".join([f'@"{g}"' for g in rw_groups] + [f'"{u}"' for u in rw_users])

        # 3. Запись в конфиг
        # 3. Writing to the config
        with open('/etc/samba/smb.conf', 'a') as f:
            f.write(f"\n[{share_name}]\n")
            f.write(f"    path = {folder_path}\n")
            f.write(f"    read only = Yes\n") # По умолчанию всем только чтение /\ By default, everyone reads only
            
            if is_hidden: f.write(f"    browseable = No\n")
            if allowed_ips: f.write(f"    hosts allow = {allowed_ips}\n")
            if valid_str: f.write(f"    valid users = {valid_str}\n")
            if write_str: f.write(f"    write list = {write_str}\n")
                
            f.write(f"    force group = {local_group}\n")
            f.write(f"    create mask = 0660\n")
            f.write(f"    directory mask = 2770\n")
            f.write(f"    vfs objects = recycle\n")
            f.write(f"    recycle:repository = .Корзина\n")
            f.write(f"    recycle:keeptree = yes\n")
            f.write(f"    recycle:versions = yes\n")

        subprocess.run(["systemctl", "restart", "smbd", "nmbd", "winbind"], check=False)
        log_action('Создание шары', f'[{share_name}] (RO: {len(ro_groups+ro_users)}, RW: {len(rw_groups+rw_users)})')
        flash(f"Шара [{share_name}] успешно создана!", "success")
    except Exception as e:
        flash(f"Ошибка создания: {e}", "danger")
        
    return redirect(url_for('shares.shares_page'))

@bp_shares.route('/delete_share/<share_name>')
def delete_share(share_name):
    # Удаление шары из конфига И физическое удаление папки с диска
    # Removing the share from the config and physically deleting the folder from the disk
    try:
        # Сначала находим информацию о шаре (нам нужен её path)
        # First, we find information about the share (we need its path)
        shares = get_samba_shares()
        target_share = next((s for s in shares if s['name'] == share_name), None)

        # 1. Удаляем из конфига Samba
        # 1. Remove data from the Samba config
        with open('/etc/samba/smb.conf', 'r') as f:
            lines = f.readlines()    
        with open('/etc/samba/smb.conf', 'w') as f:
            skip = False
            for line in lines:
                if line.strip() == f"[{share_name}]":
                    skip = True
                elif skip and line.startswith('['):
                    skip = False    
                if not skip:
                    f.write(line)
                    
        subprocess.run(["smbcontrol", "all", "reload-config"])

        # 2. Физическое удаление папки и данных
        # 2. Physically delete the folder and data
        if target_share and target_share['path']:
            folder_to_delete = os.path.abspath(target_share['path'])

            # ЗАЩИТА "ОТ ДУРАКА": Удаляем только если путь длиннее 6 символов и находится в /srv/ 
            # (Чтобы случайно не выполнить rm -rf / или rm -rf /etc)
            # FOOL-PROOF: Delete only if the path is longer than 6 characters and is located in /srv/
            # (To prevent accidentally executing rm -rf / or rm -rf /etc)
            if len(folder_to_delete) > 6 and "/srv/" in folder_to_delete:
                shutil.rmtree(folder_to_delete, ignore_errors=True)
                # Удаляем служебную группу Linux
                # Remove the Linux service group
                local_group = f"smb_{share_name.lower().replace(' ', '_')}"
                subprocess.run(["groupdel", local_group], check=False)
                flash(f"Ресурс [{share_name}] и все его файлы физически удалены с сервера.", "success")
                log_action('Удаление шары', f'Папка [{share_name}]')
            else:
                flash(f"Ресурс [{share_name}] отключен, но папка сохранена ради безопасности (системный путь).", "warning")
                log_action('Удаление шары', f'Папка [{share_name}]')
        else:
            flash(f"Ресурс [{share_name}] отключен.", "success")
            log_action('Удаление шары', f'Папка [{share_name}]')
    except Exception as e:
        flash(f"Ошибка удаления: {e}", "danger")
        
    return redirect(url_for('shares.shares_page'))

@bp_shares.route('/share/<share_name>')
def share_profile(share_name):
    shares = get_samba_shares()
    # Находим шару по имени
    # Find a share by name
    share = next((s for s in shares if s['name'] == share_name), None)
    if not share: return redirect(url_for('shares.shares_page'))

    # Обработка подпути (для навигации внутри шары)
    # Subpath handling (for navigation inside the share)    
    subpath = request.args.get('path', '').strip('/')
    base_path = os.path.abspath(share['path'])
    target_path = os.path.abspath(os.path.join(base_path, subpath))
    
    # Проверка на выход за пределы
    # Check for out of bounds
    if not target_path.startswith(base_path):
        flash("Доступ за пределы шары запрещен!", "danger")
        return redirect(url_for('shares.share_profile', share_name=share_name))

    # Гарантируем наличие папки корзины
    # Guarantee the presence of a trash folder
    os.makedirs(os.path.join(base_path, '.Корзина'), exist_ok=True)

    # Загружаем список файлов
    # Loading a list of files
    files =[]
    if os.path.exists(target_path):
        try:
            for f in os.listdir(target_path):
                full_p = os.path.join(target_path, f)
                is_dir = os.path.isdir(full_p)
                # Размер только для файлов, для папок — "-"
                # Size only for files, for folders - "-"
                size = f"{os.path.getsize(full_p) // 1024} KB" if not is_dir else "-"
                files.append({'name': f, 'is_dir': is_dir, 'size': size})
        except: pass
    # Сортировка: папки первыми, затем по имени
    # Sort by: folders first, then by name
    files.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

    # Загружаем списки групп и пользователей из AD (для управления правами)
    # Load lists of groups and users from AD (for rights management)
    groups_data, _ = run_ps("Get-ADGroup -Filter * -Properties DistinguishedName | Where-Object { $_.DistinguishedName -notmatch 'CN=Builtin' } | Select-Object Name")
    all_groups = [g['Name'] for g in groups_data if isinstance(g, dict)] if groups_data else[]
    
    users_data, _ = run_ps("Get-ADUser -Filter * | Select-Object SamAccountName, Name")
    all_users = [u for u in users_data if isinstance(u, dict)] if users_data else[]
    
    return render_template('share_profile.html', share=share, files=files, all_groups=all_groups, all_users=all_users, current_path=subpath)

@bp_shares.route('/share/<share_name>/update_groups', methods=['POST'])
def update_share_groups(share_name):
    # Получаем новые списки
    # Getting new lists
    ro_groups = request.form.getlist('ro_groups') 
    ro_users = request.form.getlist('ro_users')
    rw_groups = request.form.getlist('rw_groups') 
    rw_users = request.form.getlist('rw_users')
    
    is_hidden = bool(request.form.get('is_hidden'))
    allowed_ips = request.form.get('allowed_ips', '').strip()

    try:
        with open('/etc/samba/smb.conf', 'r') as f:
            lines = f.readlines()
            
        with open('/etc/samba/smb.conf', 'w') as f:
            in_target = False
            for line in lines:
                stripped = line.strip()
                if stripped == f"[{share_name}]":
                    in_target = True
                    f.write(line)
                    
                    # Как только нашли нашу шару, сразу вписываем новые права под ней
                    # As soon as find share, immediately enter new rights under it
                    all_groups = list(set(ro_groups + rw_groups))
                    all_users = list(set(ro_users + rw_users))
                    valid_list = [f'@"{g}"' for g in all_groups] + [f'"{u}"' for u in all_users]
                    write_list = [f'@"{g}"' for g in rw_groups] + [f'"{u}"' for u in rw_users]
                    
                    f.write(f"    read only = Yes\n")
                    if is_hidden: f.write(f"    browseable = No\n")
                    if allowed_ips: f.write(f"    hosts allow = {allowed_ips}\n")
                    if valid_list: f.write(f"    valid users = {', '.join(valid_list)}\n")
                    if write_list: f.write(f"    write list = {', '.join(write_list)}\n")
                    continue
                
                if in_target and line.startswith('['):
                    in_target = False
                    
                #if in_target:
                    # Пропускаем старые строки с правами, так как мы записали новые выше
                    # Skip the old lines with rights, since wrote the new ones above
                    # if stripped.startswith('valid users') or stripped.startswith('write list') or \
                    #   stripped.startswith('read only') or stripped.startswith('browseable') or \
                    #   stripped.startswith('hosts allow'):
                    #     continue
                    
                if in_target and any(stripped.startswith(k) for k in ['valid users', 'write list', 'read only', 'browseable', 'hosts allow']):
                    continue
                        
                f.write(line)
        
        # Перезагружаем Samba
        # Restart Samba
        subprocess.run(["systemctl", "restart", "smbd", "nmbd", "winbind"], check=False)
        log_action('Изменение прав', f'[{share_name}]')
        flash(f"Права для [{share_name}] обновлены!", "success")
        
    except Exception as e:
        flash(f"Ошибка обновления прав: {e}", "danger")
        
    return redirect(url_for('shares.share_profile', share_name=share_name))