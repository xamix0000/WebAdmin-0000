import os
from flask import flash

"""Алгоритм:
    1. Читаем файл построчно
    2. Ищем секции в формате [share_name]
    3. Пропускаем системные: [global], [printers], [homes], [sysvol], [netlogon]
    4. Для каждой шары извлекаем:
       name — имя секции
       path — путь к папке
       valid users — список групп (@Group) и пользователей (User)"""
"""Algorithm:
    1. Read the file line by line.
    2. Search for sections in the format [share_name]
    3. Skip system sections: [global], [printers], [homes], [sysvol], [netlogon]
    4. For each share, extract:
        name — section name
        path — folder path
        valid users — list of groups (@Group) and users (User)"""

def get_samba_shares():
    # Парсинг файла smb.conf для получения списка шар
    # Parsing the smb.conf file to get a list of shares
    shares =[]
    current_share = None
    try:
        with open('/etc/samba/smb.conf', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    name = line[1:-1]
                    if name.lower() not in ['global', 'printers', 'homes', 'sysvol', 'netlogon']:
                        current_share = {'name': name, 'path': '', 'groups': [], 'users': [], 
                                         'write_groups': [], 'write_users': [], 'hidden': False, 'hosts': ''}
                        shares.append(current_share)
                elif current_share and '=' in line:
                    key, val = map(str.strip, line.split('=', 1))
                    if key == 'path': current_share['path'] = val
                    elif key == 'browseable' and val.lower() == 'no': current_share['hidden'] = True
                    elif key == 'hosts allow': current_share['hosts'] = val
                    elif key in ['valid users', 'write list']:
                        # Разделяем группы (с @) и юзеров (без @)
                        # Separate groups (with @) and users (without @)
                        clean_str = val.replace('"', '').replace("'", "")
                        parts = [p.strip() for p in clean_str.split(',') if p.strip()]
                        grps = [p[1:] for p in parts if p.startswith('@')]
                        usrs = [p for p in parts if not p.startswith('@')]
                        
                        if key == 'valid users':
                            current_share['groups'] = grps
                            current_share['users'] = usrs
                        else: # write list
                            current_share['write_groups'] = grps
                            current_share['write_users'] = usrs
    except Exception as e:
        flash(f"Ошибка чтения smb.conf: {e}", "danger")
    return shares

"""Алгоритм:
    1. Проверяем существование пути
    2. os.walk() — обход дерева каталогов (рекурсивно)
    3. Для каждого файла:
       os.path.islink() — пропускаем симлинки (чтобы не считать дважды / не уйти в цикл)
       os.path.getsize() — получаем размер в байтах
       Суммируем в total_size"""

"""Algorithm:
    1. Check for the existence of the path
    2. os.walk() — traverse the directory tree (recursively)
    3. For each file:
        os.path.islink() — skip symbolic links (to avoid double counting/loop)
        os.path.getsize() — get the size in bytes
        Summarize into total_size"""

def get_dir_size(start_path):
    # Рекурсивно вычисляет размер папки в байтах
    # Recursively calculates the size of the folder in bytes
    total_size = 0
    if not os.path.exists(start_path):
        return 0
    for dirpath, _, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size