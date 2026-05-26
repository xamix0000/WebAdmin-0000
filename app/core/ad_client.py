import winrm
import json
import base64
import subprocess
import re
import threading
from datetime import datetime, timezone
from app.config import Config

# Создаем глобальный семафор для управления потоками
ad_lock = threading.Lock()

# parse_ms_date Преобразует строку времени из формата Active Directory / JSON
# AD отдает миллисекунды в /Date(), python работает с секундами
# Учитываем UTC, убираем обертку

# parse_ms_date Converts a time string from Active Directory/JSON format
# AD returns milliseconds in /Date(), Python works with seconds
# Takes UTC into, removes the wrapper

def parse_ms_date(ms_date_str): 
    # Быстрая проверка на пустоту или неверный тип
    # Quick check for empty or invalid type
    if not ms_date_str or not isinstance(ms_date_str, str): return None
    # Вырезаем "/Date(" и ")/", оставляем только цифры
    # Cut out "/Date(" and ")/", leaving only the numbers
    try: 
        return datetime.fromtimestamp(int(ms_date_str.replace('/Date(', '').replace(')/', '')) / 1000.0, tz=timezone.utc)
    except: return None

def get_kerberos_ticket():
    # 1. Проверяем наличие валидного билета в кэше ОС
    # Команда klist -s возвращает код 0, если билет есть и он еще действует
    # 1. Check for a valid ticket in the OS cache
    # The klist -s command returns code 0 if the ticket exists and is still valid.
    if subprocess.run(['klist', '-s']).returncode == 0:
        return # Билет жив, пропускаем ресурсоемкий kinit /\ Ticket is alive, skipping the resource-intensive kinit

    try:
        # Разбиваем Администратор@diplom.local на 'Администратор' и 'diplom.local'
        # Split Administrator@diplom.local into 'Administrator' and 'diplom.local'
        user, domain = Config.DOMAIN_USER.split('@')
        # Kerberos требует, чтобы домен был СТРОГО ЗАГЛАВНЫМИ БУКВАМИ!
        # Kerberos requires the domain to be ALL CAPS!
        principal = f"{user}@{domain.upper()}"
        
        # 2. Обязательно добавляем \n (Enter) к паролю, иначе kinit может зависнуть, ожидая ввода
        # 3. Ставим timeout=5, чтобы предотвратить бесконечные зависания потоков
        # 2. Be sure to add \n (Enter) to the password, otherwise kinit may freeze while waiting for input.
        # 3. Set timeout=5 to prevent threads from hanging indefinitely.
        subprocess.run(
            ['kinit', principal], 
            input=f"{Config.PASSWORD}\n", 
            text=True, 
            capture_output=True, 
            check=True,
            timeout=5
        )
    except subprocess.CalledProcessError as e:
        print(f"[Kerberos] Ошибка получения билета: {e.stderr}")

#run_ps устанавливает сессию с Windows
#PowerShell в WinRM ломает русские буквы
#Мы пакуем ответ в Base64 внутри Windows, передаем по сети и Python её распаковывает
#Мы заставляем PowerShell всегда отвечать в JSON. Это позволяет Python работать с данными не как с текстом, а как со списками и словарями
#CLIXML мусор - используем $ProgressPreference = 'SilentlyContinue', чтобы системные полоски загрузки Windows не попадали в текст ошибок

#run_ps establishes a Windows session
#PowerShell in WinRM breaks Russian letters
#We pack the response in Base64 within Windows, transfer it over the network, and Python unpacks it
#We force PowerShell to always respond in JSON. This allows Python to work with data as lists and dictionaries rather than as text
#CLIXML is garbage - we use $ProgressPreference = 'SilentlyContinue' to prevent Windows system progress bars from appearing in error messages

def run_ps(script):
    """Выполнение PowerShell с JSON-оберткой для чистых ошибок без CLIXML"""
    """Executing PowerShell with a JSON wrapper for clean errors without CLIXML"""
    with ad_lock:
        try:
            # Создаём сессию к удалённому серверу
            # session = winrm.Session(AD_SERVER, auth=(DOMAIN_USER, PASSWORD), transport=AUTH_METHOD) # Можно kerberos, установить pykerberos

            # Create a session to the remote server
            # session = winrm.Session(AD_SERVER, auth=(DOMAIN_USER, PASSWORD), transport=AUTH_METHOD) # Kerberos is possible; install pykerberos
            
            # 1. Запрашиваем криптографический билет у контроллера домена
            # 1. Request a cryptographic ticket from the domain controller
            get_kerberos_ticket()
            
            # 2. Подключаемся ТОЛЬКО по FQDN-имени и с билетом (пароль по сети больше не летит)
            # 2. Connect ONLY by FQDN name and with a ticket (the password no longer flies over the network)
            
            #if Config.AUTH_METHOD.lower() == 'kerberos':
            #    session = winrm.Session(
            #        Config.AD_SERVER_FQDN, 
            #        transport='kerberos',
            #        operation_timeout_sec=15,
            #        read_timeout_sec=20,
            #        server_cert_validation='ignore'
            #    )
            #else: # Other protocol
            #    session = winrm.Session(
            #        Config.AD_SERVER_FQDN, 
            #        auth=(Config.DOMAIN_USER, Config.PASSWORD), 
            #        transport='ntlm',
            #        operation_timeout_sec=15,
            #        read_timeout_sec=20,
            #        server_cert_validation='ignore'
            #    )
            session = winrm.Session(
            Config.AD_SERVER_FQDN, 
            auth=(Config.DOMAIN_USER, Config.PASSWORD), 
            transport=Config.AUTH_METHOD, 
            operation_timeout_sec=15, 
            read_timeout_sec=20,
            server_cert_validation='ignore')
            
            wrapped_script = f"""
            $ProgressPreference = 'SilentlyContinue'
            $ErrorActionPreference = 'Stop'
            
            try {{
                # Выполняем скрипт, который передал python
                # Execute the script passed to python
                $res = {script}
                if ($null -eq $res) {{ $res = @() }}
                # Упаковываем успешный ответ
                # Packing a successful response
                $output = @{{ success = $true; data = $res }}
            }} catch {{
                # Упаковываем чистую ошибку
                # Packing a clean error
                $output = @{{ success = $false; error = $_.Exception.Message }}
            }}
            # Конвертируем словарь $output в компактную JSON-строку
            # Convert the $output dictionary into a compact JSON string
            $json = ConvertTo-Json -InputObject $output -Compress -Depth 10
            $bytes =[System.Text.Encoding]::UTF8.GetBytes($json)
            [Convert]::ToBase64String($bytes)
            """
            # run_ps() выполняет скрипт и возвращает объект с полями:
            #   status_code: 0 = успех, !=0 = ошибка выполнения
            #   std_out: стандартный вывод 
            #   std_err: стандартный вывод ошибок
            # run_ps() executes the script and returns an object with the following fields:
            #   status_code: 0 = success, !=0 = execution error
            #   std_out: standard output
            #   std_err: standard error output
            
            result = session.run_ps(wrapped_script)

            if result.status_code == 0:
                b64_str = result.std_out.decode('utf-8').strip()
                if not b64_str: return[], None
                
                parsed = json.loads(base64.b64decode(b64_str).decode('utf-8'))
                
                # Проверяем флаг успеха
                # Checking the success flag
                if parsed.get('success'):
                    data = parsed.get('data')
                    return [data] if isinstance(data, dict) else data, None
                else:
                    # Возвращаем чистую ошибку
                    # Return a clean error
                    return[], parsed.get('error')
            else:
                # На случай критического падения самого WinRM (вырезаем теги XML)
                # In case of a critical crash of WinRM itself (cut out XML tags)
                raw_err = result.std_err.decode('utf-8', errors='ignore')
                clean_err = re.sub(r'<[^>]+>', '', raw_err).strip()
                print(f"[DEBUG-WINRM] Критическая ошибка WinRM: {clean_err}")
                return[], clean_err
    # Ловим любые исключения, которые могли возникнуть
    # Catch any exceptions that may have occurred
        except Exception as e:
            print(f"[ОШИБКА СВЯЗИ WINRM]: {e}")
            return [], str(e)