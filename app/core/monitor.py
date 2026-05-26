import psutil
import time
import threading
from datetime import datetime
from app.core.ad_client import run_ps

# Глобальный кэш
# Global cache
SYSTEM_CACHE = {
    "debian": {"cpu": 0, "cores": 0, "ram": 0, "ram_used": 0, "ram_total": 0, "status": "Ожидание...", "uptime": "...", "net_in": 0, "net_out": 0, "disk_read": 0, "disk_write": 0},
    "windows": {"cpu": 0, "cores": 0, "ram": 0, "ram_used": 0, "ram_total": 0, "status": "Ожидание..."}
}

def update_debian_stats():
    # Поток 1: Обновляет метрики Debian каждую 1 секунду
    # Thread 1: Updates Debian metrics every 1 second
    last_net = psutil.net_io_counters()
    last_disk = psutil.disk_io_counters() # Для Disk I/O /\ To Disk I/O
    
    while True:
        try:
            deb_cpu = psutil.cpu_percent(interval=0.5) 
            deb_cores = psutil.cpu_count(logical=True)
            mem = psutil.virtual_memory()
            
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            uptime_str = f"{uptime.days}д {uptime.seconds//3600}ч {(uptime.seconds//60)%60}м"
            
            current_net = psutil.net_io_counters()
            net_in = round((current_net.bytes_recv - last_net.bytes_recv) * 8 / 1024 / 1024 / 0.5, 2)
            net_out = round((current_net.bytes_sent - last_net.bytes_sent) * 8 / 1024 / 1024 / 0.5, 2)
            last_net = current_net
            
            # Расчет Disk I/O (МБ/с)
            # Disk I/O Calculation (MB/s)
            current_disk = psutil.disk_io_counters()
            disk_read = round((current_disk.read_bytes - last_disk.read_bytes) / 1024 / 1024 / 0.5, 2)
            disk_write = round((current_disk.write_bytes - last_disk.write_bytes) / 1024 / 1024 / 0.5, 2)
            last_disk = current_disk
            
            SYSTEM_CACHE["debian"].update({
                "cpu": deb_cpu, "cores": deb_cores, "ram": mem.percent, 
                "ram_used": round(mem.used / (1024**3), 2), "ram_total": round(mem.total / (1024**3), 2), 
                "status": "Online", "uptime": uptime_str, "net_in": net_in, "net_out": net_out,
                "disk_read": disk_read, "disk_write": disk_write # Disk I/O
            })
        except Exception:
            pass
        time.sleep(0.5) # Суммарно цикл занимает ровно 1 секунду /\ In total, the cycle takes exactly 1 second

def update_windows_stats():
    # Поток 2: Обновляет метрики Windows раз в 2.5 секунды (Защита от перегрузки CPU)
    # Thread 2: Updates Windows metrics every 2.5 seconds (CPU overload protection)
    ps_script = """& {
        $cpu = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
        $os = Get-CimInstance Win32_OperatingSystem
        $cores = (Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedGB = [math]::Round($totalGB - $freeGB, 2)
        $ramPercent =[math]::Round(($usedGB / $totalGB) * 100, 1)
        @{ cpu = $cpu; cores = $cores; ram = $ramPercent; ram_used = $usedGB; ram_total = $totalGB }
    }"""
    while True:
        try:
            win_data, err = run_ps(ps_script)
            if not err and win_data:
                w = win_data[0] if isinstance(win_data, list) else win_data
                SYSTEM_CACHE["windows"].update({
                    "cpu": w.get('cpu', 0), "cores": w.get('cores', 0),
                    "ram": w.get('ram', 0), "ram_used": w.get('ram_used', 0),
                    "ram_total": w.get('ram_total', 0), "status": "Online"
                })
            else:
                SYSTEM_CACHE["windows"]["status"] = "Offline"
        except: pass
        time.sleep(5)

def start_monitoring():
    # Запуск фоновых потоков при старте приложения
    # Starting background threads when the application starts
    threading.Thread(target=update_debian_stats, daemon=True).start()
    threading.Thread(target=update_windows_stats, daemon=True).start()