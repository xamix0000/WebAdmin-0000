# /opt/webadmin/app/config.py
import os
from dotenv import load_dotenv

# Определяем абсолютный путь к папке /opt/webadmin
#basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
#env_path = os.path.join(basedir, '.env')

# Загружаем данные из .env
# Loading data from .env
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'fallback_secret')
    AD_SERVER = '192.168.56.10'
    AD_SERVER_FQDN = os.environ.get('AD_SERVER_FQDN')
    DOMAIN_USER = os.environ.get('AD_DOMAIN_USER')
    PASSWORD = os.environ.get('AD_PASSWORD')
    DOMAIN_SUFFIX = os.environ.get('AD_DOMAIN_SUFFIX')
    AUTH_METHOD = os.environ.get('AUTH_METHOD', 'kerberos')


