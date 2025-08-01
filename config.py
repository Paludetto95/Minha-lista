import os
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'uma-chave-secreta-muito-segura'

    # --- Configuração da Base de Dados ---
    DATABASE_URL_FROM_ENV = os.environ.get('DATABASE_URL')
    
    # Lógica de conexão atualizada para resolver o TypeError
    if DATABASE_URL_FROM_ENV and DATABASE_URL_FROM_ENV.startswith("mysql://"):
        # Apenas substitui o protocolo para usar PyMySQL.
        # O driver PyMySQL lida com a autenticação 'caching_sha2_password' automaticamente.
        # A adição explícita de '?auth_plugin=...' foi removida pois causava o erro.
        SQLALCHEMY_DATABASE_URI = DATABASE_URL_FROM_ENV.replace("mysql://", "mysql+pymysql://", 1)
    elif DATABASE_URL_FROM_ENV:
        # Mantém a URL para outros tipos de banco de dados (ex: postgres, sqlite)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL_FROM_ENV
    else:
        # Fallback para um banco de dados SQLite local se a variável de ambiente não for encontrada
        print("AVISO: Váriavel DATABASE_URL não encontrada. Usando banco de dados SQLite local 'app.db'.")
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Opções para manter a ligação à base de dados ativa
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 280,
        'pool_pre_ping': True
    }

    # --- Configuração de Pastas ---
    UPLOAD_FOLDER = os.path.join(basedir, 'temp_uploads')
    PERSISTENT_STORAGE_PATH = os.environ.get('PERSISTENT_STORAGE_PATH', '/mnt/data') 
    PARTNER_LOGOS_FOLDER_NAME = 'partner_logos'
    PARTNER_LOGOS_FULL_PATH = os.path.join(PERSISTENT_STORAGE_PATH, PARTNER_LOGOS_FOLDER_NAME)
