# config.py (VERSÃO FINAL PARA RAILWAY VOLUME)

import os
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'uma-chave-secreta-muito-segura'

    DATABASE_URL_FROM_ENV = os.environ.get('DATABASE_URL')
    if DATABASE_URL_FROM_ENV:
        if DATABASE_URL_FROM_ENV.startswith("mysql://"):
            SQLALCHEMY_DATABASE_URI = DATABASE_URL_FROM_ENV.replace("mysql://", "mysql+pymysql://", 1)
        else:
            SQLALCHEMY_DATABASE_URI = DATABASE_URL_FROM_ENV
    else:
        print("AVISO: Váriavel DATABASE_URL não encontrada. Usando banco de dados SQLite local 'app.db'.")
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_recycle': 1800}

    UPLOAD_FOLDER = os.path.join(basedir, 'temp_uploads')

    # Caminho para o Volume montado no Railway para arquivos persistentes
    # O valor será lido da variável de ambiente PERSISTENT_STORAGE_PATH (definida no Railway ou .env)
    # O valor padrão '/mnt/data' é um exemplo comum se a variável não estiver definida.
    PERSISTENT_STORAGE_PATH = os.environ.get('PERSISTENT_STORAGE_PATH', '/mnt/data') 
    
    # Onde os logos serão armazenados DENTRO do volume persistente
    PARTNER_LOGOS_FOLDER_NAME = 'partner_logos'
    PARTNER_LOGOS_FULL_PATH = os.path.join(PERSISTENT_STORAGE_PATH, PARTNER_LOGOS_FOLDER_NAME)