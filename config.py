# config.py (VERSÃO PARA RAILWAY VOLUME)

import os
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env (para uso local)
load_dotenv()

# Define o diretório base da aplicação
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """
    Classe de configuração da aplicação.
    """
    # Chave secreta para proteger as sessões. Em produção, esta chave deve ser
    # definida como uma variável de ambiente no Railway.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'uma-chave-secreta-muito-segura'

    # --- LÓGICA DE CONEXÃO AO BANCO DE DADOS ---
    # Pega a URL do banco de dados do ambiente (fornecida pelo Railway ou pelo .env)
    DATABASE_URL_FROM_ENV = os.environ.get('DATABASE_URL')

    # Verifica se a URL foi encontrada no ambiente
    if DATABASE_URL_FROM_ENV:
        # Adapta a URL para usar o conector 'PyMySQL', que é mais compatível.
        if DATABASE_URL_FROM_ENV.startswith("mysql://"):
            SQLALCHEMY_DATABASE_URI = DATABASE_URL_FROM_ENV.replace("mysql://", "mysql+pymysql://", 1)
        else:
            # Se já estiver em outro formato, usa como está.
            SQLALCHEMY_DATABASE_URI = DATABASE_URL_FROM_ENV
    else:
        # Fallback: se nenhuma DATABASE_URL for encontrada, usa um banco SQLite local.
        print("AVISO: Váriavel DATABASE_URL não encontrada. Usando banco de dados SQLite local 'app.db'.")
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

    # Desativa uma funcionalidade do SQLAlchemy que não usaremos e consome recursos.
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Define a pasta para uploads temporários de arquivos.
    UPLOAD_FOLDER = os.path.join(basedir, 'temp_uploads')

    # NOVO: Caminho para o Volume montado no Railway para arquivos persistentes
    # IMPORTANTE: SUBSTITUA '/mnt/uploads' pelo Mount Path REAL que você definiu no Railway!
    # No .env local, você pode definir PERSISTENT_STORAGE_PATH como './_local_uploads_persistente'
    PERSISTENT_STORAGE_PATH = os.environ.get('PERSISTENT_STORAGE_PATH', '/mnt/uploads') 
    
    # Onde os logos serão armazenados DENTRO do volume persistente
    PARTNER_LOGOS_FOLDER_NAME = 'partner_logos'
    PARTNER_LOGOS_FULL_PATH = os.path.join(PERSISTENT_STORAGE_PATH, PARTNER_LOGOS_FOLDER_NAME)

    # ===== ADIÇÃO PARA ESTABILIDADE DA CONEXÃO =====
    # Recicla conexões que estão inativas por mais de 30 minutos (1800s).
    # Isso evita erros de "MySQL server has gone away" ou "Lost connection"
    # em ambientes de produção onde as conexões podem ser encerradas por inatividade.
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_recycle': 1800}