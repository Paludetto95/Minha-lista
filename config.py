# config.py (VERSÃO FINAL SIMPLIFICADA PARA PyMySQL)

import os
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env (para uso local)
load_dotenv() # Esta linha lê o arquivo .env e carrega as variáveis

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') # Ele vai encontrar a SECRET_KEY do .env
    DATABASE_URL_FROM_ENV = os.environ.get('DATABASE_URL') # Ele vai encontrar a DATABASE_URL do .env
    # ...

# Define o diretório base da aplicação
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """
    Classe de configuração da aplicação.
    """
    # Chave secreta para proteger as sessões. Em produção, esta chave deve ser
    # definida como uma variável de ambiente no Railway.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'uma-chave-secreta-muito-segura'

    # --- LÓGICA DE CONEXÃO AO BANCO DE DADOS SIMPLIFICADA ---
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
        # Isso evita que a aplicação quebre e facilita o desenvolvimento local.
        print("AVISO: Váriavel DATABASE_URL não encontrada. Usando banco de dados SQLite local 'app.db'.")
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

    # Desativa uma funcionalidade do SQLAlchemy que não usaremos e consome recursos.
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Define a pasta para uploads temporários de arquivos.
    UPLOAD_FOLDER = os.path.join(basedir, 'temp_uploads')