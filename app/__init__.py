# app/__init__.py (VERSÃO COM CORREÇÃO DO KEYERROR PARA PASTAS)

import os
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

# Instâncias das extensões
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'main.login'
login_manager.login_message = 'Por favor, faça login para aceder a esta página.'
login_manager.login_message_category = 'info'

def create_app(config_class=Config):
    """
    Application Factory: Cria e configura a instância da aplicação Flask.
    """
    app = Flask(__name__)
    app.config.from_object(config_class) # <--- ESSA LINHA PRECISA SER EXECUTADA PRIMEIRO

    # ADICIONADO: As configurações agora estão disponíveis em app.config
    # Cria a pasta de uploads temporários se ela não existir
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            print(f"DEBUG: Pasta UPLOAD_FOLDER criada: {app.config['UPLOAD_FOLDER']}")
        except OSError as e:
            print(f"ERRO: Falha ao criar UPLOAD_FOLDER: {e} no caminho {app.config['UPLOAD_FOLDER']}")
    else:
        print(f"DEBUG: Pasta UPLOAD_FOLDER já existe: {app.config['UPLOAD_FOLDER']}")
    
    # ADICIONADO: Cria a pasta para logos de parceiros se ela não existir
    if not os.path.exists(app.config['PARTNER_LOGOS_FULL_PATH']):
        try:
            os.makedirs(app.config['PARTNER_LOGOS_FULL_PATH'], exist_ok=True)
            print(f"DEBUG: Pasta de logos no Volume criada: {app.config['PARTNER_LOGOS_FULL_PATH']}")
        except OSError as e:
            print(f"ERRO: Falha ao criar PARTNER_LOGOS_FULL_PATH: {e} no caminho {app.config['PARTNER_LOGOS_FULL_PATH']}")
    else:
        print(f"DEBUG: Pasta de logos no Volume já existe: {app.config['PARTNER_LOGOS_FULL_PATH']}")

    # Restante do código em __init__.py
    app.jinja_env.globals.update(enumerate=enumerate) # Pode ficar aqui ou mover para cima se preferir, não afeta este erro

    # Inicializa as extensões com a aplicação
    db.init_app(app)
    migrate.init_app(app, db) 
    login_manager.init_app(app)

    # Importa e registra os modelos e as rotas DENTRO do contexto da app
    with app.app_context():
        from app import routes, models
        app.register_blueprint(routes.bp)

    return app