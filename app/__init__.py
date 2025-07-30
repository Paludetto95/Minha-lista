# app/__init__.py (VERSÃO PARA RAILWAY VOLUME)

import os
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'main.login'
login_manager.login_message = 'Por favor, faça login para aceder a esta página.'
login_manager.login_message_category = 'info'

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Cria a pasta de uploads temporários se ela não existir
    # Isso precisa estar AQUI (após from_object) para que app.config esteja carregado
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            print(f"DEBUG: Pasta UPLOAD_FOLDER criada: {app.config['UPLOAD_FOLDER']}")
        except OSError as e:
            print(f"ERRO: Falha ao criar UPLOAD_FOLDER: {e} no caminho {app.config['UPLOAD_FOLDER']}")
    else:
        print(f"DEBUG: Pasta UPLOAD_FOLDER já existe: {app.config['UPLOAD_FOLDER']}")
    
    # Cria a pasta de logos DENTRO do VOLUME persistente
    # É CRUCIAL que app.config['PARTNER_LOGOS_FULL_PATH'] esteja definido corretamente aqui
    if not os.path.exists(app.config['PARTNER_LOGOS_FULL_PATH']):
        try:
            os.makedirs(app.config['PARTNER_LOGOS_FULL_PATH'], exist_ok=True)
            print(f"DEBUG: Pasta de logos no Volume criada: {app.config['PARTNER_LOGOS_FULL_PATH']}")
        except OSError as e:
            print(f"ERRO: Falha ao criar PARTNER_LOGOS_FULL_PATH: {e} no caminho {app.config['PARTNER_LOGOS_FULL_PATH']}")
    else:
        print(f"DEBUG: Pasta de logos no Volume já existe: {app.config['PARTNER_LOGOS_FULL_PATH']}")

    app.jinja_env.globals.update(enumerate=enumerate)

    db.init_app(app)
    migrate.init_app(app, db) 
    login_manager.init_app(app)

    with app.app_context():
        from app import routes, models
        app.register_blueprint(routes.bp)

    return app