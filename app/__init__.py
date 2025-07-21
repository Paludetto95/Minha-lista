# app/__init__.py (VERSÃO FINAL E CORRIGIDA)

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
    app.config.from_object(config_class)

    # ===== CORREÇÃO APLICADA AQUI =====
    # Adiciona a função 'enumerate' do Python ao ambiente global do Jinja2,
    # permitindo que ela seja usada em todos os templates.
    app.jinja_env.globals.update(enumerate=enumerate)

    # Cria a pasta de uploads temporários se ela não existir
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Inicializa as extensões com a aplicação
    db.init_app(app)
    migrate.init_app(app, db) 
    login_manager.init_app(app)

    # Importa e registra os modelos e as rotas DENTRO do contexto da app
    with app.app_context():
        from app import routes, models
        app.register_blueprint(routes.bp)

    return app