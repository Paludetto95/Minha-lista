# app/models.py (VERSÃO FINAL COMPLETA)

from app import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime, timedelta

class Grupo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True)
    color = db.Column(db.String(7), default='#6c757d')
    
    users = db.relationship('User', backref='grupo', lazy='dynamic')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(50), default='consultor', nullable=False, index=True)
    theme = db.Column(db.String(50), default='default', nullable=False)
    
    grupo_id = db.Column(db.Integer, db.ForeignKey('grupo.id'), nullable=False, index=True)
    wallet_limit = db.Column(db.Integer, default=100, nullable=False)
    daily_pull_limit = db.Column(db.Integer, default=30, nullable=False)
    current_status = db.Column(db.String(50), default='Offline', index=True)
    status_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    last_activity_at = db.Column(db.DateTime, default=datetime.utcnow)

    leads = db.relationship('Lead', backref='consultor', lazy='dynamic')
    consumptions = db.relationship('LeadConsumption', backref='user', lazy='dynamic', cascade="all, delete-orphan")
    activities = db.relationship('ActivityLog', backref='user', lazy='dynamic', cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Lead(db.Model):
    __tablename__ = 'lead'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), index=True)
    cpf = db.Column(db.String(11), unique=True, nullable=False, index=True)
    telefone = db.Column(db.String(20), nullable=True)
    telefone_2 = db.Column(db.String(20), nullable=True)
    status = db.Column(db.String(20), default='Novo', index=True)
    data_criacao = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    data_tabulacao = db.Column(db.DateTime, nullable=True)
    additional_data = db.Column(db.JSON)
    
    consultor_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    tabulation_id = db.Column(db.Integer, db.ForeignKey('tabulation.id'), index=True)
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), index=True, nullable=True)
    estado = db.Column(db.String(2), index=True, nullable=True)
    available_after = db.Column(db.DateTime, nullable=True, index=True)

    tabulation = db.relationship('Tabulation', back_populates='leads')
    produto = db.relationship('Produto', back_populates='leads')
    consumptions = db.relationship('LeadConsumption', backref='lead', lazy='dynamic', cascade="all, delete-orphan")
    activities = db.relationship('ActivityLog', backref='lead', lazy='dynamic', cascade="all, delete-orphan")

class Tabulation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    color = db.Column(db.String(7), default='#000000')
    is_recyclable = db.Column(db.Boolean, default=False, nullable=False)
    recycle_in_days = db.Column(db.Integer, nullable=True)
    is_positive_conversion = db.Column(db.Boolean, default=False, nullable=False)
    leads = db.relationship('Lead', back_populates='tabulation', lazy='dynamic')

class LeadConsumption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    leads = db.relationship('Lead', back_populates='produto', lazy='dynamic', cascade="all, delete-orphan")
    layouts = db.relationship('LayoutMailing', backref='produto', lazy='dynamic', cascade="all, delete-orphan")

class LayoutMailing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), nullable=False, index=True)
    mapping = db.Column(db.JSON, nullable=False)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    tabulation_id = db.Column(db.Integer, db.ForeignKey('tabulation.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    action_type = db.Column(db.String(50)) 
    tabulation = db.relationship('Tabulation')

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Outros modelos
class Proposta(db.Model): id = db.Column(db.Integer, primary_key=True)
class Banco(db.Model): id = db.Column(db.Integer, primary_key=True)
class Convenio(db.Model): id = db.Column(db.Integer, primary_key=True)
class Situacao(db.Model): id = db.Column(db.Integer, primary_key=True)
class TipoDeOperacao(db.Model): id = db.Column(db.Integer, primary_key=True)