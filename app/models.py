# app/models.py (VERSÃO FINAL COMPLETA COM SYSTEMLOG)

from app import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime, timedelta
import uuid

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
    # ADICIONADO: Relacionamento para SystemLog
    system_logs = db.relationship('SystemLog', backref='user_performer', lazy='dynamic', cascade="all, delete-orphan")
    
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

# --- NOVO MODELO PARA TAREFAS EM SEGUNDO PLANO ---
class BackgroundTask(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4())) # UUID para ID único
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_type = db.Column(db.String(100), nullable=False) # Ex: 'delete_mailing', 'delete_product'
    status = db.Column(db.String(50), default='PENDING', nullable=False) # PENDING, RUNNING, COMPLETED, FAILED
    progress = db.Column(db.Integer, default=0, nullable=False) # Porcentagem 0-100
    total_items = db.Column(db.Integer, nullable=True) # Total de itens a processar (ex: total de leads)
    items_processed = db.Column(db.Integer, default=0, nullable=True) # Itens já processados
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    message = db.Column(db.Text, nullable=True) # Mensagens adicionais ou erro

    user = db.relationship('User', backref='background_tasks') # Relacionamento de volta com o usuário que iniciou a tarefa

# --- NOVO MODELO PARA LOGS DE SISTEMA ---
class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True) # Pode ser nulo para ações do sistema sem login (ex: primeiro registro)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    action_type = db.Column(db.String(100), nullable=False, index=True) # Ex: 'USER_CREATED', 'LOGIN', 'PRODUCT_DELETED', 'GROUP_UPDATED'
    entity_type = db.Column(db.String(50), nullable=True, index=True) # Ex: 'User', 'Product', 'Group', 'Mailing', 'Tabulation'
    entity_id = db.Column(db.Integer, nullable=True, index=True) # ID da entidade afetada (ex: user.id, product.id)
    description = db.Column(db.Text, nullable=True) # Descrição humana da ação
    details = db.Column(db.JSON, nullable=True) # Dados adicionais (ex: 'old_value': '...', 'new_value': '...')

    # Não precisamos de um relacionamento direto com a entidade aqui, apenas o ID e tipo.
    # user_performer é o backref do User model, que já criamos.


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Outros modelos (manter como estão)
class Proposta(db.Model): id = db.Column(db.Integer, primary_key=True)
class Banco(db.Model): id = db.Column(db.Integer, primary_key=True)
class Convenio(db.Model): id = db.Column(db.Integer, primary_key=True)
class Situacao(db.Model): id = db.Column(db.Integer, primary_key=True)
class TipoDeOperacao(db.Model): id = db.Column(db.Integer, primary_key=True)