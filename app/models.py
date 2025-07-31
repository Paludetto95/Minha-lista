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
    logo_filename = db.Column(db.String(255), nullable=True) 
    
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
    
    # NOVOS CAMPOS ADICIONADOS / ATUALIZADOS PARA O MODELO LEAD
    cidade = db.Column(db.String(100), nullable=True)
    rg = db.Column(db.String(20), nullable=True)
    estado = db.Column(db.String(2), index=True, nullable=True) 
    bairro = db.Column(db.String(100), nullable=True)
    cep = db.Column(db.String(10), nullable=True)
    convenio = db.Column(db.String(100), nullable=True)
    orgao = db.Column(db.String(100), nullable=True)
    nome_mae = db.Column(db.String(150), nullable=True)
    sexo = db.Column(db.String(10), nullable=True)
    nascimento = db.Column(db.String(10), nullable=True) # Manter como String se não houver lógica de data complexa
    idade = db.Column(db.Integer, nullable=True)
    tipo_vinculo = db.Column(db.String(50), nullable=True)
    rmc = db.Column(db.String(50), nullable=True) 
    valor_liberado = db.Column(db.String(50), nullable=True)
    beneficio = db.Column(db.String(100), nullable=True)
    logradouro = db.Column(db.String(255), nullable=True)
    numero = db.Column(db.String(20), nullable=True)
    complemento = db.Column(db.String(100), nullable=True)
    
    # Campos extras genéricos (se você quiser mapeá-los diretamente, caso contrário, eles irão para additional_data)
    extra_1 = db.Column(db.String(255), nullable=True)
    extra_2 = db.Column(db.String(255), nullable=True)
    extra_3 = db.Column(db.String(255), nullable=True)
    extra_4 = db.Column(db.String(255), nullable=True)
    extra_5 = db.Column(db.String(255), nullable=True)
    extra_6 = db.Column(db.String(255), nullable=True)
    extra_7 = db.Column(db.String(255), nullable=True)
    extra_8 = db.Column(db.String(255), nullable=True)
    extra_9 = db.Column(db.String(255), nullable=True)
    extra_10 = db.Column(db.String(255), nullable=True)

    additional_data = db.Column(db.JSON) # Mantém para dados não mapeados diretamente
    
    consultor_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    tabulation_id = db.Column(db.Integer, db.ForeignKey('tabulation.id'), index=True)
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), index=True, nullable=True)
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

class BackgroundTask(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default='PENDING', nullable=False)
    progress = db.Column(db.Integer, default=0, nullable=False)
    total_items = db.Column(db.Integer, nullable=True)
    items_processed = db.Column(db.Integer, default=0, nullable=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    message = db.Column(db.Text, nullable=True)
    details = db.Column(db.JSON, nullable=True) # ADICIONADO: Para armazenar CPFs encontrados ou Lead IDs

    user = db.relationship('User', backref='background_tasks')

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    action_type = db.Column(db.String(100), nullable=False, index=True)
    entity_type = db.Column(db.String(50), nullable=True, index=True)
    entity_id = db.Column(db.String(36), nullable=True)
    description = db.Column(db.Text, nullable=True)
    details = db.Column(db.JSON, nullable=True)
    user = db.relationship('User')


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Outros modelos
class Proposta(db.Model): id = db.Column(db.Integer, primary_key=True)
class Banco(db.Model): id = db.Column(db.Integer, primary_key=True)
class Convenio(db.Model): id = db.Column(db.Integer, primary_key=True)
class Situacao(db.Model): id = db.Column(db.Integer, primary_key=True)
class TipoDeOperacao(db.Model): id = db.Column(db.Integer, primary_key=True)