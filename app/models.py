from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='consultor')
    is_master_admin = db.Column(db.Boolean, default=False)
    allowed_ip = db.Column(db.String(45))
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    theme = db.Column(db.String(20), default='default')
    grupo_id = db.Column(db.Integer, db.ForeignKey('grupo.id'))
    current_status = db.Column(db.String(50), default='Offline')
    status_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity_at = db.Column(db.DateTime, default=datetime.utcnow)
    wallet_limit = db.Column(db.Integer, default=50) 
    daily_pull_limit = db.Column(db.Integer, default=100)
    # ===== NOVO CAMPO ADICIONADO =====
    last_whatsapp_contact_at = db.Column(db.DateTime, nullable=True)

    # Relacionamentos
    leads = db.relationship('Lead', back_populates='consultor', lazy='dynamic', foreign_keys='Lead.consultor_id')
    consumptions = db.relationship('LeadConsumption', back_populates='user', lazy='dynamic')
    activity_logs = db.relationship('ActivityLog', back_populates='user', lazy='dynamic')
    tasks = db.relationship('BackgroundTask', back_populates='user', lazy='dynamic')
    system_logs = db.relationship('SystemLog', back_populates='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    cpf = db.Column(db.String(11), unique=True, nullable=False, index=True)
    telefone = db.Column(db.String(20))
    telefone_2 = db.Column(db.String(20))
    cidade = db.Column(db.String(100))
    rg = db.Column(db.String(100))
    estado = db.Column(db.String(2), index=True)
    bairro = db.Column(db.String(100))
    cep = db.Column(db.String(10))
    convenio = db.Column(db.String(100))
    orgao = db.Column(db.String(100))
    nome_mae = db.Column(db.String(150))
    sexo = db.Column(db.String(10))
    nascimento = db.Column(db.String(20))
    idade = db.Column(db.Integer)
    tipo_vinculo = db.Column(db.String(50))
    rmc = db.Column(db.String(20))
    valor_liberado = db.Column(db.String(50))
    beneficio = db.Column(db.String(50))
    logradouro = db.Column(db.String(200))
    numero = db.Column(db.String(20))
    complemento = db.Column(db.String(100))
    notes = db.Column(db.Text, nullable=True)
    extra_1 = db.Column(db.String(255))
    extra_2 = db.Column(db.String(255))
    extra_3 = db.Column(db.String(255))
    extra_4 = db.Column(db.String(255))
    extra_5 = db.Column(db.String(255))
    extra_6 = db.Column(db.String(255))
    extra_7 = db.Column(db.String(255))
    extra_8 = db.Column(db.String(255))
    extra_9 = db.Column(db.String(255))
    extra_10 = db.Column(db.String(255))
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), nullable=False, index=True)
    status = db.Column(db.String(50), default='Novo', index=True)
    consultor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    tabulation_id = db.Column(db.Integer, db.ForeignKey('tabulation.id'), nullable=True)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    data_tabulacao = db.Column(db.DateTime)
    available_after = db.Column(db.DateTime, nullable=True, index=True)
    additional_data = db.Column(db.JSON)
    last_whatsapp_contact = db.Column(db.DateTime, nullable=True)
    __table_args__ = (
        db.Index('ix_lead_get_new_lead', 'produto_id', 'status', 'available_after', 'data_criacao'),
    )
    
    # Relacionamentos
    produto = db.relationship('Produto', back_populates='leads')
    consultor = db.relationship('User', back_populates='leads')
    tabulation = db.relationship('Tabulation', back_populates='leads')
    activity_logs = db.relationship('ActivityLog', back_populates='lead', cascade="all, delete-orphan")
    consumptions = db.relationship('LeadConsumption', back_populates='lead', cascade="all, delete-orphan")


class Proposta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False)
    banco_id = db.Column(db.Integer, db.ForeignKey('banco.id'), nullable=False)
    convenio_id = db.Column(db.Integer, db.ForeignKey('convenio.id'), nullable=False)
    situacao_id = db.Column(db.Integer, db.ForeignKey('situacao.id'), nullable=False)
    tipo_operacao_id = db.Column(db.Integer, db.ForeignKey('tipo_de_operacao.id'), nullable=False)
    valor_total = db.Column(db.Float)
    valor_parcela = db.Column(db.Float)
    prazo = db.Column(db.Integer)
    data_proposta = db.Column(db.DateTime, default=datetime.utcnow)

class Banco(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)

class Convenio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)

class Situacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)

class TipoDeOperacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)

class LeadConsumption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    user = db.relationship('User', back_populates='consumptions')
    lead = db.relationship('Lead', back_populates='consumptions')

class Tabulation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    color = db.Column(db.String(7), default='#6c757d')
    is_recyclable = db.Column(db.Boolean, default=False)
    recycle_in_days = db.Column(db.Integer, nullable=True)
    is_positive_conversion = db.Column(db.Boolean, default=False)
    
    # Relacionamentos
    leads = db.relationship('Lead', back_populates='tabulation', lazy='dynamic')
    activity_logs = db.relationship('ActivityLog', back_populates='tabulation', lazy='dynamic')

# Tabela de associação entre Grupo e Produto
grupo_produto = db.Table('grupo_produto',
    db.Column('grupo_id', db.Integer, db.ForeignKey('grupo.id'), primary_key=True),
    db.Column('produto_id', db.Integer, db.ForeignKey('produto.id'), primary_key=True)
)

class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    
    # Relacionamentos
    leads = db.relationship('Lead', back_populates='produto', cascade="all, delete-orphan", lazy='dynamic')
    layouts = db.relationship('LayoutMailing', back_populates='produto', cascade="all, delete-orphan", lazy='dynamic')
    grupos = db.relationship('Grupo', secondary=grupo_produto, back_populates='produtos')


class LayoutMailing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), nullable=False)
    mapping = db.Column(db.JSON, nullable=False)
    
    # Relacionamento
    produto = db.relationship('Produto', back_populates='layouts')

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tabulation_id = db.Column(db.Integer, db.ForeignKey('tabulation.id'), nullable=True)
    action_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relacionamentos
    user = db.relationship('User', back_populates='activity_logs')
    lead = db.relationship('Lead', back_populates='activity_logs')
    tabulation = db.relationship('Tabulation', back_populates='activity_logs')

class Grupo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    color = db.Column(db.String(7), default='#6c757d')
    logo_filename = db.Column(db.String(255), nullable=True)
    monthly_pull_limit = db.Column(db.Integer, nullable=True)
    
    # Relacionamento
    users = db.relationship('User', backref='grupo', lazy='dynamic')
    produtos = db.relationship('Produto', secondary=grupo_produto, back_populates='grupos')

class BackgroundTask(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text)
    progress = db.Column(db.Integer, default=0)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    total_items = db.Column(db.Integer, default=0)
    items_processed = db.Column(db.Integer, default=0)
    details = db.Column(db.JSON, nullable=True)
    
    # Relacionamento
    user = db.relationship('User', back_populates='tasks')

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    action_type = db.Column(db.String(50), index=True)
    entity_type = db.Column(db.String(50), nullable=True)
    entity_id = db.Column(db.String(36), nullable=True)
    description = db.Column(db.Text, nullable=True)
    details = db.Column(db.JSON, nullable=True)

    # Relacionamento
    user = db.relationship('User', back_populates='system_logs')