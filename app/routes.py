import pandas as pd
import io
import re
import os
import uuid
import threading
import plotly.graph_objects as go
import plotly.io as pio
import pytz
import random
from collections import defaultdict
from functools import wraps
from flask import render_template, flash, redirect, url_for, request, Blueprint, jsonify, Response, current_app, abort, send_from_directory
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from app import db
from app.models import User, Lead, Proposta, Banco, Convenio, Situacao, TipoDeOperacao, LeadConsumption, Tabulation, Produto, LayoutMailing, ActivityLog, Grupo, BackgroundTask, SystemLog
from datetime import datetime, date, time, timedelta
from sqlalchemy import func, cast, Date, or_, case, and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from sqlalchemy.sql import text

bp = Blueprint('main', __name__)

@bp.before_request
def check_ip():
    if current_user.is_authenticated and current_user.allowed_ip:
        if request.remote_addr != current_user.allowed_ip:
            abort(403)

# --- FUNÇÕES HELPER ---

def get_brasilia_time():
    """Retorna o tempo atual no fuso horário de Brasília."""
    utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    brasilia_tz = pytz.timezone('America/Sao_Paulo')
    return utc_now.astimezone(brasilia_tz)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'csv', 'xlsx'}

def allowed_file(filename):
    """Verifica se a extensão de um arquivo é permitida."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_partner_logo(file):
    """Salva o logo de um parceiro de forma segura, evitando conflitos de nome."""
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{uuid.uuid4()}.{file.filename.rsplit('.', 1)[1].lower()}")
        filepath = os.path.join(current_app.config['PARTNER_LOGOS_FULL_PATH'], filename)
        try:
            os.makedirs(current_app.config['PARTNER_LOGOS_FULL_PATH'], exist_ok=True)
            file.save(filepath)
            return filename
        except Exception as e:
            print(f"ERRO: Falha ao salvar logo no Volume: {e} no caminho {filepath}")
            return None
    return None

def delete_partner_logo(filename):
    """Remove um arquivo de logo do armazenamento."""
    if filename:
        filepath = os.path.join(current_app.config['PARTNER_LOGOS_FULL_PATH'], filename)
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                return True
            except Exception as e:
                print(f"ERRO: Falha ao deletar logo do Volume: {e} no caminho {filepath}")
                return False
    return False

def start_background_task(task_func, task_type, user_id, initial_message="", *args, **kwargs):
    """Inicia uma tarefa em segundo plano e a registra no banco de dados."""
    app_context = current_app._get_current_object()
    
    with app_context.app_context():
        task = BackgroundTask(
            user_id=user_id,
            task_type=task_type,
            status='PENDING',
            message=initial_message,
            progress=0,
            items_processed=0,
            total_items=0
        )
        db.session.add(task)
        db.session.commit()
        task_id = task.id
    
    thread = threading.Thread(target=task_func, args=(app_context, task_id, *args), kwargs=kwargs)
    thread.start()
    return task_id

def log_system_action(action_type, entity_type=None, entity_id=None, description=None, details=None, user_id=None):
    """Centraliza o registro de logs do sistema."""
    if user_id is None:
        try:
            if current_user and current_user.is_authenticated:
                user_id = current_user.id
        except RuntimeError:
            user_id = None
    
    log_entry = SystemLog(
        user_id=user_id,
        action_type=action_type,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        description=description,
        details=details,
        timestamp=get_brasilia_time()
    )
    db.session.add(log_entry)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"ERRO: Falha ao salvar SystemLog: {e}")

# --- DECORADORES ---

def require_role(*roles):
    """Decorador para restringir acesso a rotas com base no papel do usuário."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('main.login'))
            if current_user.role == 'super_admin':
                return f(*args, **kwargs)
            if current_user.role not in roles:
                flash('Acesso negado. Você não tem permissão para ver esta página.', 'danger')
                return redirect(url_for('main.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def update_user_status(user, new_status):
    """Atualiza o status e a última atividade de um usuário."""
    user.current_status = new_status
    user.status_timestamp = get_brasilia_time()
    user.last_activity_at = get_brasilia_time()
    db.session.add(user)

# --- ROTAS DE AUTENTICAÇÃO E GERAIS ---

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and user.check_password(request.form.get('password')):
            user.last_login = get_brasilia_time()
            if user.role == 'consultor':
                update_user_status(user, 'Ocioso')
            db.session.commit()
            login_user(user, remember=request.form.get('remember_me'))
            log_system_action('LOGIN', entity_type='User', entity_id=user.id, description=f"Usuário '{user.username}' logou no sistema.")
            return redirect(url_for('main.index'))
        flash('Email ou senha inválidos', 'danger')
    return render_template('login.html', title='Login')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if User.query.first():
        flash('O registro está desabilitado.', 'warning')
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        grupo = Grupo.query.filter_by(nome="Equipe Principal").first() or Grupo(nome="Equipe Principal")
        db.session.add(grupo)
        db.session.flush()

        user = User(username=request.form['username'], email=request.form['email'], role='super_admin', is_master_admin=True, grupo_id=grupo.id)
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        log_system_action('USER_REGISTERED_INITIAL_ADMIN', entity_type='User', entity_id=user.id, description=f"Primeiro Super Admin '{user.username}' registrado.")
        flash('Conta de Super Administrador criada com sucesso!', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title='Registrar Super Admin')

@bp.route('/logout')
@login_required
def logout():
    log_system_action('LOGOUT', entity_type='User', entity_id=current_user.id, description=f"Usuário '{current_user.username}' deslogou.")
    if current_user.is_authenticated and current_user.role == 'consultor':
        update_user_status(current_user, 'Offline')
        db.session.commit()
    logout_user()
    return redirect(url_for('main.login'))

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    role_dashboard_map = {
        'super_admin': 'main.admin_dashboard',
        'admin_parceiro': 'main.parceiro_dashboard',
        'consultor': 'main.consultor_dashboard'
    }
    return redirect(url_for(role_dashboard_map.get(current_user.role, 'main.login')))

@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        theme = request.form.get('theme')
        if theme in ['default', 'dark', 'ocean']:
            log_system_action('USER_THEME_CHANGED', entity_type='User', entity_id=current_user.id, 
                              description=f"Usuário '{current_user.username}' mudou o tema.",
                              details={'old': current_user.theme, 'new': theme})
            current_user.theme = theme
            db.session.commit()
            
            flash('Tema atualizado com sucesso!', 'success')
            return redirect(url_for('main.profile'))
            
    return render_template('profile.html', title="Minhas Configurações")    

# --- ROTAS DE ADMIN ---

@bp.route('/admin/dashboard')
@login_required
@require_role('super_admin')
def admin_dashboard():
    all_products = Produto.query.order_by(Produto.name).all()
    all_layouts = LayoutMailing.query.order_by(LayoutMailing.name).all()
    page = request.args.get('page', 1, type=int)
    recent_activity = ActivityLog.query.options(
        joinedload(ActivityLog.lead), 
        joinedload(ActivityLog.user), 
        joinedload(ActivityLog.tabulation)
    ).order_by(ActivityLog.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)
    
    return render_template('admin/admin_dashboard.html', 
                           title='Dashboard do Admin', 
                           all_products=all_products, 
                           all_layouts=all_layouts, 
                           recent_activity=recent_activity)

@bp.route('/api/admin/monitor_data')
@login_required
@require_role('super_admin')
def admin_monitor_data():
    brasilia_tz = pytz.timezone('America/Sao_Paulo')
    now_in_brasilia = get_brasilia_time()
    start_of_day = now_in_brasilia.replace(hour=0, minute=0, second=0, microsecond=0)

    stats_query = db.session.query(
        User.id, User.username, User.current_status, User.last_login,
        User.last_activity_at, Grupo.nome.label('grupo_nome'),
        func.count(ActivityLog.id).label('calls_today'),
        func.sum(case((Tabulation.is_positive_conversion == True, 1), else_=0)).label('conversions_today')
    ).join(Grupo, User.grupo_id == Grupo.id) \
     .outerjoin(ActivityLog, and_(User.id == ActivityLog.user_id, ActivityLog.timestamp >= start_of_day)) \
     .outerjoin(Tabulation, ActivityLog.tabulation_id == Tabulation.id) \
     .filter(User.role == 'consultor').group_by(User.id, Grupo.nome).all()

    agents_data = []
    for agent in stats_query:
        real_status = agent.current_status
        inactivity_threshold = timedelta(minutes=2)
        if agent.last_activity_at and agent.current_status != 'Offline':
            aware_last_activity = brasilia_tz.localize(agent.last_activity_at) if agent.last_activity_at.tzinfo is None else agent.last_activity_at.astimezone(brasilia_tz)
            if (now_in_brasilia - aware_last_activity) > inactivity_threshold:
                real_status = 'Offline'
        
        current_work = Lead.query.join(Produto).filter(Lead.consultor_id == agent.id, Lead.status == 'Em Atendimento').with_entities(Produto.name).first()
        
        agents_data.append({
            'name': agent.username,
            'status': real_status,
            'last_login': agent.last_login.astimezone(brasilia_tz).strftime('%d/%m/%Y às %H:%M') if agent.last_login else 'Nunca logou',
            'local': f"{agent.grupo_nome} / {current_work[0] if current_work else 'Nenhum'}",
            'calls_today': agent.calls_today or 0,
            'conversions_today': agent.conversions_today or 0
        })
    
    agents_data.sort(key=lambda x: (x['conversions_today'], x['calls_today']), reverse=True)
    return jsonify(agents_data=agents_data)

@bp.route('/admin/monitor')
@login_required
@require_role('super_admin')
def admin_monitor():
    """ Apenas carrega a página base. Os dados são preenchidos via API. """
    return render_template('admin/monitor.html', title="Monitor Global")

@bp.route('/admin/system-logs')
@login_required
@require_role('super_admin')
def admin_system_logs_page():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search_query', '').strip()
    filter_type = request.args.get('filter_type', 'all').strip()
    filter_user_id = request.args.get('filter_user', 'all').strip()

    logs_query = SystemLog.query.options(joinedload(SystemLog.user)).order_by(SystemLog.timestamp.desc())

    if search_query:
        search_pattern = f"%{search_query}%"
        logs_query = logs_query.filter(
            or_(
                SystemLog.description.ilike(search_pattern),
                SystemLog.action_type.ilike(search_pattern)
            )
        )

    if filter_type != 'all':
        logs_query = logs_query.filter(SystemLog.action_type == filter_type)

    if filter_user_id != 'all':
        if filter_user_id == 'none':
            logs_query = logs_query.filter(SystemLog.user_id.is_(None))
        else:
            try:
                user_id_int = int(filter_user_id)
                logs_query = logs_query.filter(SystemLog.user_id == user_id_int)
            except (ValueError, TypeError):
                flash("ID de usuário inválido para o filtro.", "warning")

    pagination = logs_query.paginate(page=page, per_page=25, error_out=False)
    logs = pagination.items

    action_types_for_select = [item[0] for item in db.session.query(SystemLog.action_type).distinct().order_by(SystemLog.action_type)]
    all_users_for_filter = User.query.order_by(User.username).all()

    return render_template(
        'admin/system_logs.html',
        title="Logs do Sistema",
        logs=logs,
        pagination=pagination,
        search_query=search_query,
        filter_type=filter_type,
        filter_user_id=filter_user_id,
        action_types_for_select=action_types_for_select,
        all_users_for_filter=all_users_for_filter
    )

@bp.route('/upload_step1', methods=['POST'])
@login_required
@require_role('super_admin')
def upload_step1():
    uploaded_file = request.files.get('file')
    produto_id = request.form.get('produto_id')
    layout_id = request.form.get('layout_id')
    if not all([uploaded_file, produto_id]):
        flash('Os campos (Arquivo e Produto) são obrigatórios.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    if not uploaded_file.filename.lower().endswith(('.csv', '.xlsx')):
        flash('Formato de ficheiro inválido. Apenas .csv ou .xlsx.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    try:
        if uploaded_file.filename.lower().endswith('.csv'):
            df = pd.read_csv(uploaded_file.stream, sep=None, engine='python', encoding='latin1', dtype=str, nrows=5)
        else:
            df = pd.read_excel(uploaded_file.stream, dtype=str, nrows=5)
            
        temp_filename = f"{uuid.uuid4()}{os.path.splitext(uploaded_file.filename)[1]}"
        temp_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
        uploaded_file.stream.seek(0)
        with open(temp_filepath, 'wb') as f:
             f.write(uploaded_file.stream.read())
        headers = df.columns.tolist()
        sample_rows = df.head(2).to_dict(orient='records')
        system_fields = ['nome', 'cpf', 'telefone', 'telefone_2','cidade','rg','estado', 'bairro', 'cep', 'convenio', 'orgao', 'nome_mae', 'sexo', 'nascimento', 'idade', 'tipo_vinculo', 'rmc', 'valor_liberado', 'beneficio', 'logradouro', 'numero', 'complemento', 'extra_1', 'extra_2', 'extra_3', 'extra_4', 'extra_5', 'extra_6', 'extra_7', 'extra_8', 'extra_9', 'extra_10']
        existing_mapping = {}
        extra_names = {}
        if layout_id:
            layout = LayoutMailing.query.get(layout_id)
            if layout and layout.mapping:
                for field, value in layout.mapping.items():
                    if isinstance(value, dict): # New format: {'column': '...', 'name': '...'}
                        existing_mapping[value['column']] = field
                        extra_names[field] = value.get('name', '')
                    else: # Old format
                        existing_mapping[value] = field
        return render_template('admin/map_columns.html', headers=headers, sample_rows=sample_rows, temp_filename=temp_filename, produto_id=produto_id, system_fields=system_fields, existing_mapping=existing_mapping, extra_names=extra_names)
    except Exception as e:
        flash(f'Erro ao ler o arquivo: {e}', 'danger')
        return redirect(url_for('main.admin_dashboard'))

@bp.route('/upload_step2_process', methods=['POST'])
@login_required
@require_role('super_admin')
def upload_step2_process():
    form_data = request.form
    temp_filename = form_data.get('temp_filename')
    produto_id = form_data.get('produto_id')
    if not all([temp_filename, produto_id]):
        flash('Erro: informações da importação foram perdidas.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    temp_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
    if not os.path.exists(temp_filepath):
        flash('Erro: arquivo temporário não encontrado.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    
    leads_importados = 0
    leads_ignorados = 0
    
    try:
        mapping = {}
        layout_mapping_to_save = {}
        extra_field_names = {} # Para armazenar os nomes personalizados dos campos extra
        ignored_columns_headers = []
        
        df_headers = pd.read_excel(temp_filepath, nrows=0) if temp_filepath.endswith('.xlsx') else pd.read_csv(temp_filepath, nrows=0, sep=None, engine='python', encoding='latin1', dtype=str)
        
        for i in range(len(df_headers.columns)):
            original_header_name = form_data.get(f'header_name_{i}')
            if not original_header_name: continue
            
            if f'include_column_{i}' in form_data:
                selected_system_field = form_data.get(f'mapping_{i}')
                
                if selected_system_field and selected_system_field != 'Ignorar':
                    if selected_system_field in mapping:
                        flash(f'Erro: O campo do sistema "{selected_system_field}" foi mapeado para mais de uma coluna.', 'danger')
                        return redirect(url_for('main.admin_dashboard'))
                    
                    mapping[selected_system_field] = original_header_name
                    
                    # Verifica se é um campo extra e se um nome personalizado foi fornecido
                    if selected_system_field.startswith('extra_'):
                        custom_name = form_data.get(f'extra_name_{i}', '').strip()
                        if custom_name:
                            extra_field_names[selected_system_field] = custom_name
                            # Salva no formato de dicionário para o layout
                            layout_mapping_to_save[selected_system_field] = {'column': original_header_name, 'name': custom_name}
                        else:
                            layout_mapping_to_save[selected_system_field] = original_header_name
                    else:
                        layout_mapping_to_save[selected_system_field] = original_header_name
                else:
                    ignored_columns_headers.append(original_header_name)
            else:
                ignored_columns_headers.append(original_header_name)

        if 'cpf' not in mapping or 'nome' not in mapping:
            flash("Erro de mapeamento: As colunas 'CPF' e 'Nome' são obrigatórias.", "danger")
            return redirect(url_for('main.admin_dashboard'))

        if form_data.get('save_layout') and form_data.get('layout_name'):
            new_layout = LayoutMailing(name=form_data.get('layout_name'), produto_id=int(produto_id), mapping=layout_mapping_to_save)
            db.session.add(new_layout)
            flash('Novo layout de mapeamento salvo com sucesso!', 'info')

        chunk_size = 2000
        df_iterator = pd.read_excel(temp_filepath, dtype=str, chunksize=chunk_size) if temp_filepath.endswith('.xlsx') else pd.read_csv(temp_filepath, sep=None, engine='python', encoding='latin1', dtype=str, chunksize=chunk_size)

        campos_do_modelo_lead = [c.name for c in Lead.__table__.columns]
        
        for df_chunk in df_iterator:
            df_chunk.columns = [str(col) for col in df_chunk.columns]
            
            cpfs_no_lote_str = df_chunk[mapping['cpf']].dropna().astype(str)
            cpfs_no_lote_limpos = [re.sub(r'\D', '', s) for s in cpfs_no_lote_str]
            cpfs_validos_lote = {cpf for cpf in cpfs_no_lote_limpos if len(cpf) == 11}

            if not cpfs_validos_lote:
                leads_ignorados += len(df_chunk)
                continue
            
            cpfs_ja_existentes_db = {item[0] for item in db.session.query(Lead.cpf).filter(Lead.cpf.in_(cpfs_validos_lote)).all()}
            
            leads_para_adicionar = []
            
            for index, row in df_chunk.iterrows():
                cpf_bruto = str(row.get(mapping['cpf'], ''))
                cpf_limpo = re.sub(r'\D', '', cpf_bruto)
                
                if not cpf_limpo or len(cpf_limpo) != 11 or cpf_limpo in cpfs_ja_existentes_db:
                    leads_ignorados += 1
                    continue
                
                row_data = {}
                additional_data = {}

                for system_field, original_header in mapping.items():
                    valor = row.get(original_header)
                    if pd.notna(valor):
                        # Se for um campo extra, usa o nome personalizado (se houver), senão o nome do campo
                        display_name = extra_field_names.get(system_field, system_field)
                        
                        if system_field in campos_do_modelo_lead:
                            row_data[system_field] = str(valor).strip()
                        else:
                            # Garante que campos extra usem o nome personalizado no additional_data
                            additional_data[display_name] = str(valor).strip()
                
                final_lead_data = {
                    'produto_id': produto_id,
                    'cpf': cpf_limpo,
                    'status': 'Novo',
                    'data_criacao': get_brasilia_time(),
                    'additional_data': additional_data 
                }
                final_lead_data.update(row_data)

                novo_lead = Lead(**final_lead_data)
                leads_para_adicionar.append(novo_lead)
                cpfs_ja_existentes_db.add(cpf_limpo)

            if leads_para_adicionar:
                db.session.bulk_save_objects(leads_para_adicionar)
                leads_importados += len(leads_para_adicionar)
        
        db.session.commit()

        if leads_importados > 0:
            flash(f'{leads_importados} leads importados com sucesso! {leads_ignorados} foram ignorados.', 'success')
        else:
            flash('Nenhum novo lead válido para importar foi encontrado na planilha.', 'warning')
        
        log_system_action('LEAD_IMPORT', entity_type='Product', entity_id=int(produto_id), 
                          description=f"Importação de {leads_importados} leads. {leads_ignorados} ignorados.",
                          details={'filename': temp_filename, 'total_imported': leads_importados, 'total_ignored': leads_ignorados})

    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro crítico durante o processamento: {e}', 'danger')
        log_system_action('LEAD_IMPORT_FAILED', entity_type='Product', entity_id=int(produto_id),
                          description=f"Erro crítico ao importar leads.",
                          details={'filename': temp_filename, 'error': str(e)})
    finally:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
    return redirect(url_for('main.admin_dashboard'))

@bp.route('/consultor/dashboard')
@login_required
@require_role('consultor')
def consultor_dashboard():
    update_user_status(current_user, 'Ocioso')
    db.session.commit()
    
    leads_em_atendimento = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    vagas_na_carteira = current_user.wallet_limit - leads_em_atendimento
    
    start_of_day = get_brasilia_time().replace(hour=0, minute=0, second=0, microsecond=0)
    
    leads_consumidos_hoje = LeadConsumption.query.filter(
        LeadConsumption.user_id == current_user.id,
        LeadConsumption.timestamp >= start_of_day
    ).count()
    vagas_na_puxada_diaria = current_user.daily_pull_limit - leads_consumidos_hoje

    mailings_disponiveis = db.session.query(
        Lead.produto_id,
        Produto.name.label('produto_nome'),
        Lead.estado,
        func.count(Lead.id).label('leads_disponiveis')
    ).join(Produto, Lead.produto_id == Produto.id).filter(
        Lead.status == 'Novo',
        or_(Lead.available_after.is_(None), Lead.available_after <= get_brasilia_time())
    ).group_by(Lead.produto_id, Produto.name, Lead.estado).order_by(Produto.name, Lead.estado).all()

    search_history = request.args.get('search_history', '')
    tabulated_history_query = ActivityLog.query.filter(
        ActivityLog.user_id == current_user.id,
        ActivityLog.tabulation_id.isnot(None)
    ).options(
        joinedload(ActivityLog.lead),
        joinedload(ActivityLog.tabulation)
    ).order_by(ActivityLog.timestamp.desc())

    if search_history:
        search_pattern = f"%{search_history}%"
        tabulated_history_query = tabulated_history_query.join(Lead).filter(
            or_(
                Lead.nome.ilike(search_pattern),
                Lead.cpf.ilike(search_pattern)
            )
        )
    
    tabulated_history = tabulated_history_query.limit(50).all()

    all_tabulations = Tabulation.query.order_by(Tabulation.name).all()

    produtos_em_atendimento = db.session.query(
        Produto, 
        func.count(Lead.id).label('lead_count')
    ).join(Lead, Produto.id == Lead.produto_id).filter(
        Lead.consultor_id == current_user.id,
        Lead.status == 'Em Atendimento'
    ).group_by(Produto).order_by(Produto.name).all()

    return render_template('consultor_dashboard.html', 
                           title='Dashboard do Consultor',
                           leads_em_atendimento=leads_em_atendimento,
                           vagas_na_carteira=vagas_na_carteira,
                           leads_consumidos_hoje=leads_consumidos_hoje,
                           vagas_na_puxada_diaria=vagas_na_puxada_diaria,
                           mailings_disponiveis=mailings_disponiveis,
                           tabulated_history=tabulated_history,
                           search_history=search_history,
                           all_tabulations=all_tabulations,
                           available_products=Produto.query.all(),
                           produtos_em_atendimento=produtos_em_atendimento)

@bp.route('/consultor/pegar_leads_selecionados', methods=['POST'])
@login_required
@require_role('consultor')
def pegar_leads_selecionados():
    form_data = request.form
    total_leads_a_pegar = 0
    leads_a_pegar_por_lote = {}

    for key, value in form_data.items():
        if key.startswith('leads_') and value.isdigit() and int(value) > 0:
            try:
                produto_id_str, estado = key.split('_')[1].split('-', 1)
                produto_id = int(produto_id_str)
                quantidade = int(value)
                total_leads_a_pegar += quantidade
                if (produto_id, estado) not in leads_a_pegar_por_lote:
                    leads_a_pegar_por_lote[(produto_id, estado)] = 0
                leads_a_pegar_por_lote[(produto_id, estado)] += quantidade
            except (ValueError, IndexError):
                flash('Erro ao processar o formulário de seleção de leads.', 'danger')
                return redirect(url_for('main.consultor_dashboard'))

    if total_leads_a_pegar == 0:
        flash('Nenhuma quantidade de lead foi selecionada.', 'warning')
        return redirect(url_for('main.consultor_dashboard'))

    leads_em_atendimento = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    vagas_na_carteira = current_user.wallet_limit - leads_em_atendimento

    start_of_day = get_brasilia_time().replace(hour=0, minute=0, second=0, microsecond=0)
    leads_consumidos_hoje = LeadConsumption.query.filter(
        LeadConsumption.user_id == current_user.id,
        LeadConsumption.timestamp >= start_of_day
    ).count()
    vagas_na_puxada_diaria = current_user.daily_pull_limit - leads_consumidos_hoje

    if total_leads_a_pegar > vagas_na_carteira:
        flash(f'Você tentou pegar {total_leads_a_pegar} leads, mas só tem {vagas_na_carteira} vagas na carteira.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))

    if total_leads_a_pegar > vagas_na_puxada_diaria:
        flash(f'Você tentou pegar {total_leads_a_pegar} leads, mas só tem {vagas_na_puxada_diaria} puxadas restantes hoje.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))

    leads_pegos_count = 0
    for (produto_id, estado), quantidade in leads_a_pegar_por_lote.items():
        if quantidade <= 0:
            continue

        leads_disponiveis = Lead.query.filter(
            Lead.produto_id == produto_id,
            Lead.estado == estado,
            Lead.status == 'Novo',
            or_(Lead.available_after.is_(None), Lead.available_after <= get_brasilia_time())
        ).order_by(Lead.data_criacao).limit(quantidade).all()

        for lead in leads_disponiveis:
            lead.consultor_id = current_user.id
            lead.status = 'Em Atendimento'
            db.session.add(lead)

            consumption = LeadConsumption(
                lead_id=lead.id,
                user_id=current_user.id,
                timestamp=get_brasilia_time()
            )
            db.session.add(consumption)
            leads_pegos_count += 1

    if leads_pegos_count > 0:
        update_user_status(current_user, 'Em Atendimento')
        db.session.commit()
        flash(f'{leads_pegos_count} leads foram adicionados à sua carteira!', 'success')
        log_system_action('LEADS_PULLED_BATCH', entity_type='Lead',
                          description=f"{leads_pegos_count} leads puxados em lote por '{current_user.username}'.",
                          details={'total_pulled': leads_pegos_count, 'breakdown': {f'{pid}-{est}': qty for (pid, est), qty in leads_a_pegar_por_lote.items()}})
    else:
        flash('Nenhum lead novo foi encontrado para os lotes selecionados.', 'warning')

    return redirect(url_for('main.consultor_dashboard'))

@bp.route('/consultor/atendimento', methods=['GET', 'POST'])
@login_required
@require_role('consultor')
def atendimento():
    if request.method == 'POST':
        lead_id = request.form.get('lead_id')
        tabulation_id = request.form.get('tabulation_id')

        if not lead_id or not tabulation_id:
            flash('Informações de tabulação inválidas.', 'danger')
            return redirect(url_for('main.consultor_dashboard'))

        lead = Lead.query.get(lead_id)
        tabulation = Tabulation.query.get(tabulation_id)

        if not lead or not tabulation or lead.consultor_id != current_user.id:
            flash('Lead ou tabulação inválida.', 'danger')
            return redirect(url_for('main.consultor_dashboard'))

        lead.tabulation_id = tabulation.id
        lead.data_tabulacao = get_brasilia_time()

        if tabulation.is_positive_conversion:
            lead.status = 'Convertido'
        elif tabulation.is_recyclable:
            lead.status = 'Novo'
            lead.available_after = get_brasilia_time() + timedelta(days=tabulation.recycle_in_days)
        else:
            lead.status = 'Tabulado'
        
        log = ActivityLog(
            lead_id=lead.id,
            user_id=current_user.id,
            tabulation_id=tabulation.id,
            action_type='Tabulação'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Lead {lead.nome} tabulado com sucesso como "{tabulation.name}".', 'success')
        return redirect(url_for('main.atendimento'))

    # GET request logic
    produto_id = request.args.get('produto_id', type=int)
    lead_id = request.args.get('lead_id', type=int)    
    # If no lead_id is provided, find the next available lead
    if not lead_id:
        if produto_id:
            lead = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento', produto_id=produto_id).order_by(Lead.data_criacao).first()
        else:
            lead = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').order_by(Lead.data_criacao).first()
        
        if lead:
            return redirect(url_for('main.atendimento', lead_id=lead.id))
        else:
            flash('Nenhum lead em atendimento no momento para este produto.', 'info')
            return redirect(url_for('main.consultor_dashboard'))

    # If a lead_id is provided, display the lead
    lead = Lead.query.get(lead_id)
    if not lead or lead.consultor_id != current_user.id or lead.status != 'Em Atendimento':
        flash('Lead não encontrado ou não está mais em atendimento.', 'warning')
        # Try to find the next one
        next_lead = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').order_by(Lead.data_criacao).first()
        if next_lead:
            return redirect(url_for('main.atendimento', lead_id=next_lead.id))
        else:
            return redirect(url_for('main.consultor_dashboard'))

    # Calculations for the template
    start_of_day = get_brasilia_time().replace(hour=0, minute=0, second=0, microsecond=0)
    leads_consumidos_hoje = LeadConsumption.query.filter(
        LeadConsumption.user_id == current_user.id,
        LeadConsumption.timestamp >= start_of_day
    ).count()
    vagas_na_puxada_diaria = current_user.daily_pull_limit - leads_consumidos_hoje
    leads_em_atendimento = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    vagas_na_carteira = current_user.wallet_limit - leads_em_atendimento
    all_tabulations = Tabulation.query.order_by(Tabulation.name).all()
    cleaned_telefone = re.sub(r'\D', '', lead.telefone) if lead.telefone else None
    cleaned_telefone_2 = re.sub(r'\D', '', lead.telefone_2) if lead.telefone_2 else None
    
    lead_details = {}
    
    exclude_fields = [
        'id', 'consultor_id', 'produto_id', 'tabulation_id', 'additional_data', 
        'consultor', 'produto', 'tabulation', 'activities', 'consumptions',
        'available_after', 'data_tabulacao'
    ]

    field_labels = {
        'nome': 'Nome', 'cpf': 'CPF', 'telefone': 'Telefone 1', 'telefone_2': 'Telefone 2',
        'cidade': 'Cidade', 'rg': 'RG', 'estado': 'Estado', 'bairro': 'Bairro', 'cep': 'CEP',
        'convenio': 'Convênio', 'orgao': 'Órgão', 'nome_mae': 'Nome da Mãe', 'sexo': 'Sexo',
        'nascimento': 'Nascimento', 'idade': 'Idade', 'tipo_vinculo': 'Tipo de Vínculo',
        'rmc': 'RMC', 'valor_liberado': 'Valor Liberado', 'beneficio': 'Benefício',
        'logradouro': 'Logradouro', 'numero': 'Número', 'complemento': 'Complemento',
        'status': 'Status', 'notes': 'Observações',
        'data_criacao': 'Data de Criação', 'last_whatsapp_contact': 'Último Contato WhatsApp',
        'extra_1': 'Extra 1', 'extra_2': 'Extra 2', 'extra_3': 'Extra 3', 'extra_4': 'Extra 4',
        'extra_5': 'Extra 5', 'extra_6': 'Extra 6', 'extra_7': 'Extra 7', 'extra_8': 'Extra 8',
        'extra_9': 'Extra 9', 'extra_10': 'Extra 10'
    }

    for column in Lead.__table__.columns:
        if column.name not in exclude_fields:
            value = getattr(lead, column.name)
            if value is not None and value != '':
                label = field_labels.get(column.name, column.name.replace('_', ' ').title())
                
                if isinstance(value, datetime):
                    lead_details[label] = value.strftime('%d/%m/%Y %H:%M')
                elif isinstance(value, date):
                    lead_details[label] = value.strftime('%d/%m/%Y')
                else:
                    lead_details[label] = str(value)

    if lead.produto:
        lead_details['Produto'] = lead.produto.name

    if lead.additional_data:
        for key, value in lead.additional_data.items():
            if value is not None and value != '':
                label = field_labels.get(key, key)
                lead_details[label] = value

    return render_template('atendimento.html',
                           title='Atendimento',
                           lead=lead,
                           all_tabulations=all_tabulations,
                           cleaned_telefone=cleaned_telefone,
                           cleaned_telefone_2=cleaned_telefone_2,
                           lead_details=lead_details,
                           vagas_na_puxada_diaria=vagas_na_puxada_diaria,
                           vagas_na_carteira=vagas_na_carteira,
                           leads_em_atendimento=leads_em_atendimento)