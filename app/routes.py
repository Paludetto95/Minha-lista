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
from flask import render_template, flash, redirect, url_for, request, Blueprint, jsonify, Response, current_app, abort, send_from_directory, session
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
        
        # --- MODIFICATION START ---
        # After tabulation, redirect back to atendimento, preserving the product_id
        current_product_id = session.get('current_product_id')
        if current_product_id:
            return redirect(url_for('main.atendimento', produto_id=current_product_id))
        else:
            return redirect(url_for('main.atendimento'))
        # --- MODIFICATION END ---

    # GET request logic
    requested_produto_id = request.args.get('produto_id', type=int)
    lead_id = request.args.get('lead_id', type=int)    

    # --- MODIFICATION START ---
    # Determine the product_id to use for filtering
    if requested_produto_id:
        session['current_product_id'] = requested_produto_id
        product_id_filter = requested_produto_id
    else:
        product_id_filter = session.get('current_product_id')
    # --- MODIFICATION END ---

    # If no lead_id is provided, find the next available lead
    if not lead_id:
        lead_query = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento')
        # --- MODIFICATION START ---
        if product_id_filter:
            lead_query = lead_query.filter_by(produto_id=product_id_filter)
        # --- MODIFICATION END ---
        lead = lead_query.order_by(Lead.data_criacao).first()
        
        if lead:
            # --- MODIFICATION START ---
            # Ensure product_id is passed in the redirect if it's set
            if product_id_filter:
                return redirect(url_for('main.atendimento', lead_id=lead.id, produto_id=product_id_filter))
            else:
                return redirect(url_for('main.atendimento', lead_id=lead.id))
            # --- MODIFICATION END ---
        else:
            flash('Nenhum lead em atendimento no momento para este produto.', 'info')
            # --- MODIFICATION START ---
            # Clear the session product_id if no leads are found for it
            if 'current_product_id' in session:
                session.pop('current_product_id')
            # --- MODIFICATION END ---
            return redirect(url_for('main.consultor_dashboard'))

    # If a lead_id is provided, display the lead
    lead = Lead.query.get(lead_id)
    # --- MODIFICATION START ---
    # Add product_id_filter to the lead validation
    if not lead or lead.consultor_id != current_user.id or lead.status != 'Em Atendimento' or (product_id_filter and lead.produto_id != product_id_filter):
    # --- MODIFICATION END ---
        flash('Lead não encontrado ou não está mais em atendimento.', 'warning')
        # Try to find the next one
        next_lead_query = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento')
        # --- MODIFICATION START ---
        if product_id_filter:
            next_lead_query = next_lead_query.filter_by(produto_id=product_id_filter)
        # --- MODIFICATION END ---
        next_lead = next_lead_query.order_by(Lead.data_criacao).first()
        if next_lead:
            # --- MODIFICATION START ---
            if product_id_filter:
                return redirect(url_for('main.atendimento', lead_id=next_lead.id, produto_id=product_id_filter))
            else:
                return redirect(url_for('main.atendimento', lead_id=next_lead.id))
            # --- MODIFICATION END ---
        else:
            # --- MODIFICATION START ---
            if 'current_product_id' in session:
                session.pop('current_product_id')
            # --- MODIFICATION END ---
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

@bp.route('/admin/manage-groups', methods=['GET'])
@login_required
@require_role('super_admin')
def manage_groups():
    """ Rota para exibir e gerenciar todos os grupos/equipes. """
    
    # Subquery para contar usuários por grupo
    user_count_subquery = db.session.query(
        User.grupo_id,
        func.count(User.id).label('user_count')
    ).group_by(User.grupo_id).subquery()

    # Subquery para calcular o consumo mensal de leads por grupo
    start_of_month = get_brasilia_time().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    monthly_consumption_subquery = db.session.query(
        User.grupo_id,
        func.count(LeadConsumption.id).label('monthly_consumption')
    ).join(User, LeadConsumption.user_id == User.id)\
     .filter(LeadConsumption.timestamp >= start_of_month)\
     .group_by(User.grupo_id).subquery()

    # Query principal para buscar os grupos com os dados agregados
    teams_data = db.session.query(
        Grupo,
        func.coalesce(user_count_subquery.c.user_count, 0).label('user_count'),
        func.coalesce(monthly_consumption_subquery.c.monthly_consumption, 0).label('monthly_consumption')
    ).outerjoin(user_count_subquery, Grupo.id == user_count_subquery.c.grupo_id)\
     .outerjoin(monthly_consumption_subquery, Grupo.id == monthly_consumption_subquery.c.grupo_id)\
     .order_by(Grupo.nome).all()

    return render_template('admin/manage_teams.html', title="Gerenciar Equipes", teams_data=teams_data)

@bp.route('/admin/groups/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_group():
    """ Adiciona um novo grupo/equipe. """
    name = request.form.get('name')
    monthly_pull_limit = request.form.get('monthly_pull_limit')
    color = request.form.get('color')
    logo_file = request.files.get('logo_file')

    if not name:
        flash('O nome da equipe é obrigatório.', 'danger')
        return redirect(url_for('main.manage_groups'))

    new_group = Grupo(
        nome=name,
        color=color,
        monthly_pull_limit=int(monthly_pull_limit) if monthly_pull_limit else None
    )

    if logo_file:
        logo_filename = save_partner_logo(logo_file)
        if logo_filename:
            new_group.logo_filename = logo_filename
        else:
            flash('Houve um erro ao salvar o logo.', 'warning')

    db.session.add(new_group)
    db.session.commit()
    
    log_system_action('GROUP_CREATED', entity_type='Group', entity_id=new_group.id, description=f"Equipe '{new_group.nome}' criada.")
    flash(f'A equipe "{name}" foi criada com sucesso!', 'success')
    return redirect(url_for('main.manage_groups'))

@bp.route('/admin/groups/<int:group_id>/details')
@login_required
@require_role('super_admin')
def team_details(group_id):
    """ Exibe os detalhes de uma equipe/grupo específico. """
    grupo = Grupo.query.get_or_404(group_id)
    
    admins = User.query.filter_by(grupo_id=group_id, role='admin_parceiro').all()
    consultores = User.query.filter_by(grupo_id=group_id, role='consultor').all()
    
    # Calcula o consumo mensal do grupo
    start_of_month = get_brasilia_time().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_consumption = db.session.query(func.count(LeadConsumption.id))\
        .join(User, LeadConsumption.user_id == User.id)\
        .filter(User.grupo_id == group_id, LeadConsumption.timestamp >= start_of_month)\
        .scalar() or 0
        
    # Calcula o total de logins do grupo
    total_logins_group = db.session.query(func.count(SystemLog.id)) \
        .filter(SystemLog.action_type == 'LOGIN', SystemLog.user_id.in_([u.id for u in admins + consultores])) \
        .scalar() or 0

    # Usuários disponíveis para adicionar à equipe (que não estão em nenhuma ou estão na equipe "principal" e não são super_admin)
    available_users = User.query.filter(
        or_(User.grupo_id.is_(None), User.grupo_id == 1),
        User.role != 'super_admin'
    ).order_by(User.username).all()

    return render_template('admin/team_details.html', 
                           title=f"Detalhes da Equipe {grupo.nome}",
                           grupo=grupo, 
                           admins=admins, 
                           consultores=consultores,
                           monthly_consumption=monthly_consumption,
                           total_logins_group=total_logins_group,
                           available_users=available_users)

@bp.route('/admin/groups/<int:group_id>/edit', methods=['POST'])
@login_required
@require_role('super_admin')
def edit_group_name_color(group_id):
    """ Edita o nome, cor, limite e logo de um grupo. """
    group = Grupo.query.get_or_404(group_id)
    
    # Obter dados do formulário
    name = request.form.get('name')
    color = request.form.get('color')
    monthly_pull_limit = request.form.get('monthly_pull_limit')
    remove_logo = request.form.get('remove_logo')
    logo_file = request.files.get('logo_file')

    if not name:
        flash('O nome da equipe não pode ser vazio.', 'danger')
        return redirect(url_for('main.team_details', group_id=group_id))

    # Atualizar campos
    group.nome = name
    group.color = color
    group.monthly_pull_limit = int(monthly_pull_limit) if monthly_pull_limit and monthly_pull_limit.isdigit() else None

    # Lógica para o logo
    if logo_file: # Novo logo enviado
        if group.logo_filename: # Deleta o antigo se existir
            delete_partner_logo(group.logo_filename)
        logo_filename = save_partner_logo(logo_file)
        if logo_filename:
            group.logo_filename = logo_filename
        else:
            flash('Erro ao salvar o novo logo.', 'warning')
    elif remove_logo: # Checkbox para remover logo marcada
        if group.logo_filename:
            delete_partner_logo(group.logo_filename)
            group.logo_filename = None

    db.session.commit()
    log_system_action('GROUP_UPDATED', entity_type='Group', entity_id=group.id, description=f"Equipe '{group.nome}' atualizada.")
    flash('Equipe atualizada com sucesso!', 'success')
    return redirect(url_for('main.team_details', group_id=group_id))

@bp.route('/admin/groups/<int:group_id>/delete', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_group(group_id):
    """ Exclui um grupo se ele não tiver membros. """
    group = Grupo.query.get_or_404(group_id)
    if group.users.count() > 0:
        flash('Não é possível excluir uma equipe que ainda tem membros.', 'danger')
        return redirect(url_for('main.team_details', group_id=group_id))
    
    # Deletar logo associado se existir
    if group.logo_filename:
        delete_partner_logo(group.logo_filename)

    db.session.delete(group)
    db.session.commit()
    log_system_action('GROUP_DELETED', entity_type='Group', entity_id=group_id, description=f"Equipe '{group.nome}' excluída.")
    flash(f'A equipe "{group.nome}" foi excluída com sucesso.', 'success')
    return redirect(url_for('main.manage_groups'))

@bp.route('/admin/groups/<int:group_id>/add_member', methods=['POST'])
@login_required
@require_role('super_admin')
def add_member_to_team(group_id):
    """ Adiciona ou atualiza um membro em uma equipe. """
    group = Grupo.query.get_or_404(group_id)
    user_id = request.form.get('user_id')
    role = request.form.get('role')

    if not user_id or not role:
        flash('Usuário e Papel são obrigatórios.', 'danger')
        return redirect(url_for('main.team_details', group_id=group_id))

    user = User.query.get(user_id)
    if not user:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('main.team_details', group_id=group_id))

    user.grupo_id = group_id
    user.role = role
    db.session.commit()
    
    log_system_action('USER_ADDED_TO_GROUP', entity_type='Group', entity_id=group_id, description=f"Usuário '{user.username}' adicionado/atualizado na equipe '{group.nome}'.")
    flash(f'Usuário {user.username} foi adicionado/atualizado na equipe {group.nome} como {role}.', 'success')
    return redirect(url_for('main.team_details', group_id=group_id))

@bp.route('/admin/groups/<int:group_id>/remove_member/<int:user_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def remove_member_from_team(group_id, user_id):
    """ Remove um membro de uma equipe, movendo-o para o grupo padrão. """
    user = User.query.get_or_404(user_id)
    
    # Garante que o usuário pertence ao grupo do qual está sendo removido
    if user.grupo_id != group_id:
        flash('Este usuário não pertence a esta equipe.', 'warning')
        return redirect(url_for('main.team_details', group_id=group_id))

    # Encontra o grupo "Equipe Principal" ou cria se não existir
    default_group = Grupo.query.filter_by(nome="Equipe Principal").first()
    if not default_group:
        default_group = Grupo(nome="Equipe Principal")
        db.session.add(default_group)
        db.session.flush() # Garante que o ID está disponível

    user.grupo_id = default_group.id
    user.role = 'consultor' # Papel padrão ao ser removido
    db.session.commit()
    
    log_system_action('USER_REMOVED_FROM_GROUP', entity_type='Group', entity_id=group_id, description=f"Usuário '{user.username}' removido da equipe.")
    flash(f'Usuário {user.username} foi removido da equipe.', 'success')
    return redirect(url_for('main.team_details', group_id=group_id))

@bp.route('/partner_logos/<filename>')
def serve_partner_logo(filename):
    """ Serve os logos dos parceiros a partir do volume. """
    logo_path = current_app.config.get('PARTNER_LOGOS_FULL_PATH')
    if not logo_path or not os.path.exists(os.path.join(logo_path, filename)):
        # Se não encontrar, tenta servir de um caminho estático legado como fallback
        return send_from_directory(os.path.join(current_app.root_path, 'static', 'partner_logos'), filename, as_attachment=False)
    return send_from_directory(logo_path, filename, as_attachment=False)

@bp.route('/admin/manage-users', methods=['GET'])
@login_required
@require_role('super_admin')
def manage_users():
    """ Rota para exibir e gerenciar todos os usuários. """
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search_query', '')
    filter_role = request.args.get('filter_role', 'all')
    filter_group = request.args.get('filter_group', 'all')
    sort_by = request.args.get('sort_by', 'username')
    sort_order = request.args.get('sort_order', 'asc')

    users_query = User.query.options(joinedload(User.grupo))

    if search_query:
        search_pattern = f"%{search_query}%"
        users_query = users_query.filter(
            or_(User.username.ilike(search_pattern), User.email.ilike(search_pattern))
        )

    if filter_role != 'all':
        users_query = users_query.filter(User.role == filter_role)

    if filter_group != 'all':
        users_query = users_query.filter(User.grupo_id == filter_group)

    order_column = getattr(User, sort_by, User.username)
    if sort_order == 'desc':
        order_column = order_column.desc()
    
    users_query = users_query.order_by(order_column)

    pagination = users_query.paginate(page=page, per_page=15, error_out=False)
    users = pagination.items
    grupos = Grupo.query.order_by(Grupo.nome).all()

    return render_template('admin/manage_users.html', 
                           title="Gerir Utilizadores",
                           users=users, 
                           pagination=pagination, 
                           grupos=grupos,
                           search_query=search_query,
                           filter_role=filter_role,
                           filter_group=filter_group,
                           sort_by=sort_by,
                           sort_order=sort_order)

@bp.route('/admin/users/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_user():
    """ Adiciona um novo usuário. """
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')
    grupo_id = request.form.get('grupo_id')
    allowed_ip = request.form.get('allowed_ip')

    if User.query.filter_by(email=email).first():
        flash('Este email já está em uso.', 'danger')
        return redirect(url_for('main.manage_users'))

    user = User(
        username=username,
        email=email,
        role=role,
        grupo_id=int(grupo_id) if grupo_id else None,
        allowed_ip=allowed_ip if allowed_ip else None
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    log_system_action('USER_CREATED', entity_type='User', entity_id=user.id, description=f"Usuário '{user.username}' criado.")
    flash('Utilizador criado com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

@bp.route('/admin/users/<int:user_id>/update_limits', methods=['POST'])
@login_required
@require_role('super_admin')
def update_user_limits(user_id):
    """ Atualiza os limites de um usuário. """
    user = User.query.get_or_404(user_id)
    wallet_limit = request.form.get('wallet_limit')
    daily_pull_limit = request.form.get('daily_pull_limit')

    user.wallet_limit = int(wallet_limit) if wallet_limit else 0
    user.daily_pull_limit = int(daily_pull_limit) if daily_pull_limit else 0
    
    db.session.commit()
    log_system_action('USER_LIMITS_UPDATED', entity_type='User', entity_id=user.id, description=f"Limites do usuário '{user.username}' atualizados.")
    flash('Limites do utilizador atualizados com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

@bp.route('/admin/users/<int:user_id>/update_ip', methods=['POST'])
@login_required
@require_role('super_admin', 'master_admin')
def update_user_ip(user_id):
    """ Atualiza o IP permitido de um usuário. """
    user = User.query.get_or_404(user_id)
    allowed_ip = request.form.get('allowed_ip')
    
    user.allowed_ip = allowed_ip if allowed_ip else None
    
    db.session.commit()
    log_system_action('USER_IP_UPDATED', entity_type='User', entity_id=user.id, description=f"IP do usuário '{user.username}' atualizado.")
    flash('IP do utilizador atualizado com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

@bp.route('/admin/users/<int:id>/delete', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_user(id):
    """ Exclui um usuário. """
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('Não pode apagar a sua própria conta.', 'danger')
        return redirect(url_for('main.manage_users'))
        
    db.session.delete(user)
    db.session.commit()
    log_system_action('USER_DELETED', entity_type='User', entity_id=id, description=f"Usuário '{user.username}' excluído.")
    flash('Utilizador apagado com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

@bp.route('/admin/manage-mailings')
@login_required
@require_role('super_admin')
def manage_mailings():
    """ Exibe uma visão geral de todos os mailings, agrupados por produto e estado. """
    mailings_query = db.session.query(
        Lead.produto_id,
        Produto.name.label('produto_nome'),
        Lead.estado,
        func.count(Lead.id).label('total_leads'),
        func.sum(case((Lead.status == 'Novo', 1), else_=0)).label('leads_novos')
    ).join(Produto, Lead.produto_id == Produto.id)\
     .group_by(Lead.produto_id, Produto.name, Lead.estado)\
     .order_by(Produto.name, Lead.estado)\
     .all()

    mailings_por_produto = defaultdict(list)
    for mailing in mailings_query:
        mailings_por_produto[mailing.produto_nome].append(mailing)

    return render_template('admin/manage_mailings.html', 
                           title="Gerenciar Mailings",
                           mailings_por_produto=mailings_por_produto)

@bp.route('/admin/mailings/export-all')
@login_required
@require_role('super_admin')
def export_all_mailings():
    """ Exporta um relatório completo de todos os mailings para um arquivo Excel. """
    all_leads = Lead.query.options(joinedload(Lead.produto), joinedload(Lead.consultor)).all()
    
    if not all_leads:
        flash('Não há leads para exportar.', 'warning')
        return redirect(url_for('main.manage_mailings'))

    leads_data = []
    for lead in all_leads:
        leads_data.append({
            'Produto': lead.produto.name if lead.produto else 'N/A',
            'Estado': lead.estado,
            'Nome': lead.nome,
            'CPF': lead.cpf,
            'Telefone': lead.telefone,
            'Status': lead.status,
            'Consultor': lead.consultor.username if lead.consultor else 'N/A',
            'Data Criação': lead.data_criacao.strftime('%Y-%m-%d %H:%M:%S') if lead.data_criacao else '',
            'Data Tabulação': lead.data_tabulacao.strftime('%Y-%m-%d %H:%M:%S') if lead.data_tabulacao else ''
        })
    
    df = pd.DataFrame(leads_data)
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Todos os Leads')
    output.seek(0)

    return Response(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment;filename=relatorio_completo_mailings.xlsx"}
    )

@bp.route('/admin/mailings/export/<int:produto_id>/<estado>')
@login_required
@require_role('super_admin')
def export_mailing(produto_id, estado):
    """ Exporta um mailing específico (produto/estado) para um arquivo CSV. """
    leads = Lead.query.filter_by(produto_id=produto_id, estado=estado).all()
    
    if not leads:
        flash('Nenhum lead encontrado para este mailing.', 'warning')
        return redirect(url_for('main.manage_mailings'))

    # Create a list of dictionaries
    leads_data = []
    for lead in leads:
        leads_data.append(lead.to_dict()) # Assumes you have a to_dict() method in your Lead model

    df = pd.DataFrame(leads_data)
    
    output = io.StringIO()
    df.to_csv(output, index=False, sep=';', encoding='latin1')
    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={f"Content-Disposition": f"attachment;filename=mailing_{produto_id}_{estado}.csv"}
    )

def _delete_mailing_task(app, task_id, produto_id, estado):
    with app.app_context():
        task = BackgroundTask.query.get(task_id)
        if not task:
            return

        try:
            leads_to_delete = Lead.query.filter_by(produto_id=produto_id, estado=estado)
            total_leads = leads_to_delete.count()

            task.status = 'RUNNING'
            task.total_items = total_leads
            task.message = f"Excluindo {total_leads} leads..."
            db.session.commit()

            deleted_count = 0
            for lead_batch in leads_to_delete.yield_per(100):
                # Log activities before deleting the lead
                ActivityLog.query.filter(ActivityLog.lead_id == lead_batch.id).delete(synchronize_session=False)
                LeadConsumption.query.filter(LeadConsumption.lead_id == lead_batch.id).delete(synchronize_session=False)
                
                db.session.delete(lead_batch)
                deleted_count += 1
                if deleted_count % 100 == 0:
                    task.progress = (deleted_count / total_leads) * 100
                    task.items_processed = deleted_count
                    task.message = f"Excluindo {deleted_count}/{total_leads} leads..."
                    db.session.commit()
            
            db.session.commit()

            task.status = 'COMPLETED'
            task.progress = 100
            task.message = "Exclusão concluída com sucesso."
            db.session.commit()

        except Exception as e:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Erro durante a exclusão: {str(e)}"
            db.session.commit()


@bp.route('/admin/mailings/delete', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_mailing():
    """ Inicia a exclusão de um mailing em segundo plano. """
    produto_id = request.form.get('produto_id')
    estado = request.form.get('estado')

    if not produto_id or not estado:
        return jsonify({'status': 'error', 'message': 'Produto e Estado são obrigatórios.'}), 400

    task_id = start_background_task(
        _delete_mailing_task,
        'DELETE_MAILING',
        current_user.id,
        f"Preparando para excluir mailing (Produto ID: {produto_id}, Estado: {estado})",
        produto_id=int(produto_id),
        estado=estado
    )

    return jsonify({'status': 'processing', 'task_id': task_id})

@bp.route('/admin/manage-products', methods=['GET'])
@login_required
@require_role('super_admin')
def manage_products():
    """ Rota para exibir e gerenciar todos os produtos. """
    products = Produto.query.order_by(Produto.name).all()
    return render_template('admin/manage_products.html', title="Gerenciar Produtos", products=products)

@bp.route('/admin/products/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_product():
    """ Adiciona um novo produto. """
    name = request.form.get('name')
    if not name:
        flash('O nome do produto é obrigatório.', 'danger')
        return redirect(url_for('main.manage_products'))

    new_product = Produto(name=name)
    db.session.add(new_product)
    db.session.commit()
    
    log_system_action('PRODUCT_CREATED', entity_type='Product', entity_id=new_product.id, description=f"Produto '{new_product.name}' criado.")
    flash(f'O produto "{name}" foi criado com sucesso!', 'success')
    return redirect(url_for('main.manage_products'))

def _delete_product_task(app, task_id, product_id):
    with app.app_context():
        task = BackgroundTask.query.get(task_id)
        if not task:
            return

        try:
            product = Produto.query.get(product_id)
            if not product:
                task.status = 'FAILED'
                task.message = 'Produto não encontrado.'
                db.session.commit()
                return

            leads_to_delete = Lead.query.filter_by(produto_id=product_id)
            total_leads = leads_to_delete.count()

            task.status = 'RUNNING'
            task.total_items = total_leads
            task.message = f"Excluindo {total_leads} leads associados ao produto '{product.name}'..."
            db.session.commit()

            # Delete related records in batches
            lead_ids = [lead.id for lead in leads_to_delete]
            for i in range(0, len(lead_ids), 100):
                batch_ids = lead_ids[i:i+100]
                ActivityLog.query.filter(ActivityLog.lead_id.in_(batch_ids)).delete(synchronize_session=False)
                LeadConsumption.query.filter(LeadConsumption.lead_id.in_(batch_ids)).delete(synchronize_session=False)
                Lead.query.filter(Lead.id.in_(batch_ids)).delete(synchronize_session=False)
                db.session.commit()

                task.progress = ((i + len(batch_ids)) / total_leads) * 100
                task.items_processed = i + len(batch_ids)
                task.message = f"Excluindo leads... ({task.items_processed}/{total_leads})"
                db.session.commit()

            db.session.delete(product)
            db.session.commit()

            task.status = 'COMPLETED'
            task.progress = 100
            task.message = "Produto e leads associados foram excluídos com sucesso."
            db.session.commit()

        except Exception as e:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Erro durante a exclusão: {str(e)}"
            db.session.commit()


@bp.route('/admin/products/<int:id>/delete', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_product(id):
    """ Inicia a exclusão de um produto e seus leads associados em segundo plano. """
    product = Produto.query.get_or_404(id)
    
    task_id = start_background_task(
        _delete_product_task,
        'DELETE_PRODUCT',
        current_user.id,
        f"Preparando para excluir o produto '{product.name}' e seus leads.",
        product_id=id
    )

    return jsonify({
        'status': 'processing',
        'message': f'A exclusão do produto "{product.name}" e seus leads foi iniciada em segundo plano.',
        'task_id': task_id
    })

@bp.route('/admin/manage-layouts')
@login_required
@require_role('super_admin')
def manage_layouts():
    """ Rota para exibir e gerenciar todos os layouts de mailing. """
    layouts = LayoutMailing.query.options(joinedload(LayoutMailing.produto)).order_by(LayoutMailing.name).all()
    return render_template('admin/manage_layouts.html', title="Gerenciar Layouts", layouts=layouts)

@bp.route('/admin/layouts/<int:layout_id>/delete', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_layout(layout_id):
    """ Exclui um layout de mailing. """
    layout = LayoutMailing.query.get_or_404(layout_id)
    db.session.delete(layout)
    db.session.commit()
    log_system_action('LAYOUT_DELETED', entity_type='Layout', entity_id=layout_id, description=f"Layout '{layout.name}' excluído.")
    flash(f'O layout "{layout.name}" foi excluído com sucesso!', 'success')
    return redirect(url_for('main.manage_layouts'))

@bp.route('/admin/manage-tabulations', methods=['GET'])
@login_required
@require_role('super_admin')
def manage_tabulations():
    """ Rota para exibir e gerenciar todas as tabulações. """
    tabulations = Tabulation.query.order_by(Tabulation.name).all()
    return render_template('admin/manage_tabulations.html', title="Gerenciar Tabulações", tabulations=tabulations)

@bp.route('/admin/tabulations/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_tabulation():
    """ Adiciona uma nova tabulação. """
    name = request.form.get('name')
    color = request.form.get('color')
    is_recyclable = 'is_recyclable' in request.form
    recycle_in_days = request.form.get('recycle_in_days')
    is_positive_conversion = 'is_positive_conversion' in request.form

    if not name:
        flash('O nome da tabulação é obrigatório.', 'danger')
        return redirect(url_for('main.manage_tabulations'))

    new_tabulation = Tabulation(
        name=name,
        color=color,
        is_recyclable=is_recyclable,
        recycle_in_days=int(recycle_in_days) if is_recyclable and recycle_in_days else None,
        is_positive_conversion=is_positive_conversion
    )
    db.session.add(new_tabulation)
    db.session.commit()
    
    log_system_action('TABULATION_CREATED', entity_type='Tabulation', entity_id=new_tabulation.id, description=f"Tabulação '{new_tabulation.name}' criada.")
    flash(f'A tabulação "{name}" foi criada com sucesso!', 'success')
    return redirect(url_for('main.manage_tabulations'))

@bp.route('/admin/tabulations/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@require_role('super_admin')
def edit_tabulation(id):
    """ Edita uma tabulação existente. """
    tabulation = Tabulation.query.get_or_404(id)
    if request.method == 'POST':
        tabulation.name = request.form.get('name')
        tabulation.color = request.form.get('color')
        tabulation.is_recyclable = 'is_recyclable' in request.form
        tabulation.recycle_in_days = int(request.form.get('recycle_in_days')) if tabulation.is_recyclable and request.form.get('recycle_in_days') else None
        tabulation.is_positive_conversion = 'is_positive_conversion' in request.form
        
        db.session.commit()
        log_system_action('TABULATION_UPDATED', entity_type='Tabulation', entity_id=tabulation.id, description=f"Tabulação '{tabulation.name}' atualizada.")
        flash('Tabulação atualizada com sucesso!', 'success')
        return redirect(url_for('main.manage_tabulations'))

    return render_template('admin/edit_tabulation.html', title="Editar Tabulação", tabulation=tabulation)

@bp.route('/admin/tabulations/<int:id>/delete', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_tabulation(id):
    """ Exclui uma tabulação. """
    tabulation = Tabulation.query.get_or_404(id)
    db.session.delete(tabulation)
    db.session.commit()
    log_system_action('TABULATION_DELETED', entity_type='Tabulation', entity_id=id, description=f"Tabulação '{tabulation.name}' excluída.")
    flash('Tabulação excluída com sucesso!', 'success')
    return redirect(url_for('main.manage_tabulations'))

@bp.route('/admin/hygiene', methods=['GET', 'POST'])
@login_required
@require_role('super_admin')
def hygiene_upload_page():
    """ Exibe a página de upload para higienização e processa o arquivo enviado. """
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Nenhum arquivo selecionado.', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('Nenhum arquivo selecionado.', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            try:
                if file.filename.lower().endswith('.csv'):
                    df = pd.read_csv(file.stream, sep=None, engine='python', encoding='latin1', dtype=str)
                else:
                    df = pd.read_excel(file.stream, dtype=str)

                if df.empty:
                    flash('O arquivo enviado está vazio.', 'warning')
                    return redirect(request.url)

                # Assume the first column contains the CPFs
                cpf_column = df.columns[0]
                cpfs_to_check = {re.sub(r'\D', '', str(cpf)) for cpf in df[cpf_column].dropna()}
                
                leads_to_delete = Lead.query.filter(Lead.cpf.in_(cpfs_to_check)).all()
                
                # Store the list of lead IDs in the session to pass to the next step
                session['leads_to_delete_ids'] = [lead.id for lead in leads_to_delete]

                return render_template('admin/hygiene_confirm.html', 
                                       title="Confirmar Higienização", 
                                       leads=leads_to_delete,
                                       total_found=len(leads_to_delete))

            except Exception as e:
                flash(f'Erro ao processar o arquivo: {e}', 'danger')
                return redirect(request.url)
        else:
            flash('Formato de arquivo inválido. Apenas .csv ou .xlsx são permitidos.', 'danger')
            return redirect(request.url)

    return render_template('admin/hygiene_upload.html', title="Higienizar Base")

@bp.route('/admin/hygiene/execute', methods=['POST'])
@login_required
@require_role('super_admin')
def execute_hygiene():
    """ Executa a exclusão dos leads selecionados para higienização. """
    lead_ids_to_delete = session.pop('leads_to_delete_ids', [])

    if not lead_ids_to_delete:
        flash('Nenhum lead para excluir. A sessão pode ter expirado.', 'warning')
        return redirect(url_for('main.hygiene_upload_page'))

    try:
        # Delete related records
        ActivityLog.query.filter(ActivityLog.lead_id.in_(lead_ids_to_delete)).delete(synchronize_session=False)
        LeadConsumption.query.filter(LeadConsumption.lead_id.in_(lead_ids_to_delete)).delete(synchronize_session=False)
        
        # Delete leads
        leads_deleted_count = Lead.query.filter(Lead.id.in_(lead_ids_to_delete)).delete(synchronize_session=False)
        
        db.session.commit()
        
        log_system_action('HYGIENE_EXECUTED', entity_type='Lead', description=f"{leads_deleted_count} leads foram higienizados (excluídos).")
        flash(f'{leads_deleted_count} leads foram removidos com sucesso!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro durante a exclusão: {e}', 'danger')

    return redirect(url_for('main.hygiene_upload_page'))
