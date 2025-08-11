import pandas as pd
import io
import re
import os
import uuid
import threading
import plotly.graph_objects as go
import plotly.io as pio
import pytz
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

        user = User(username=request.form['username'], email=request.form['email'], role='super_admin', grupo_id=grupo.id)
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
        existing_mapping = None
        if layout_id:
            layout = LayoutMailing.query.get(layout_id)
            if layout:
                existing_mapping = {v: k for k, v in layout.mapping.items()}
        return render_template('admin/map_columns.html', headers=headers, sample_rows=sample_rows, temp_filename=temp_filename, produto_id=produto_id, system_fields=system_fields, existing_mapping=existing_mapping)
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
                    layout_mapping_to_save[selected_system_field] = original_header_name

        if 'cpf' not in mapping or 'nome' not in mapping:
            flash("Erro de mapeamento: As colunas 'CPF' e 'Nome' são obrigatórias.", 'danger')
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
                    if system_field in campos_do_modelo_lead and pd.notna(valor):
                        row_data[system_field] = str(valor).strip()

                for col in df_chunk.columns:
                    if col not in mapping.values():
                        valor = row.get(col)
                        if pd.notna(valor):
                            additional_data[col.title()] = str(valor).strip()
                
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

@bp.route('/admin/users')
@login_required
@require_role('super_admin')
def manage_users():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search_query', '').strip()
    filter_role = request.args.get('filter_role', '').strip()
    filter_group = request.args.get('filter_group', '').strip()
    sort_by = request.args.get('sort_by', 'username').strip()
    sort_order = request.args.get('sort_order', 'asc').strip()

    users_query = User.query

    if search_query:
        search_pattern = f"%{search_query}%"
        users_query = users_query.filter(or_(User.username.ilike(search_pattern), User.email.ilike(search_pattern)))

    if filter_role and filter_role != 'all':
        users_query = users_query.filter_by(role=filter_role)

    if filter_group and filter_group != 'all':
        try:
            users_query = users_query.filter_by(grupo_id=int(filter_group))
        except ValueError:
            flash("ID de grupo inválido para filtro.", "warning")

    order_expression = text(f'{sort_by} {sort_order}')
    if sort_by == 'group':
        users_query = users_query.outerjoin(Grupo)
        order_expression = text(f'grupo.nome {sort_order}')

    pagination = users_query.order_by(order_expression).paginate(page=page, per_page=25, error_out=False)
    users = pagination.items
    
    grupos = Grupo.query.order_by(Grupo.nome).all()

    return render_template(
        'admin/manage_users.html', 
        title="Gerir Utilizadores", 
        users=users, 
        grupos=grupos,
        pagination=pagination,
        search_query=search_query,
        filter_role=filter_role,
        filter_group=filter_group,
        sort_by=sort_by,
        sort_order=sort_order
    )

@bp.route('/admin/teams')
@login_required
@require_role('super_admin')
def manage_teams():
    today = get_brasilia_time().date()
    start_of_month = datetime(today.year, today.month, 1)

    monthly_consumption_subquery = db.session.query(
        User.grupo_id.label('grupo_id'),
        func.count(LeadConsumption.id).label('monthly_consumption')
    ).join(LeadConsumption, LeadConsumption.user_id == User.id)\
     .filter(LeadConsumption.timestamp >= start_of_month)\
     .group_by(User.grupo_id)\
     .subquery()

    teams_with_counts = db.session.query(
        Grupo,
        func.count(User.id),
        func.coalesce(monthly_consumption_subquery.c.monthly_consumption, 0).label('monthly_consumption')
    ).outerjoin(User, Grupo.id == User.grupo_id)\
    .outerjoin(monthly_consumption_subquery, Grupo.id == monthly_consumption_subquery.c.grupo_id)\
    .group_by(Grupo.id, monthly_consumption_subquery.c.monthly_consumption)\
    .order_by(Grupo.nome)\
    .all()

    return render_template('admin/manage_teams.html', title="Gerenciar Equipes", teams_data=teams_with_counts)

@bp.route('/admin/teams/<int:group_id>')
@login_required
@require_role('super_admin')
def team_details(group_id):
    grupo = Grupo.query.get_or_404(group_id)
    
    users_in_group = User.query.filter_by(grupo_id=grupo.id).order_by(User.username).all()

    admins = [user for user in users_in_group if user.role == 'admin_parceiro']
    consultores = [user for user in users_in_group if user.role == 'consultor']

    total_logins_group = sum(1 for user in users_in_group if user.last_login is not None)
    
    available_users = User.query.filter(
        User.grupo_id != group_id, 
        User.role != 'super_admin'
    ).order_by(User.username).all()

    today = get_brasilia_time().date()
    start_of_month = datetime(today.year, today.month, 1)
    user_ids_in_group = [user.id for user in users_in_group]
    
    monthly_consumption = 0
    if user_ids_in_group:
        monthly_consumption = db.session.query(func.count(LeadConsumption.id))\
            .filter(LeadConsumption.user_id.in_(user_ids_in_group))\
            .filter(LeadConsumption.timestamp >= start_of_month)\
            .scalar() or 0

    return render_template(
        'admin/team_details.html', 
        title=f"Detalhes - {grupo.nome}", 
        grupo=grupo, 
        admins=admins, 
        consultores=consultores,
        total_logins_group=total_logins_group,
        available_users=available_users,
        monthly_consumption=monthly_consumption 
    )

@bp.route('/admin/groups/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_group():
    nome = request.form.get('name')
    color = request.form.get('color', '#6c757d')
    logo_file = request.files.get('logo_file')
    
    monthly_pull_limit_str = request.form.get('monthly_pull_limit')
    monthly_pull_limit = int(monthly_pull_limit_str) if monthly_pull_limit_str and monthly_pull_limit_str.isdigit() and int(monthly_pull_limit_str) > 0 else None
    
    logo_filename = None
    if logo_file and logo_file.filename:
        logo_filename = save_partner_logo(logo_file)
        if not logo_filename:
            flash('Formato de arquivo de logo inválido ou erro ao salvar.', 'danger')
            return redirect(url_for('main.manage_teams'))

    if nome:
        existing_group = Grupo.query.filter_by(nome=nome).first()
        if existing_group:
            flash('Uma equipe com este nome já existe.', 'danger')
            if logo_filename:
                delete_partner_logo(logo_filename)
        else:
            new_group = Grupo(
                nome=nome, 
                color=color, 
                logo_filename=logo_filename,
                monthly_pull_limit=monthly_pull_limit
            )
            db.session.add(new_group)
            db.session.commit()
            flash('Equipe adicionada com sucesso!', 'success')
            log_system_action(
                action_type='GROUP_CREATED', 
                entity_type='Group', 
                entity_id=new_group.id, 
                description=f"Grupo '{new_group.nome}' criado.",
                details={
                    'color': new_group.color, 
                    'logo_filename': new_group.logo_filename,
                    'monthly_pull_limit': new_group.monthly_pull_limit
                }
            )
    return redirect(url_for('main.manage_teams'))

@bp.route('/admin/groups/edit/<int:group_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def edit_group_name_color(group_id):
    grupo = Grupo.query.get_or_404(group_id)
    old_details = {
        'name': grupo.nome, 'color': grupo.color, 'logo': grupo.logo_filename,
        'monthly_pull_limit': grupo.monthly_pull_limit
    }

    new_name = request.form.get('name')
    new_color = request.form.get('color')
    new_logo_file = request.files.get('logo_file')
    remove_logo = request.form.get('remove_logo') == 'on'
    new_monthly_pull_limit_str = request.form.get('monthly_pull_limit')
    
    changes = {}

    if new_name and new_name != grupo.nome:
        grupo.nome = new_name
        changes['name'] = {'old': old_details['name'], 'new': new_name}
    
    if new_color and new_color != grupo.color:
        grupo.color = new_color
        changes['color'] = {'old': old_details['color'], 'new': new_color}

    try:
        new_monthly_pull_limit = int(new_monthly_pull_limit_str) if new_monthly_pull_limit_str and int(new_monthly_pull_limit_str) > 0 else None
        if new_monthly_pull_limit != grupo.monthly_pull_limit:
            grupo.monthly_pull_limit = new_monthly_pull_limit
            changes['monthly_pull_limit'] = {'old': old_details['monthly_pull_limit'], 'new': new_monthly_pull_limit}
    except (ValueError, TypeError):
        flash('O limite mensal deve ser um número válido.', 'warning')
    
    if remove_logo:
        if grupo.logo_filename:
            if delete_partner_logo(grupo.logo_filename):
                changes['logo'] = {'old': grupo.logo_filename, 'new': 'removido'}
                grupo.logo_filename = None
    elif new_logo_file and new_logo_file.filename:
        saved_filename = save_partner_logo(new_logo_file)
        if saved_filename:
            if grupo.logo_filename:
                delete_partner_logo(grupo.logo_filename)
            changes['logo'] = {'old': old_details['logo'], 'new': saved_filename}
            grupo.logo_filename = saved_filename

    if changes:
        db.session.commit()
        flash(f'Equipe "{grupo.nome}" atualizada com sucesso!', 'success')
        log_system_action('GROUP_UPDATED', entity_type='Group', entity_id=grupo.id, 
                          description=f"Grupo '{grupo.nome}' atualizado.",
                          details=changes)
    else:
        flash('Nenhuma alteração detectada.', 'info')

    return redirect(url_for('main.team_details', group_id=group_id))

@bp.route('/admin/groups/delete/<int:group_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_group(group_id):
    grupo = Grupo.query.get_or_404(group_id)
    group_name = grupo.nome
    logo_to_delete = grupo.logo_filename

    if grupo.users.count() > 0:
        flash(f'Erro: Não é possível excluir a equipe "{grupo.nome}" porque ela ainda contém usuários.', 'danger')
        log_system_action(action_type='GROUP_DELETE_FAILED', entity_type='Group', entity_id=grupo.id, 
                          description=f"Tentativa de excluir grupo '{group_name}' falhou: contém usuários.")
        return redirect(url_for('main.manage_teams'))
    
    db.session.delete(grupo)
    db.session.commit()
    
    if logo_to_delete:
        delete_partner_logo(logo_to_delete)
        log_system_action(action_type='GROUP_LOGO_DELETED_FILE', entity_type='Group', entity_id=group_id, 
                          description=f"Arquivo de logo '{logo_to_delete}' excluído do disco para o grupo '{group_name}'.")

    flash(f'Equipe "{group_name}" excluída com sucesso!', 'success')
    log_system_action(action_type='GROUP_DELETED', entity_type='Group', entity_id=group_id, description=f"Grupo '{group_name}' excluído.")
    return redirect(url_for('main.manage_teams'))

@bp.route('/admin/teams/add_member/<int:group_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def add_member_to_team(group_id):
    grupo = Grupo.query.get_or_404(group_id)
    user_id = request.form.get('user_id')
    new_role = request.form.get('role')
    user = User.query.get_or_404(user_id)
    
    old_group_id = user.grupo_id
    old_role = user.role

    if user.grupo_id == group_id and user.role == new_role:
        flash(f'Erro: {user.username} já é {new_role} nesta equipe.', 'warning')
        log_system_action(action_type='TEAM_MEMBER_ADD_FAILED', entity_type='User', entity_id=user.id, 
                          description=f"Tentativa de adicionar '{user.username}' ao grupo '{grupo.nome}' falhou: já pertence com o mesmo papel.")
        return redirect(url_for('main.team_details', group_id=group_id))
    
    user.grupo_id = group_id
    user.role = new_role
    db.session.commit()
    flash(f'{user.username} adicionado(a) como {new_role} à equipe {grupo.nome}!', 'success')
    log_system_action(action_type='TEAM_MEMBER_UPDATED', entity_type='User', entity_id=user.id, 
                      description=f"Usuário '{user.username}' movido/atualizado para equipe '{grupo.nome}' como '{new_role}'.",
                      details={'old_group_id': old_group_id, 'old_role': old_role, 
                               'new_group_id': group_id, 'new_role': new_role})
    return redirect(url_for('main.team_details', group_id=group_id))

@bp.route('/admin/teams/remove_member/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def remove_member_from_team(group_id, user_id):
    grupo = Grupo.query.get_or_404(group_id)
    user_to_remove = User.query.get_or_404(user_id)
    
    old_group_id = user_to_remove.grupo_id
    old_role = user_to_remove.role

    if user_to_remove.role == 'super_admin':
        flash('Não é possível remover um Super Administrador de uma equipe.', 'danger')
        log_system_action(action_type='TEAM_MEMBER_REMOVE_FAILED', entity_type='User', entity_id=user_to_remove.id, 
                          description=f"Tentativa de remover Super Admin '{user_to_remove.username}' da equipe '{grupo.nome}'.")
        return redirect(url_for('main.team_details', group_id=group_id))
    if user_to_remove.grupo_id != group_id:
        flash(f'Erro: {user_to_remove.username} não pertence à equipe {grupo.nome}.', 'danger')
        log_system_action(action_type='TEAM_MEMBER_REMOVE_FAILED', entity_type='User', entity_id=user_to_remove.id, 
                          description=f"Tentativa de remover '{user_to_remove.username}' da equipe '{grupo.nome}' falhou: não é membro.")
        return redirect(url_for('main.team_details', group_id=group_id))
    
    equipe_principal = Grupo.query.filter_by(nome="Equipe Principal").first()
    if equipe_principal:
        user_to_remove.grupo_id = equipe_principal.id
        user_to_remove.role = 'consultor'
        db.session.commit()
        flash(f'{user_to_remove.username} removido(a) da equipe {grupo.nome} e movido(a) para Equipe Principal.', 'info')
        log_system_action(action_type='TEAM_MEMBER_REMOVED', entity_type='User', entity_id=user_to_remove.id, 
                          description=f"Usuário '{user_to_remove.username}' removido da equipe '{grupo.nome}' e movido para '{equipe_principal.nome}'.",
                          details={'old_group_id': old_group_id, 'old_role': old_role, 
                                   'new_group_id': equipe_principal.id, 'new_role': 'consultor'})
    else:
        flash('Erro: Não foi possível mover o usuário para uma equipe padrão. Crie uma "Equipe Principal".', 'danger')
        log_system_action(action_type='TEAM_MEMBER_REMOVE_FAILED', entity_type='User', entity_id=user_to_remove.id, 
                          description=f"Tentativa de remover '{user_to_remove.username}' da equipe '{grupo.nome}' falhou: Equipe Principal não encontrada.")
    return redirect(url_for('main.team_details', group_id=group_id))

# --- O RESTANTE DO SEU ARQUIVO `routes.py` CONTINUA ABAIXO ---
# (As funções restantes não foram coladas para manter a resposta concisa,
# mas elas devem estar aqui no seu arquivo final)


@bp.route('/admin/users/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'consultor')
    grupo_id = request.form.get('grupo_id')
    
    if not all([username, email, password, role, grupo_id]):
        flash('Todos os campos são obrigatórios.', 'danger')
        log_system_action(action_type='USER_CREATE_FAILED', description=f"Tentativa de criar usuário falhou: campos obrigatórios vazios. Por: '{current_user.username}'.")
        return redirect(url_for('main.manage_users'))
    if User.query.filter_by(username=username).first():
        flash('Esse nome de utilizador já existe.', 'danger')
        log_system_action(action_type='USER_CREATE_FAILED', description=f"Tentativa de criar usuário '{username}' falhou: nome de usuário já existe. Por: '{current_user.username}'.")
        return redirect(url_for('main.manage_users'))
    if User.query.filter_by(email=email).first():
        flash('Esse email já está a ser utilizado.', 'danger')
        log_system_action(action_type='USER_CREATE_FAILED', description=f"Tentativa de criar usuário '{username}' com email '{email}' falhou: email já utilizado. Por: '{current_user.username}'.")
        return redirect(url_for('main.manage_users'))
    
    new_user = User(username=username, email=email, role=role, grupo_id=int(grupo_id))
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash('Utilizador criado com sucesso!', 'success')
    log_system_action(action_type='USER_CREATED', entity_type='User', entity_id=new_user.id, 
                      description=f"Usuário '{new_user.username}' criado com papel '{new_user.role}' no grupo '{new_user.grupo.nome}'.",
                      details={'email': new_user.email, 'role': new_user.role, 'grupo_id': new_user.grupo_id})
    return redirect(url_for('main.manage_users'))

@bp.route('/users/update_name/<int:user_id>', methods=['POST'])
@login_required
@require_role('super_admin', 'admin_parceiro')
def update_user_name(user_id):
    user_to_update = User.query.get_or_404(user_id)
    redirect_url = url_for('main.parceiro_manage_users') if current_user.role == 'admin_parceiro' else url_for('main.manage_users')

    if current_user.role == 'admin_parceiro' and not (user_to_update.role == 'consultor' and user_to_update.grupo_id == current_user.grupo_id):
        flash('Você não tem permissão para editar o nome deste usuário ou ele não pertence ao seu grupo.', 'danger')
        log_system_action(action_type='USER_UPDATE_FAILED', entity_type='User', entity_id=user_id, 
                          description=f"Tentativa não autorizada de editar nome de usuário '{user_to_update.username}' por '{current_user.username}'.",
                          details={'reason': 'Permissão negada ou fora do grupo.'})
        return redirect(redirect_url)

    old_username = user_to_update.username
    new_username = request.form.get('username')

    if not new_username or not new_username.strip():
        flash('O nome de usuário não pode ser vazio.', 'warning')
        log_system_action(action_type='USER_UPDATE_FAILED', entity_type='User', entity_id=user_id, 
                          description=f"Tentativa de renomear '{old_username}' falhou: nome vazio. Por: '{current_user.username}'.")
        return redirect(redirect_url)

    existing_user_with_name = User.query.filter(User.username.ilike(new_username.strip()), User.id != user_id).first()
    if existing_user_with_name:
        flash(f'O nome de usuário "{new_username.strip()}" já está em uso por outro usuário.', 'danger')
        log_system_action(action_type='USER_UPDATE_FAILED', entity_type='User', entity_id=user_id, 
                          description=f"Tentativa de renomear '{old_username}' para '{new_username}' falhou: nome já em uso. Por: '{current_user.username}'.")
        return redirect(redirect_url)

    user_to_update.username = new_username.strip()
    db.session.commit()
    flash('Nome de usuário atualizado com sucesso!', 'success')
    log_system_action(action_type='USER_NAME_UPDATED', entity_type='User', entity_id=user_id, 
                      description=f"Nome do usuário '{old_username}' alterado para '{new_username}'.",
                      details={'old_username': old_username, 'new_username': new_username})

    return redirect(redirect_url)

@bp.route('/admin/users/update_limits/<int:user_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def update_user_limits(user_id):
    user = User.query.get_or_404(user_id)
    old_wallet_limit = user.wallet_limit
    old_daily_pull_limit = user.daily_pull_limit
    
    try:
        wallet_limit = int(request.form.get('wallet_limit', user.wallet_limit))
        daily_pull_limit = int(request.form.get('daily_pull_limit', user.daily_pull_limit))
        
        changes = {}
        if wallet_limit != old_wallet_limit:
            user.wallet_limit = wallet_limit
            changes['wallet_limit'] = {'old': old_wallet_limit, 'new': wallet_limit}
        
        if daily_pull_limit != old_daily_pull_limit:
            user.daily_pull_limit = daily_pull_limit
            changes['daily_pull_limit'] = {'old': old_daily_pull_limit, 'new': daily_pull_limit}

        if changes:
            db.session.commit()
            flash(f'Limites do usuário {user.username} atualizados com sucesso!', 'success')
            log_system_action(action_type='USER_LIMITS_UPDATED', entity_type='User', entity_id=user.id, 
                              description=f"Limites de '{user.username}' atualizados.",
                              details=changes)
        else:
            flash('Nenhuma alteração de limite detectada.', 'info')

    except (ValueError, TypeError) as e:
        db.session.rollback()
        flash('Valores de limite inválidos. Por favor, insira apenas números.', 'danger')
        log_system_action(action_type='USER_LIMITS_UPDATE_FAILED', entity_type='User', entity_id=user.id, 
                          description=f"Tentativa de atualizar limites de '{user.username}' falhou: valores inválidos.",
                          details={'error': str(e), 'form_data': request.form.to_dict()})
                          
    return redirect(url_for('main.manage_users'))

@bp.route('/admin/users/delete/<int:id>', methods=['POST'])
@login_required
@require_role('super_admin', 'admin_parceiro')
def delete_user(id):
    user_to_delete = User.query.get_or_404(id)
    redirect_url = url_for('main.parceiro_manage_users') if current_user.role == 'admin_parceiro' else url_for('main.manage_users')

    if id == current_user.id:
        flash('Não pode eliminar a sua própria conta.', 'danger')
        log_system_action(action_type='USER_DELETE_FAILED', entity_type='User', entity_id=id,
                          description=f"Tentativa de auto-excluir a conta '{user_to_delete.username}'.")
        return redirect(redirect_url)

    delete_permitted = False
    if current_user.role == 'super_admin':
        if user_to_delete.role == 'super_admin':
             flash('A conta do Super Administrador não pode ser excluída.', 'danger')
             log_system_action(action_type='USER_DELETE_FAILED', entity_type='User', entity_id=id,
                               description=f"Tentativa de excluir a conta do Super Admin '{user_to_delete.username}'.")
             return redirect(redirect_url)
        delete_permitted = True
    elif current_user.role == 'admin_parceiro':
        if user_to_delete.role == 'consultor' and user_to_delete.grupo_id == current_user.grupo_id:
            delete_permitted = True

    if not delete_permitted:
        flash('Você não tem permissão para apagar este usuário ou ele não pertence ao seu grupo.', 'danger')
        log_system_action(action_type='USER_DELETE_FAILED', entity_type='User', entity_id=id,
                          description=f"Tentativa não autorizada de apagar usuário '{user_to_delete.username}' por '{current_user.username}'.",
                          details={'reason': 'Permissão negada ou fora do grupo.'})
        return redirect(redirect_url)

    username_deleted = user_to_delete.username
    user_email_deleted = user_to_delete.email
    user_role_deleted = user_to_delete.role
    user_group_deleted = user_to_delete.grupo.nome if user_to_delete.grupo else 'N/A'

    try:
        Lead.query.filter_by(consultor_id=id).update({'consultor_id': None})
        LeadConsumption.query.filter_by(user_id=id).delete(synchronize_session=False)
        ActivityLog.query.filter_by(user_id=id).delete(synchronize_session=False)
        BackgroundTask.query.filter_by(user_id=id).delete(synchronize_session=False)
        SystemLog.query.filter_by(user_id=id).update({'user_id': None})
        
        db.session.delete(user_to_delete)
        db.session.commit()
        
        flash('Utilizador eliminado com sucesso!', 'success')
        log_system_action(action_type='USER_DELETED', entity_type='User', entity_id=id,
                          description=f"Usuário '{username_deleted}' (Email: {user_email_deleted}, Perfil: {user_role_deleted}, Equipe: {user_group_deleted}) excluído.",
                          details={'deleted_username': username_deleted, 'deleted_email': user_email_deleted,
                                   'deleted_role': user_role_deleted, 'deleted_group': user_group_deleted})
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro ao eliminar o utilizador: {e}', 'danger')
        log_system_action(action_type='USER_DELETE_FAILED', entity_type='User', entity_id=id,
                          description=f"Erro ao excluir usuário '{username_deleted}': {e}",
                          details={'error': str(e)})

    return redirect(redirect_url)

@bp.route('/partner_logos/<filename>')
def serve_partner_logo(filename):
    return send_from_directory(current_app.config['PARTNER_LOGOS_FULL_PATH'], filename)

# --- ROTAS DE GESTÃO (ADMIN) ---

@bp.route('/admin/products')
@login_required
@require_role('super_admin')
def manage_products():
    products = Produto.query.order_by(Produto.name).all()
    return render_template('admin/manage_products.html', title="Gerir Produtos", products=products)

@bp.route('/admin/products/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_product():
    name = request.form.get('name')
    if name:
        try:
            new_product = Produto(name=name)
            db.session.add(new_product)
            db.session.commit()
            flash('Produto adicionado com sucesso!', 'success')
            log_system_action(action_type='PRODUCT_CREATED', entity_type='Product', entity_id=new_product.id, 
                              description=f"Produto '{new_product.name}' criado.")
        except IntegrityError:
            db.session.rollback()
            flash('Erro: Este produto já existe.', 'danger')
            log_system_action(action_type='PRODUCT_CREATE_FAILED', entity_type='Product', 
                              description=f"Tentativa de criar produto com nome duplicado: '{name}'.")
    return redirect(url_for('main.manage_products'))

@bp.route('/admin/products/delete/<int:id>', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_product(id):
    product_to_delete = Produto.query.get_or_404(id)
    product_name = product_to_delete.name
    
    task_id = start_background_task(
        delete_product_in_background,
        'delete_product',
        current_user.id,
        initial_message=f"A exclusão do produto '{product_name}' e seus leads associados está sendo processada em segundo plano.",
        product_id=id
    )
    log_system_action(action_type='PRODUCT_DELETE_BACKGROUND_INITIATED', entity_type='Product', entity_id=id, 
                      description=f"Exclusão do produto '{product_name}' e seus leads iniciada em segundo plano.",
                      details={'task_id': task_id})
    return jsonify({'status': 'processing', 'task_id': task_id, 'message': f"A exclusão do produto '{product_name}' e seus leads associados foi iniciada em segundo plano."})

@bp.route('/admin/layouts')
@login_required
@require_role('super_admin')
def manage_layouts():
    layouts = LayoutMailing.query.options(joinedload(LayoutMailing.produto)).order_by(LayoutMailing.name).all()
    return render_template('admin/manage_layouts.html', title="Gerir Layouts", layouts=layouts)

@bp.route('/admin/layouts/delete/<int:layout_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_layout(layout_id):
    layout_to_delete = LayoutMailing.query.get_or_404(layout_id)
    layout_name = layout_to_delete.name
    try:
        db.session.delete(layout_to_delete)
        db.session.commit()
        flash(f'Layout "{layout_name}" excluído com sucesso!', 'success')
        log_system_action(action_type='LAYOUT_DELETED', entity_type='LayoutMailing', entity_id=layout_id, 
                          description=f"Layout '{layout_name}' excluído.")
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro ao excluir o layout: {e}', 'danger')
        log_system_action(action_type='LAYOUT_DELETE_FAILED', entity_type='LayoutMailing', entity_id=layout_id, 
                          description=f"Erro ao excluir layout '{layout_name}'.",
                          details={'error': str(e)})
    return redirect(url_for('main.manage_layouts'))

def delete_leads_in_background(app, task_id, produto_id, estado):
    with app.app_context():
        task = BackgroundTask.query.get(task_id)
        if not task: return
        
        user_id_for_task = task.user_id

        task.status = 'RUNNING'
        task.start_time = get_brasilia_time()
        task.message = f"Iniciando exclusão de leads para Produto {produto_id} e Estado {estado}..."
        db.session.add(task)
        db.session.commit()
        
        try:
            estado_para_query = None if str(estado).lower() == 'none' else estado

            if estado_para_query is None:
                total_leads_to_delete = Lead.query.filter_by(produto_id=produto_id).filter(Lead.estado.is_(None)).count()
            else:
                total_leads_to_delete = Lead.query.filter_by(produto_id=produto_id, estado=estado_para_query).count()
            
            task.total_items = total_leads_to_delete
            task.items_processed = 0
            db.session.commit()

            if total_leads_to_delete == 0:
                task.status = 'COMPLETED'
                task.progress = 100
                task.message = f"Nenhum lead encontrado para o mailing de Produto {produto_id}, Estado {estado}. Concluído."
                task.end_time = get_brasilia_time()
                db.session.commit()
                log_system_action('MAILING_DELETE_COMPLETED', entity_type='Mailing', entity_id=produto_id, 
                                  description=f"Exclusão do mailing de produto {produto_id}, estado {estado} concluída (0 leads).",
                                  details={'estado': estado, 'produto_id': produto_id, 'total_leads_deleted': 0}, user_id=user_id_for_task)
                return

            batch_size = 1000 
            processed_count = 0

            while True:
                if estado_para_query is None:
                    leads_to_delete_query = db.session.query(Lead.id).filter_by(produto_id=produto_id).filter(Lead.estado.is_(None))
                else:
                    leads_to_delete_query = db.session.query(Lead.id).filter_by(produto_id=produto_id, estado=estado_para_query)

                leads_to_delete_ids = [lead.id for lead in leads_to_delete_query.limit(batch_size).all()]

                if not leads_to_delete_ids:
                    break 

                ActivityLog.query.filter(ActivityLog.lead_id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                LeadConsumption.query.filter(LeadConsumption.lead_id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                db.session.query(Lead).filter(Lead.id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                
                db.session.commit()

                processed_count += len(leads_to_delete_ids)
                task.items_processed = processed_count
                task.progress = min(100, int((processed_count / total_leads_to_delete) * 100))
                task.message = f"Processando... {processed_count}/{total_leads_to_delete} leads excluídos."
                db.session.commit()

            task.status = 'COMPLETED'
            task.progress = 100
            task.message = f"Exclusão do mailing de Produto {produto_id}, Estado {estado} concluída. Total de {processed_count} leads excluídos."
            task.end_time = get_brasilia_time()
            db.session.commit()
            log_system_action('MAILING_DELETE_COMPLETED', entity_type='Mailing', entity_id=produto_id, 
                              description=f"Exclusão do mailing de produto {produto_id}, estado {estado} concluída. {processed_count} leads excluídos.",
                              details={'estado': estado, 'produto_id': produto_id, 'total_leads_deleted': processed_count}, user_id=user_id_for_task)

        except Exception as e:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Erro na exclusão do mailing: {str(e)}"
            task.end_time = get_brasilia_time()
            db.session.commit()
            log_system_action('MAILING_DELETE_FAILED', entity_type='Mailing', entity_id=produto_id, 
                              description=f"Erro ao excluir mailing de produto {produto_id}, estado {estado}.",
                              details={'estado': estado, 'produto_id': produto_id, 'error': str(e)}, user_id=user_id_for_task)
        finally:
            db.session.remove() 

def delete_product_in_background(app, task_id, product_id): 
    with app.app_context(): 
        task = BackgroundTask.query.get(task_id)
        if not task: return
        
        user_id_for_task = task.user_id

        task.status = 'RUNNING'
        task.start_time = get_brasilia_time()
        task.message = f"Iniciando exclusão do produto e seus leads associados..."
        db.session.add(task)
        db.session.commit()

        try:
            produto = Produto.query.get(product_id)
            if not produto:
                raise ValueError("Produto não encontrado.")

            product_name = produto.name
            
            total_leads_to_delete = Lead.query.filter_by(produto_id=product_id).count()
            task.total_items = total_leads_to_delete
            task.items_processed = 0
            db.session.commit()

            if total_leads_to_delete == 0:
                task.status = 'COMPLETED'
                task.progress = 100
                task.message = f"Produto '{product_name}' excluído. Nenhum lead associado."
                task.end_time = get_brasilia_time()
                
                produto_final = Produto.query.get(product_id)
                if produto_final:
                    db.session.delete(produto_final)
                
                db.session.commit()
                
                log_system_action('PRODUCT_DELETE_COMPLETED', entity_type='Product', entity_id=product_id, 
                                  description=f"Produto '{product_name}' excluído (0 leads associados).",
                                  details={'product_name': product_name, 'total_leads_deleted': 0}, user_id=user_id_for_task)
                return

            batch_size = 1000
            processed_count = 0

            while True:
                leads_to_delete_ids = [
                    lead.id for lead in db.session.query(Lead.id)
                    .filter_by(produto_id=product_id)
                    .limit(batch_size).all()
                ]
                
                if not leads_to_delete_ids:
                    break

                ActivityLog.query.filter(ActivityLog.lead_id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                LeadConsumption.query.filter(LeadConsumption.lead_id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                db.session.query(Lead).filter(Lead.id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                
                db.session.commit()

                processed_count += len(leads_to_delete_ids)
                task.items_processed = processed_count
                task.progress = min(100, int((processed_count / total_leads_to_delete) * 100))
                task.message = f"Processando leads do produto '{product_name}': {processed_count}/{total_leads_to_delete} excluídos."
                db.session.commit()

            db.session.delete(produto)
            db.session.commit()

            task.status = 'COMPLETED'
            task.progress = 100
            task.message = f"Exclusão do produto '{product_name}' e seus {processed_count} leads associados concluída com sucesso."
            task.end_time = get_brasilia_time()
            db.session.commit()
            log_system_action('PRODUCT_DELETE_COMPLETED', entity_type='Product', entity_id=product_id, 
                              description=f"Produto '{product_name}' e seus {processed_count} leads associados excluídos.",
                              details={'product_name': product_name, 'total_leads_deleted': processed_count}, user_id=user_id_for_task)

        except Exception as e:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Erro na exclusão do produto: {str(e)}"
            task.end_time = get_brasilia_time()
            db.session.commit()
            log_system_action('PRODUCT_DELETE_FAILED', entity_type='Product', entity_id=product_id, 
                              description=f"Erro ao excluir produto '{product_name}'.",
                              details={'product_name': product_name, 'error': str(e)}, user_id=user_id_for_task)
        finally:
            db.session.remove() 

@bp.route('/admin/mailings')
@login_required
@require_role('super_admin')
def manage_mailings():
    mailing_groups = db.session.query(Lead.produto_id, Produto.name.label('produto_nome'), Lead.estado, func.count(Lead.id).label('total_leads'), func.count(case((Lead.status == 'Novo', Lead.id), else_=None)).label('leads_novos')).join(Produto, Lead.produto_id == Produto.id).group_by(Lead.produto_id, Produto.name, Lead.estado).order_by(Produto.name, Lead.estado).all()
    mailings_por_produto = defaultdict(list)
    for group in mailing_groups:
        mailings_por_produto[group.produto_nome].append(group)
    return render_template('admin/manage_mailings.html', title="Gerir Mailings", mailings_por_produto=mailings_por_produto)

@bp.route('/admin/mailings/delete', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_mailing():
    produto_id = request.form.get('produto_id')
    estado = request.form.get('estado')
    
    if not produto_id or not estado:
        return jsonify({'status': 'error', 'message': 'Informações do mailing inválidas.'})
    
    produto_nome = Produto.query.get(produto_id).name if Produto.query.get(produto_id) else 'Desconhecido'

    task_id = start_background_task(
        delete_leads_in_background,
        'delete_mailing',
        current_user.id,
        initial_message=f"A exclusão dos leads do mailing '{produto_nome}' ({estado}) está sendo processada em segundo plano.",
        produto_id=int(produto_id),
        estado=estado
    )
    log_system_action('MAILING_DELETE_BACKGROUND_INITIATED', entity_type='Mailing', entity_id=int(produto_id), 
                      description=f"Exclusão do mailing de produto {produto_nome}, estado {estado} iniciada em segundo plano.",
                      details={'estado': estado, 'produto_id': produto_id, 'task_id': task_id})

    return jsonify({'status': 'processing', 'task_id': task_id, 'message': f"A exclusão dos leads do mailing '{produto_nome}' ({estado}) foi iniciada em segundo plano."})

@bp.route('/admin/mailings/export')
@login_required
@require_role('super_admin')
def export_mailing():
    produto_id = request.args.get('produto_id')
    estado = request.args.get('estado')
    if not produto_id or not estado:
        flash('Informações do mailing inválidas.', 'danger')
        return redirect(url_for('main.manage_mailings'))
    leads = Lead.query.options(joinedload(Lead.produto), joinedload(Lead.tabulation), joinedload(Lead.consultor)).filter_by(produto_id=produto_id, estado=estado).order_by(Lead.data_criacao).all()
    if not leads:
        flash('Nenhum lead encontrado para este grupo.', 'warning')
        return redirect(url_for('main.manage_mailings'))
    data_for_df = [{'ID do Lead': lead.id, 'Nome': lead.nome, 'CPF': lead.cpf, 'Telefone 1': lead.telefone, 'Telefone 2': lead.telefone_2, 'Estado': lead.estado, 'Produto': lead.produto.name if lead.produto else 'N/A', 'Status': lead.status, 'Consultor': lead.consultor.username if lead.consultor else 'N/A', 'Tabulação': lead.tabulation.name if lead.tabulation else 'NÃO TABULADO', 'Data Tabulação': lead.data_tabulacao.strftime('%d/%m/%Y %H:%M') if lead.data_tabulacao else '', **(lead.additional_data or {})} for lead in leads]
    df = pd.DataFrame(data_for_df)
    output = io.StringIO()
    df.to_csv(output, index=False, sep=';', encoding='utf-8-sig')
    csv_data = output.getvalue()
    filename = f"mailing_{leads[0].produto.name}_{leads[0].estado}.csv".replace(" ", "_")
    return Response(csv_data, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={filename}"})

@bp.route('/admin/mailings/export_all')
@login_required
@require_role('super_admin')
def export_all_mailings():
    leads = Lead.query.options(joinedload(Lead.produto), joinedload(Lead.tabulation), joinedload(Lead.consultor)).order_by(Lead.produto_id, Lead.estado, Lead.data_criacao).all()
    if not leads:
        flash('Nenhum lead encontrado para exportar.', 'warning')
        return redirect(url_for('main.manage_mailings'))
    data_for_df = [{'Produto': lead.produto.name if lead.produto else 'N/A', 'Estado': lead.estado, 'Status': lead.status, 'Tabulação': lead.tabulation.name if lead.tabulation else 'NÃO TABULADO', 'Consultor': lead.consultor.username if lead.consultor else 'N/A', 'Nome': lead.nome, 'CPF': lead.cpf, 'Telefone 1': lead.telefone, 'Telefone 2': lead.telefone_2, **(lead.additional_data or {})} for lead in leads]
    df = pd.DataFrame(data_for_df)
    output = io.StringIO()
    df.to_csv(output, index=False, sep=';', encoding='utf-8-sig')
    csv_data = output.getvalue()
    filename = f"relatorio_completo_mailings_{get_brasilia_time().date().strftime('%Y-%m-%d')}.csv"
    return Response(csv_data, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={filename}"})

@bp.route('/admin/tabulations')
@login_required
@require_role('super_admin')
def manage_tabulations():
    tabulations = Tabulation.query.order_by(Tabulation.name).all()
    return render_template('admin/manage_tabulations.html', title="Gerir Tabulações", tabulations=tabulations)

@bp.route('/admin/tabulations/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_tabulation():
    name = request.form.get('name')
    color = request.form.get('color')
    is_recyclable = request.form.get('is_recyclable') == 'on'
    is_positive_conversion = request.form.get('is_positive_conversion') == 'on'
    recycle_in_days = int(request.form.get('recycle_in_days', 0)) if is_recyclable else None
    if name and color:
        new_tabulation = Tabulation(name=name, color=color, is_recyclable=is_recyclable, recycle_in_days=recycle_in_days, is_positive_conversion=is_positive_conversion)
        db.session.add(new_tabulation)
        try:
            db.session.commit()
            flash('Tabulação criada com sucesso!', 'success')
            log_system_action(action_type='TABULATION_CREATED', entity_type='Tabulation', entity_id=new_tabulation.id, 
                              description=f"Tabulação '{new_tabulation.name}' criada.",
                              details={'color': new_tabulation.color, 'is_recyclable': new_tabulation.is_recyclable, 
                                       'recycle_in_days': new_tabulation.recycle_in_days, 'is_positive_conversion': new_tabulation.is_positive_conversion})
        except IntegrityError:
            db.session.rollback()
            flash('Essa tabulação já existe.', 'danger')
            log_system_action(action_type='TABULATION_CREATE_FAILED', entity_type='Tabulation', 
                              description=f"Tentativa de criar tabulação com nome duplicado: '{name}'.")
    return redirect(url_for('main.manage_tabulations'))

@bp.route('/admin/tabulations/delete/<int:id>', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_tabulation(id):
    tabulation_to_delete = Tabulation.query.get_or_404(id)
    tabulation_name = tabulation_to_delete.name
    try:
        db.session.delete(tabulation_to_delete)
        db.session.commit()
        flash('Tabulação eliminada com sucesso!', 'success')
        log_system_action(action_type='TABULATION_DELETED', entity_type='Tabulation', entity_id=id, 
                          description=f"Tabulação '{tabulation_name}' excluída.")
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro ao excluir a tabulação: {e}', 'danger')
        log_system_action(action_type='TABULATION_DELETE_FAILED', entity_type='Tabulation', entity_id=id, 
                          description=f"Erro ao excluir tabulação '{tabulation_name}'.",
                          details={'error': str(e)})
    return redirect(url_for('main.manage_tabulations'))

@bp.route('/admin/export/tabulations')
@login_required
@require_role('super_admin')
def export_tabulations():
    results = ActivityLog.query.options(joinedload(ActivityLog.lead).joinedload(Lead.produto), joinedload(ActivityLog.user), joinedload(ActivityLog.tabulation)).order_by(ActivityLog.timestamp.asc()).all()
    if not results:
        flash('Nenhum dado encontrado para exportar.', 'warning')
        return redirect(url_for('main.admin_dashboard'))
    data_for_df = [{'Data da Ação': log.timestamp.strftime('%d/%m/%Y %H:%M:%S'), 'Tipo de Ação': log.action_type, 'Consultor': log.user.username if log.user else 'N/A', 'Cliente': log.lead.nome if log.lead else 'N/A', 'CPF': log.lead.cpf if log.lead else 'N/A', 'Produto': log.lead.produto.name if log.lead and log.lead.produto else 'N/A', 'Tabulação Escolhida': log.tabulation.name if log.tabulation else 'N/A'} for log in results]
    df = pd.DataFrame(data_for_df)
    output = io.StringIO()
    df.to_csv(output, index=False, sep=';', encoding='utf-8-sig')
    csv_data = output.getvalue()
    return Response(csv_data, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename=relatorio_completo_atividades.csv"})

@bp.route('/task_status/<string:task_id>', methods=['GET'])
@login_required
def get_task_status(task_id):
    task = BackgroundTask.query.get(task_id)
    if not task:
        return jsonify({'status': 'NOT_FOUND', 'message': 'Tarefa não encontrada'}), 404
    
    if current_user.id != task.user_id and current_user.role != 'super_admin':
        return jsonify({'status': 'FORBIDDEN', 'message': 'Você não tem permissão para ver esta tarefa.'}), 403

    return jsonify({
        'task_id': task.id,
        'status': task.status,
        'progress': task.progress,
        'message': task.message,
        'total_items': task.total_items,
        'items_processed': task.items_processed,
        'end_time': task.end_time.strftime('%Y-%m-%d %H:%M:%S') if task.end_time else None,
        'details': task.details
    })

# --- ROTAS DE HIGIENIZAÇÃO DE LEADS ---

@bp.route('/admin/hygiene/upload', methods=['GET', 'POST'])
@login_required
@require_role('super_admin')
def hygiene_upload_page():
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        if not uploaded_file:
            flash('Nenhum arquivo enviado.', 'danger')
            return redirect(url_for('main.hygiene_upload_page'))
        
        if not allowed_file(uploaded_file.filename):
            flash('Formato de arquivo inválido. Apenas .csv ou .xlsx são permitidos.', 'danger')
            return redirect(url_for('main.hygiene_upload_page'))
        
        temp_hygiene_filename = f"hygiene_{uuid.uuid4()}{os.path.splitext(uploaded_file.filename)[1]}"
        temp_hygiene_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_hygiene_filename)
        
        try:
            os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
            uploaded_file.save(temp_hygiene_filepath)
        except Exception as e:
            flash(f"Erro ao salvar arquivo temporário: {e}", 'danger')
            log_system_action(action_type='HYGIENE_UPLOAD_FAILED', description=f"Erro ao salvar arquivo de higienização temporário.", details={'error': str(e)})
            return redirect(url_for('main.hygiene_upload_page'))

        task_id = start_background_task(
            hygiene_compare_cpfs_background,
            'hygiene_compare',
            current_user.id,
            initial_message="Iniciando comparação de CPFs para higienização...",
            filepath=temp_hygiene_filepath
        )
        log_system_action(action_type='HYGIENE_UPLOAD_INITIATED', description=f"Upload de arquivo para higienização iniciado. Task ID: {task_id}")
        
        return redirect(url_for('main.hygiene_confirm_page', task_id=task_id))

    return render_template('admin/hygiene_upload.html', title='Higienizar Leads')

def hygiene_compare_cpfs_background(app, task_id, filepath):
    with app.app_context():
        task = BackgroundTask.query.get(task_id)
        if not task: return
        
        user_id_for_task = task.user_id

        task.status = 'RUNNING'
        task.message = "Lendo CPFs da planilha e comparando com leads existentes..."
        db.session.add(task)
        db.session.commit()

        leads_found = []

        try:
            if filepath.endswith('.csv'):
                df = pd.read_csv(filepath, sep=None, engine='python', encoding='latin1', dtype=str)
            else:
                df = pd.read_excel(filepath, dtype=str)
            
            cpf_column = next((col for col in df.columns if 'cpf' in str(col).lower()), None)

            if not cpf_column:
                raise ValueError("Nenhuma coluna 'CPF' encontrada na planilha.")

            total_cpfs_in_file = len(df)
            task.total_items = total_cpfs_in_file
            db.session.commit()

            batch_size = 5000
            
            existing_lead_cpfs_map = {lead.cpf: {'id': lead.id, 'nome': lead.nome} for lead in db.session.query(Lead.id, Lead.cpf, Lead.nome).all()}

            for i in range(0, total_cpfs_in_file, batch_size):
                batch_df = df.iloc[i:i+batch_size]
                for cpf_val in batch_df[cpf_column].dropna():
                    clean_cpf = re.sub(r'\D', '', str(cpf_val))
                    if len(clean_cpf) == 11 and clean_cpf in existing_lead_cpfs_map:
                        lead_info = existing_lead_cpfs_map[clean_cpf]
                        leads_found.append({'id': lead_info['id'], 'cpf': clean_cpf, 'nome': lead_info['nome']})
                
                task.items_processed = min(i + batch_size, total_cpfs_in_file)
                task.progress = min(99, int((task.items_processed / total_cpfs_in_file) * 100))
                task.message = f"Comparando CPFs: {task.progress}% concluído. Encontrados {len(leads_found)} leads para remoção."
                db.session.commit()
            
            task.status = 'COMPLETED'
            task.progress = 100
            task.message = f"Comparação concluída. {len(leads_found)} leads encontrados para higienização."
            task.end_time = get_brasilia_time()
            task.details = {'leads_to_delete_preview': leads_found}
            db.session.commit()
            log_system_action('HYGIENE_COMPARE_COMPLETED', user_id=user_id_for_task, 
                              description=f"Comparação de higienização de CPFs concluída. {len(leads_found)} leads encontrados.",
                              details={'total_cpfs_in_file': total_cpfs_in_file, 'leads_found_count': len(leads_found), 'task_id': task_id})

        except ValueError as ve:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Erro na planilha: {ve}"
            task.end_time = get_brasilia_time()
            db.session.commit()
            log_system_action('HYGIENE_COMPARE_FAILED', user_id=user_id_for_task, 
                              description=f"Comparação de higienização falhou: {ve}.",
                              details={'error': str(ve), 'task_id': task_id})
        except Exception as e:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Ocorreu um erro inesperado: {str(e)}"
            task.end_time = get_brasilia_time()
            db.session.commit()
            log_system_action('HYGIENE_COMPARE_FAILED', user_id=user_id_for_task, 
                              description=f"Comparação de higienização falhou: {e}.",
                              details={'error': str(e), 'task_id': task_id})
        finally:
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except OSError as e:
                    print(f"ERRO: Falha ao remover arquivo de higienização temporário {filepath}: {e}")
            db.session.remove()

@bp.route('/admin/hygiene/confirm/<string:task_id>', methods=['GET', 'POST'])
@login_required
@require_role('super_admin')
def hygiene_confirm_page(task_id):
    task = BackgroundTask.query.get(task_id)
    if not task:
        flash('Tarefa de higienização não encontrada ou inválida.', 'danger')
        return redirect(url_for('main.hygiene_upload_page'))
    
    if task.status in ['PENDING', 'RUNNING']:
        return render_template('admin/hygiene_confirm.html', 
                               title='Higienização - A Processar', 
                               task_id=task.id)
    
    if task.status == 'FAILED':
        flash(f"A tarefa de comparação de CPFs falhou: {task.message}", 'danger')
        log_system_action(action_type='HYGIENE_CONFIRM_FAILED', entity_type='BackgroundTask', entity_id=task.id, description="Acesso à confirmação de higienização falhou: tarefa com status FAILED.")
        return redirect(url_for('main.hygiene_upload_page'))

    leads_to_delete = task.details.get('leads_to_delete_preview', []) if task.details else []
    
    if request.method == 'POST':
        if not leads_to_delete:
            flash('Nenhum lead para higienizar.', 'warning')
            return redirect(url_for('main.hygiene_upload_page'))

        new_delete_task_id = start_background_task(
            hygiene_delete_leads_in_background,
            'hygiene_delete',
            current_user.id,
            initial_message=f"Iniciando exclusão de {len(leads_to_delete)} leads para higienização...",
            leads_to_delete_ids=[l['id'] for l in leads_to_delete]
        )
        log_system_action(action_type='HYGIENE_DELETE_INITIATED', entity_type='BackgroundTask', entity_id=new_delete_task_id, 
                          description=f"Higienização de {len(leads_to_delete)} leads confirmada. Task ID: {new_delete_task_id}",
                          details={'leads_count': len(leads_to_delete)})
        
        flash('A higienização dos leads foi iniciada em segundo plano. Você será notificado sobre o progresso.', 'info')
        return redirect(url_for('main.hygiene_confirm_page', task_id=new_delete_task_id))

    return render_template('admin/hygiene_confirm.html', 
                           title='Higienização - Confirmar', 
                           task_id=task.id)

def hygiene_delete_leads_in_background(app, task_id, leads_to_delete_ids):
    with app.app_context():
        task = BackgroundTask.query.get(task_id)
        if not task: return
        
        user_id_for_task = task.user_id

        task.status = 'RUNNING'
        task.message = "Iniciando exclusão dos leads..."
        db.session.add(task)
        db.session.commit()

        try:
            total_leads_to_delete = len(leads_to_delete_ids)
            task.total_items = total_leads_to_delete
            task.items_processed = 0
            db.session.commit()

            if total_leads_to_delete == 0:
                task.status = 'COMPLETED'
                task.progress = 100
                task.message = "Nenhum lead para higienizar. Concluído."
                task.end_time = get_brasilia_time()
                db.session.commit()
                log_system_action('HYGIENE_DELETE_COMPLETED', description="Higienização concluída (0 leads).", user_id=user_id_for_task)
                return

            batch_size = 1000
            processed_count = 0

            for i in range(0, total_leads_to_delete, batch_size):
                batch_ids = leads_to_delete_ids[i:i+batch_size]

                ActivityLog.query.filter(ActivityLog.lead_id.in_(batch_ids)).delete(synchronize_session=False)
                LeadConsumption.query.filter(LeadConsumption.lead_id.in_(batch_ids)).delete(synchronize_session=False)
                db.session.query(Lead).filter(Lead.id.in_(batch_ids)).delete(synchronize_session=False)
                
                db.session.commit()

                processed_count += len(batch_ids)
                task.items_processed = processed_count
                task.progress = min(100, int((processed_count / total_leads_to_delete) * 100))
                task.message = f"Higienizando... {processed_count}/{total_leads_to_delete} leads removidos."
                db.session.commit()

            task.status = 'COMPLETED'
            task.progress = 100
            task.message = f"Higienização concluída. Total de {processed_count} leads removidos do sistema."
            task.end_time = get_brasilia_time()
            db.session.commit()
            log_system_action('HYGIENE_DELETE_COMPLETED', description=f"Higienização concluída. {processed_count} leads removidos.", details={'total_removed': processed_count}, user_id=user_id_for_task)

        except Exception as e:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Erro na higienização: {str(e)}"
            task.end_time = get_brasilia_time()
            db.session.commit()
            log_system_action('HYGIENE_DELETE_FAILED', description=f"Higienização falhou: {e}.", details={'error': str(e)}, user_id=user_id_for_task)
        finally:
            db.session.remove()

# --- ROTAS DE EXPORTAÇÃO FILTRADA DE LEADS ---
@bp.route('/admin/reports')
@login_required
@require_role('super_admin')
def admin_export_reports_page():
    all_products = Produto.query.order_by(Produto.name).all()
    
    distinct_states = db.session.query(Lead.estado).distinct().order_by(Lead.estado).all()
    states_for_select = []
    for state_tuple in distinct_states:
        state_value = state_tuple[0]
        if state_value is None:
            states_for_select.append(('N/A (Sem Estado)', 'None')) 
        else:
            states_for_select.append((state_value, state_value))
    
    tabulation_statuses = [
        ('Todos os Leads', 'all'),
        ('Leads Tabulados', 'tabulated'),
        ('Leads Não Tabulados (Novos/Em Atendimento/Reciclados)', 'not_tabulated'),
        ('Leads em Atendimento', 'in_service'),
        ('Leads Novos (Nunca Atendidos)', 'new'),
        ('Leads Reciclados', 'recycled')
    ]

    return render_template('admin/export_reports.html', 
                           title="Relatórios de Leads", 
                           all_products=all_products, 
                           distinct_states=states_for_select,
                           tabulation_statuses=tabulation_statuses)

@bp.route('/admin/export_filtered_leads', methods=['GET'])
@login_required
@require_role('super_admin')
def admin_export_filtered_leads():
    tabulation_status = request.args.get('tabulation_status', 'all')
    product_ids_str = request.args.get('product_ids')
    states_str = request.args.get('states')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    leads_query = db.session.query(Lead).options(
        joinedload(Lead.produto),
        joinedload(Lead.tabulation),
        joinedload(Lead.consultor)
    )

    if tabulation_status == 'tabulated':
        leads_query = leads_query.filter(Lead.tabulation_id.isnot(None), Lead.status == 'Tabulado')
    elif tabulation_status == 'not_tabulated':
        leads_query = leads_query.filter(Lead.tabulation_id.is_(None), or_(Lead.status == 'Novo', Lead.status == 'Em Atendimento'))
    elif tabulation_status == 'in_service':
        leads_query = leads_query.filter(Lead.status == 'Em Atendimento')
    elif tabulation_status == 'new':
        leads_query = leads_query.filter(Lead.status == 'Novo', Lead.available_after.is_(None))
    elif tabulation_status == 'recycled':
        leads_query = leads_query.filter(Lead.status == 'Novo', Lead.available_after.isnot(None), Lead.available_after > get_brasilia_time())
    
    if product_ids_str:
        try:
            product_ids = [int(p_id) for p_id in product_ids_str.split(',') if p_id]
            if product_ids:
                leads_query = leads_query.filter(Lead.produto_id.in_(product_ids))
        except ValueError:
            flash('IDs de produto inválidos.', 'danger')
            return redirect(url_for('main.admin_export_reports_page'))

    if states_str:
        states = states_str.split(',')
        
        if 'None' in states:
            states_filtered = [s for s in states if s != 'None']
            if states_filtered:
                leads_query = leads_query.filter(or_(Lead.estado.in_(states_filtered), Lead.estado.is_(None)))
            else:
                leads_query = leads_query.filter(Lead.estado.is_(None))
        else:
            leads_query = leads_query.filter(Lead.estado.in_(states))

    if start_date_str:
        try:
            start_date_obj = datetime.strptime(start_date_str, '%Y-%m-%d')
            leads_query = leads_query.filter(Lead.data_criacao >= start_date_obj)
        except ValueError:
            flash('Data de início inválida.', 'danger')
            return redirect(url_for('main.admin_export_reports_page'))

    if end_date_str:
        try:
            end_date_obj = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1) - timedelta(microseconds=1)
            leads_query = leads_query.filter(Lead.data_criacao <= end_date_obj)
        except ValueError:
            flash('Data de fim inválida.', 'danger')
            return redirect(url_for('main.admin_export_reports_page'))

    leads_to_export = leads_query.order_by(Lead.data_criacao.desc()).all()

    if not leads_to_export:
        flash('Nenhum lead encontrado com os filtros selecionados para exportar.', 'warning')
        return redirect(url_for('main.admin_export_reports_page'))

    data_for_df = []
    for lead in leads_to_export:
        row = {
            'ID do Lead': lead.id,
            'Nome': lead.nome,
            'CPF': lead.cpf,
            'Telefone 1': lead.telefone,
            'Telefone 2': lead.telefone_2,
            'Estado': lead.estado if lead.estado is not None else 'N/A',
            'Produto': lead.produto.name if lead.produto else 'N/A',
            'Status Atual': lead.status,
            'Consultor Responsável': lead.consultor.username if lead.consultor else 'N/A',
            'Tabulação Final': lead.tabulation.name if lead.tabulation else 'NÃO TABULADO',
            'Data de Criação': lead.data_criacao.strftime('%d/%m/%Y %H:%M') if lead.data_criacao else '',
            'Data de Tabulação': lead.data_tabulacao.strftime('%d/%m/%Y %H:%M') if lead.data_tabulacao else '',
            'Disponível Após (Reciclagem)': lead.available_after.strftime('%d/%m/%Y %H:%M') if lead.available_after else '',
        }
        if lead.additional_data:
            for k, v in lead.additional_data.items():
                row[k] = v
        data_for_df.append(row)

    df = pd.DataFrame(data_for_df)

    base_columns_order = [
        'ID do Lead', 'Nome', 'CPF', 'Telefone 1', 'Telefone 2', 'Produto', 
        'Estado', 'Status Atual', 'Consultor Responsável', 'Tabulação Final', 
        'Data de Criação', 'Data de Tabulação', 'Disponível Após (Reciclagem)'
    ]
    
    all_df_columns = df.columns.tolist()
    
    ordered_columns = base_columns_order + [col for col in all_df_columns if col not in base_columns_order]
    
    df = df[ordered_columns]

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Relatorio_Leads_Filtrado')
    output.seek(0)

    filename = f"relatorio_leads_filtrado_{get_brasilia_time().date().strftime('%Y-%m-%d')}.xlsx"
    log_system_action('LEAD_EXPORT_FILTERED', entity_type='Lead', 
                      description=f"Exportação de relatório de leads filtrado com {len(leads_to_export)} leads.",
                      details={'filters': request.args.to_dict(), 'total_exported': len(leads_to_export)})
    return Response(output, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f"attachment;filename={filename}"})

# --- ROTAS DO PARCEIRO ---
@bp.route('/parceiro/dashboard')
@login_required
@require_role('admin_parceiro')
def parceiro_dashboard():
    user_ids_in_group = [user.id for user in User.query.filter_by(grupo_id=current_user.grupo_id).with_entities(User.id)]
    recent_activity = ActivityLog.query.filter(ActivityLog.user_id.in_(user_ids_in_group)).options(joinedload(ActivityLog.lead), joinedload(ActivityLog.user), joinedload(ActivityLog.tabulation)).order_by(ActivityLog.timestamp.desc()).limit(15).all()
    
    today = get_brasilia_time().date()
    start_of_month = datetime(today.year, today.month, 1)
    
    monthly_consumption = 0
    if user_ids_in_group:
        monthly_consumption = db.session.query(func.count(LeadConsumption.id))\
            .filter(LeadConsumption.user_id.in_(user_ids_in_group))\
            .filter(LeadConsumption.timestamp >= start_of_month)\
            .scalar() or 0
            
    return render_template('parceiro/dashboard.html', 
                           title=f"Painel - {current_user.grupo.nome}", 
                           recent_activity=recent_activity,
                           monthly_consumption=monthly_consumption,
                           grupo=current_user.grupo)

@bp.route('/parceiro/monitor')
@login_required
@require_role('admin_parceiro')
def parceiro_monitor():
    return render_template('parceiro/monitor.html', title="Monitor da Equipe", agents_data=[])


@bp.route('/api/parceiro/monitor_data')
@login_required
@require_role('admin_parceiro')
def parceiro_monitor_data():
    consultants = User.query.filter_by(role='consultor', grupo_id=current_user.grupo_id).all()
    
    brasilia_tz = pytz.timezone('America/Sao_Paulo')
    now_in_brasilia = get_brasilia_time()
    start_of_day = now_in_brasilia.replace(hour=0, minute=0, second=0, microsecond=0)
    
    agents_data = []
    for agent in consultants:
        real_status = agent.current_status

        inactivity_threshold = timedelta(minutes=2)
        if agent.last_activity_at:
            aware_last_activity = brasilia_tz.localize(agent.last_activity_at) if agent.last_activity_at.tzinfo is None else agent.last_activity_at.astimezone(brasilia_tz)
            if (now_in_brasilia - aware_last_activity) > inactivity_threshold and agent.current_status != 'Offline':
                real_status = 'Offline'
                update_user_status(agent, 'Offline')
                db.session.commit()

        current_work = Lead.query.join(Produto).filter(Lead.consultor_id == agent.id, Lead.status == 'Em Atendimento').with_entities(Produto.name).first()
        local_str = f"{agent.grupo.nome} / {current_work[0] if current_work else 'Nenhum'}"

        last_login_str = agent.last_login.astimezone(brasilia_tz).strftime('%d/%m/%Y às %H:%M') if agent.last_login else 'Nunca logou'

        calls_today = ActivityLog.query.filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day).count()
        conversions_today = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day, Tabulation.is_positive_conversion == True).count()
        
        agents_data.append({
            'name': agent.username, 
            'status': real_status,
            'local': local_str,
            'last_login': last_login_str,
            'calls_today': calls_today, 
            'conversions_today': conversions_today
        })
    
    agents_data.sort(key=lambda x: (x['conversions_today'], x['calls_today']), reverse=True)
    
    return jsonify(agents_data=agents_data)


@bp.route('/parceiro/performance_dashboard')
@login_required
@require_role('admin_parceiro')
def parceiro_performance_dashboard():
    period = request.args.get('periodo', 'hoje')
    today = get_brasilia_time().date()
    if period == 'ontem':
        start_date = datetime.combine(today - timedelta(days=1), time.min)
        end_date = datetime.combine(today - timedelta(days=1), time.max)
    elif period == '7dias':
        start_date = datetime.combine(today - timedelta(days=6), time.min)
        end_date = datetime.combine(today, time.max)
    else: # 'hoje'
        start_date = datetime.combine(today, time.min)
        end_date = datetime.combine(today, time.max)
    
    user_ids_in_group = [user.id for user in User.query.filter_by(grupo_id=current_user.grupo_id, role='consultor').with_entities(User.id)]
    
    total_calls_team = 0
    total_conversions_team = 0
    if user_ids_in_group:
        total_calls_team = ActivityLog.query.filter(ActivityLog.user_id.in_(user_ids_in_group), ActivityLog.timestamp.between(start_date, end_date)).count()
        total_conversions_team = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id.in_(user_ids_in_group), ActivityLog.timestamp.between(start_date, end_date), Tabulation.is_positive_conversion == True).count()

    team_conversion_rate = (total_conversions_team / total_calls_team * 100) if total_calls_team > 0 else 0
    
    pie_chart_data_query = db.session.query(Tabulation.name, Tabulation.color, func.count(ActivityLog.id)).join(ActivityLog).filter(ActivityLog.user_id.in_(user_ids_in_group), ActivityLog.timestamp.between(start_date, end_date)).group_by(Tabulation.name, Tabulation.color).order_by(func.count(ActivityLog.id).desc()).all()
    
    pie_chart_html = None
    legend_data = []
    if pie_chart_data_query:
        pie_data = {'labels': [r[0] for r in pie_chart_data_query], 'colors': [r[1] for r in pie_chart_data_query], 'data': [r[2] for r in pie_chart_data_query]}
        legend_data = zip(pie_data['labels'], pie_data['colors'])
        fig = go.Figure(data=[go.Pie(labels=pie_data['labels'], values=pie_data['data'], marker=dict(colors=pie_data['colors'], line=dict(color='#ffffff', width=2)), hole=.4, textinfo='percent', insidetextorientation='radial')])
        fig.update_layout(title_text=None, showlegend=False, height=300, margin=dict(t=10, b=10, l=10, r=10), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        pie_chart_html = pio.to_html(fig, full_html=False, include_plotlyjs='cdn', config={'displayModeBar': False})
        
    consultants = User.query.filter(User.id.in_(user_ids_in_group)).all()
    performance_data = []
    for consultant in consultants:
        total_calls = ActivityLog.query.filter(ActivityLog.user_id == consultant.id, ActivityLog.timestamp.between(start_date, end_date)).count()
        total_conversions = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id == consultant.id, ActivityLog.timestamp.between(start_date, end_date), Tabulation.is_positive_conversion == True).count()
        conversion_rate = (total_conversions / total_calls * 100) if total_calls > 0 else 0
        performance_data.append({'name': consultant.username, 'status': consultant.current_status, 'total_calls': total_calls, 'total_conversions': total_conversions, 'conversion_rate': conversion_rate})
    
    performance_data.sort(key=lambda x: (x['total_conversions'], x['total_calls']), reverse=True)
    
    kpis = {"total_calls": total_calls_team, "total_conversions": total_conversions_team, "conversion_rate": team_conversion_rate}
    context = {"title": "Desempenho da Equipe", "kpis": kpis, "pie_chart_html": pie_chart_html, "legend_data": legend_data, "performance_data": performance_data, "selected_period": period}
    
    return render_template('parceiro/performance_dashboard.html', **context)

@bp.route('/parceiro/performance_dashboard/export')
@login_required
@require_role('admin_parceiro')
def parceiro_performance_dashboard_export():
    period = request.args.get('periodo', 'hoje')
    today = get_brasilia_time().date()
    if period == 'ontem':
        start_date = datetime.combine(today - timedelta(days=1), time.min)
        end_date = datetime.combine(today - timedelta(days=1), time.max)
    elif period == '7dias':
        start_date = datetime.combine(today - timedelta(days=6), time.min)
        end_date = datetime.combine(today, time.max)
    else: # 'hoje'
        start_date = datetime.combine(today, time.min)
        end_date = datetime.combine(today, time.max)
    
    user_ids_in_group = [user.id for user in User.query.filter_by(grupo_id=current_user.grupo_id, role='consultor').with_entities(User.id)]
    
    consultants = User.query.filter(User.id.in_(user_ids_in_group)).all()
    performance_data = []
    for consultant in consultants:
        total_calls = ActivityLog.query.filter(ActivityLog.user_id == consultant.id, ActivityLog.timestamp.between(start_date, end_date)).count()
        total_conversions = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id == consultant.id, ActivityLog.timestamp.between(start_date, end_date), Tabulation.is_positive_conversion == True).count()
        conversion_rate = (total_conversions / total_calls * 100) if total_calls > 0 else 0
        performance_data.append({'Consultor': consultant.username, 'Status': consultant.current_status, 'Ligações': total_calls, 'Conversões': total_conversions, 'Taxa de Conversão (%)': f"{conversion_rate:.2f}"})
    
    df = pd.DataFrame(performance_data)
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Desempenho_Equipe')
    output.seek(0)

    filename = f"desempenho_equipe_{current_user.grupo.nome.replace(' ', '_')}_{period}_{today.strftime('%Y-%m-%d')}.xlsx"
    return Response(output, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f"attachment;filename={filename}"})

@bp.route('/parceiro/manage_users', methods=['GET', 'POST'])
@login_required
@require_role('admin_parceiro')
def parceiro_manage_users():
    group_id = current_user.grupo_id
    grupo = Grupo.query.get_or_404(group_id)
    
    if request.method == 'POST':
        total_limit = grupo.monthly_pull_limit or 0
        assigned_limits = 0
        
        limits_to_update = {}
        
        for user in grupo.users:
            if user.role == 'consultor':
                try:
                    limit = int(request.form.get(f'limit_{user.id}', 0))
                    if limit < 0:
                        flash('O limite de puxadas não pode ser negativo.', 'danger')
                        return redirect(url_for('main.parceiro_manage_users'))
                    assigned_limits += limit
                    limits_to_update[user.id] = limit
                except (ValueError, TypeError):
                    flash('Valor de limite inválido detectado.', 'danger')
                    return redirect(url_for('main.parceiro_manage_users'))

        if assigned_limits > total_limit:
            flash(f'A soma dos limites ({assigned_limits}) excede o limite total da equipe ({total_limit}).', 'danger')
            return redirect(url_for('main.parceiro_manage_users'))
            
        for user_id, limit in limits_to_update.items():
            user = User.query.get(user_id)
            if user:
                user.daily_pull_limit = limit
        
        db.session.commit()
        flash('Distribuição de leads atualizada com sucesso!', 'success')
        return redirect(url_for('main.parceiro_manage_users'))

    consultores = User.query.filter_by(grupo_id=group_id, role='consultor').order_by(User.username).all()
    
    total_assigned = sum(c.daily_pull_limit for c in consultores)

    return render_template('parceiro/manage_users.html', 
                           title="Gerir Consultores e Leads", 
                           consultores=consultores, 
                           grupo=grupo,
                           total_assigned=total_assigned)

# --- ROTAS DO CONSULTOR ---

@bp.route('/consultor/dashboard')
@login_required
@require_role('consultor')
def consultor_dashboard():
    update_user_status(current_user, 'Ocioso')
    db.session.commit()
    
    total_leads_in_wallet = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    
    start_of_day = get_brasilia_time().replace(hour=0, minute=0, second=0, microsecond=0)
    calls_today = ActivityLog.query.filter(
        ActivityLog.user_id == current_user.id,
        ActivityLog.timestamp >= start_of_day
    ).count()
    conversions_today = ActivityLog.query.join(Tabulation).filter(
        ActivityLog.user_id == current_user.id,
        ActivityLog.timestamp >= start_of_day,
        Tabulation.is_positive_conversion == True
    ).count()

    start_of_month = get_brasilia_time().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    calls_month = ActivityLog.query.filter(
        ActivityLog.user_id == current_user.id,
        ActivityLog.timestamp >= start_of_month
    ).count()
    conversions_month = ActivityLog.query.join(Tabulation).filter(
        ActivityLog.user_id == current_user.id,
        ActivityLog.timestamp >= start_of_month,
        Tabulation.is_positive_conversion == True
    ).count()

    available_products = Produto.query.all()

    return render_template('consultor_dashboard.html', 
                           title='Dashboard do Consultor',
                           total_leads_in_wallet=total_leads_in_wallet,
                           calls_today=calls_today,
                           conversions_today=conversions_today,
                           calls_month=calls_month,
                           conversions_month=conversions_month,
                           available_products=available_products)

@bp.route('/consultor/get_lead', methods=['POST'])
@login_required
@require_role('consultor')
def get_lead():
    produto_id = request.form.get('produto_id')
    if not produto_id:
        flash('Selecione um produto para puxar o lead.', 'warning')
        return redirect(url_for('main.consultor_dashboard'))

    current_wallet_size = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    if current_wallet_size >= current_user.wallet_limit:
        flash(f'Você atingiu o limite de {current_user.wallet_limit} leads na sua carteira.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))

    start_of_day = get_brasilia_time().replace(hour=0, minute=0, second=0, microsecond=0)
    leads_pulled_today = LeadConsumption.query.filter(
        LeadConsumption.user_id == current_user.id,
        LeadConsumption.timestamp >= start_of_day
    ).count()
    if leads_pulled_today >= current_user.daily_pull_limit:
        flash(f'Você atingiu seu limite diário de {current_user.daily_pull_limit} puxadas de lead.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))

    lead = Lead.query.filter(
        Lead.produto_id == produto_id,
        Lead.status == 'Novo',
        or_(Lead.available_after.is_(None), Lead.available_after <= get_brasilia_time())
    ).order_by(Lead.data_criacao).first()

    if lead:
        lead.consultor_id = current_user.id
        lead.status = 'Em Atendimento'
        
        consumption = LeadConsumption(
            lead_id=lead.id,
            user_id=current_user.id,
            timestamp=get_brasilia_time()
        )
        db.session.add(consumption)
        
        update_user_status(current_user, 'Em Atendimento')
        db.session.commit()
        
        log_system_action('LEAD_PULLED', entity_type='Lead', entity_id=lead.id, 
                          description=f"Lead '{lead.nome}' (ID: {lead.id}) puxado por '{current_user.username}'.")
                          
        return redirect(url_for('main.atendimento', lead_id=lead.id))
    else:
        flash('Nenhum lead novo disponível para este produto no momento.', 'warning')
        return redirect(url_for('main.consultor_dashboard'))

@bp.route('/atendimento/<int:lead_id>', methods=['GET', 'POST'])
@login_required
@require_role('consultor')
def atendimento(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    if lead.consultor_id != current_user.id:
        flash('Este lead não está atribuído a você.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))

    if request.method == 'POST':
        tabulation_id = request.form.get('tabulation_id')
        if not tabulation_id:
            flash('Selecione uma tabulação.', 'danger')
            return redirect(url_for('main.atendimento', lead_id=lead.id))

        tabulation = Tabulation.query.get(tabulation_id)
        if not tabulation:
            flash('Tabulação inválida.', 'danger')
            return redirect(url_for('main.atendimento', lead_id=lead.id))

        lead.status = 'Tabulado'
        lead.tabulation_id = tabulation.id
        lead.data_tabulacao = get_brasilia_time()

        if tabulation.is_recyclable and tabulation.recycle_in_days:
            lead.status = 'Novo' # Alterado de 'Reciclado' para 'Novo' para voltar à fila
            lead.available_after = get_brasilia_time() + timedelta(days=tabulation.recycle_in_days)
            lead.consultor_id = None

        activity = ActivityLog(
            lead_id=lead.id,
            user_id=current_user.id,
            action_type='Tabulação',
            tabulation_id=tabulation.id,
            timestamp=get_brasilia_time()
        )
        db.session.add(activity)
        
        update_user_status(current_user, 'Ocioso')
        db.session.commit()

        log_system_action('LEAD_TABULATED', entity_type='Lead', entity_id=lead.id, 
                          description=f"Lead '{lead.nome}' (ID: {lead.id}) tabulado como '{tabulation.name}' por '{current_user.username}'.",
                          details={'tabulation_id': tabulation.id, 'tabulation_name': tabulation.name})

        flash(f'Lead {lead.nome} tabulado com sucesso!', 'success')
        return redirect(url_for('main.consultor_dashboard'))

    tabulations = Tabulation.query.order_by(Tabulation.name).all()
    update_user_status(current_user, 'Em Atendimento')
    db.session.commit()
    
    phone_numbers = []
    if lead.telefone:
        phone_numbers.append({'label': 'Telefone 1', 'number': re.sub(r'\D', '', lead.telefone)})
    if lead.telefone_2:
        phone_numbers.append({'label': 'Telefone 2', 'number': re.sub(r'\D', '', lead.telefone_2)})

    lead_details = {
        'CPF': lead.cpf,
        'Cidade': lead.cidade,
        'Estado': lead.estado,
        'Bairro': lead.bairro,
        'Nascimento': lead.nascimento,
        'Idade': lead.idade,
        'Convênio': lead.convenio,
        'Orgão': lead.orgao,
        'Benefício': lead.beneficio
    }
    if lead.additional_data:
        lead_details.update(lead.additional_data)

    return render_template('atendimento.html', 
                           title='Atendimento', 
                           lead=lead, 
                           tabulations=tabulations,
                           phone_numbers=phone_numbers,
                           lead_details=lead_details)