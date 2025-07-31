# app/routes.py (CÓDIGO COMPLETO - FINAL E MAIS RECENTE)
import pandas as pd
import io
import re
import os
import uuid
import threading
import plotly.graph_objects as go
import plotly.io as pio
from collections import defaultdict
from functools import wraps
from flask import render_template, flash, redirect, url_for, request, Blueprint, jsonify, Response, current_app, abort, send_from_directory
from flask_login import login_user, logout_user, current_user, login_required
from app import db
from app.models import User, Lead, Proposta, Banco, Convenio, Situacao, TipoDeOperacao, LeadConsumption, Tabulation, Produto, LayoutMailing, ActivityLog, Grupo, BackgroundTask, SystemLog
from datetime import datetime, date, time, timedelta
from sqlalchemy import func, cast, Date, or_, case, and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from sqlalchemy.sql import text

bp = Blueprint('main', __name__)

# --- FUNÇÕES HELPER ---

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'csv', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_partner_logo(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower())
        filepath = os.path.join(current_app.config['PARTNER_LOGOS_FULL_PATH'], filename)
        try:
            os.makedirs(current_app.config['PARTNER_LOGOS_FULL_PATH'], exist_ok=True)
            file.save(filepath)
            print(f"DEBUG: Logo '{filename}' salvo no Volume em: {filepath}")
            return filename
        except Exception as e:
            print(f"ERRO: Falha ao salvar logo no Volume: {e} no caminho {filepath}")
            return None
    return None

def delete_partner_logo(filename):
    if filename:
        filepath = os.path.join(current_app.config['PARTNER_LOGOS_FULL_PATH'], filename)
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                print(f"DEBUG: Logo '{filename}' deletado do Volume em: {filepath}")
                return True
            except Exception as e:
                print(f"ERRO: Falha ao deletar logo do Volume: {e} no caminho {filepath}")
                return False
    return False


def generate_gradient(start_hex, end_hex, n_steps):
    if n_steps <= 1: return [start_hex]
    start_rgb = tuple(int(start_hex.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
    end_rgb = tuple(int(end_hex.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
    gradient = []
    for i in range(n_steps):
        intermediate_rgb = [int(start_rgb[j] + (float(i) / (n_steps - 1)) * (end_rgb[j] - start_rgb[j])) for j in range(3)]
        gradient.append('#{:02x}{:02x}{:02x}'.format(*intermediate_rgb))
    return gradient

def darken_color(hex_color, amount=0.8):
    hex_color = hex_color.lstrip('#')
    rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    dark_rgb = tuple(int(c * amount) for c in rgb)
    return '#{:02x}{:02x}{:02x}'.format(*dark_rgb)

def start_background_task(task_func, task_type, user_id, initial_message="", *args, **kwargs):
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

def log_system_action(action_type, entity_type=None, entity_id=None, description=None, details=None):
    user_id = current_user.id if current_user.is_authenticated else None
    
    log_entry = SystemLog(
        user_id=user_id,
        action_type=action_type,
        entity_type=entity_type,
        entity_id=entity_id,
        description=description,
        details=details
    )
    db.session.add(log_entry)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"ERRO: Falha ao salvar SystemLog: {e}")

# --- DECORADORES DE PERMISSÃO ---
def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: return redirect(url_for('main.login'))
            if current_user.role == 'super_admin': return f(*args, **kwargs)
            if current_user.role not in roles:
                flash('Acesso negado. Você não tem permissão para ver esta página.', 'danger')
                return redirect(url_for('main.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- FUNÇÃO HELPER DE STATUS ---
def update_user_status(user, new_status):
    user.current_status = new_status
    user.status_timestamp = datetime.utcnow()
    user.last_activity_at = datetime.utcnow()
    db.session.add(user)

# --- ROTAS DE AUTENTICAÇÃO E GERAIS ---
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('main.index'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user is None or not user.check_password(request.form.get('password')):
            flash('Email ou senha inválidos', 'danger')
            return redirect(url_for('main.login'))
        user.last_login = datetime.utcnow()
        db.session.add(user)
        login_user(user, remember=request.form.get('remember_me') is not None)
        if user.role == 'consultor':
            update_user_status(user, 'Ocioso')
        db.session.commit()
        log_system_action('LOGIN', entity_type='User', entity_id=user.id, description=f"Usuário '{user.username}' logou no sistema.")
        return redirect(url_for('main.index'))
    return render_template('login.html', title='Login')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if User.query.first() is not None:
        flash('O registro está desabilitado.', 'warning')
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        grupo_principal = Grupo.query.filter_by(nome="Equipe Principal").first()
        if not grupo_principal:
            grupo_principal = Grupo(nome="Equipe Principal")
            db.session.add(grupo_principal)
            db.session.flush()
        user = User(username=request.form.get('username'), email=request.form.get('email'), role='super_admin', grupo_id=grupo_principal.id)
        user.set_password(request.form.get('password'))
        db.session.add(user)
        db.session.commit()
        log_system_action('USER_REGISTERED_INITIAL_ADMIN', entity_type='User', entity_id=user.id, description=f"Primeiro Super Admin '{user.username}' registrado.")
        flash('Conta de Super Administrador criada com sucesso!', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title='Registrar Super Admin')

@bp.route('/logout')
@login_required
def logout():
    log_system_action('LOGOUT', entity_type='User', entity_id=current_user.id, description=f"Usuário '{current_user.username}' deslogou do sistema.")
    if current_user.is_authenticated and current_user.role == 'consultor':
        update_user_status(current_user, 'Offline')
        db.session.commit()
    logout_user()
    return redirect(url_for('main.login'))

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    if current_user.role == 'super_admin': return redirect(url_for('main.admin_dashboard'))
    elif current_user.role == 'admin_parceiro': return redirect(url_for('main.parceiro_dashboard'))
    else: return redirect(url_for('main.consultor_dashboard'))

@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        old_theme = current_user.theme
        theme_choice = request.form.get('theme')
        if theme_choice in ['default', 'dark', 'ocean']:
            current_user.theme = theme_choice
            db.session.commit()
            log_system_action('USER_THEME_CHANGED', entity_type='User', entity_id=current_user.id, 
                              description=f"Usuário '{current_user.username}' mudou o tema.",
                              details={'old_theme': old_theme, 'new_theme': theme_choice})
            flash_message = """Tema atualizado com sucesso!<script>localStorage.setItem('userTheme', '{new_theme}');window.location.reload();</script>""".format(new_theme=theme_choice)
            flash(flash_message, 'success')
        else:
            flash('Seleção de tema inválida.', 'danger')
        return redirect(url_for('main.profile'))
    return render_template('profile.html', title="Minhas Configurações")

@bp.route('/admin/dashboard')
@login_required
@require_role('super_admin')
def admin_dashboard():
    all_products = Produto.query.order_by(Produto.name).all()
    all_layouts = LayoutMailing.query.order_by(LayoutMailing.name).all()
    page = request.args.get('page', 1, type=int)
    recent_activity = ActivityLog.query.options(joinedload(ActivityLog.lead), joinedload(ActivityLog.user), joinedload(ActivityLog.tabulation)).order_by(ActivityLog.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)
    return render_template('admin/admin_dashboard.html', title='Dashboard do Admin', all_products=all_products, all_layouts=all_layouts, recent_activity=recent_activity)

@bp.route('/admin/monitor')
@login_required
@require_role('super_admin')
def admin_monitor():
    consultants = User.query.filter_by(role='consultor').all()
    start_of_day = datetime.combine(date.today(), time.min)
    agents_data = []
    for agent in consultants:
        inactivity_threshold_minutes = 2 
        if agent.role == 'consultor' and datetime.utcnow() - agent.last_activity_at > timedelta(minutes=inactivity_threshold_minutes):
            real_status = 'Offline'
            if agent.current_status != 'Offline':
                agent.current_status = 'Offline'
                agent.status_timestamp = datetime.utcnow()
                db.session.add(agent)
                db.session.commit()
        else:
            real_status = agent.current_status

        time_in_status = datetime.utcnow() - agent.status_timestamp
        hours, remainder = divmod(time_in_status.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        timer_str = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
        calls_today = ActivityLog.query.filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day).count()
        conversions_today = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day, Tabulation.is_positive_conversion == True).count()
        current_work = Lead.query.join(Produto).filter(Lead.consultor_id == agent.id, Lead.status == 'Em Atendimento').with_entities(Produto.name).first()
        agents_data.append({'id': agent.id, 'name': agent.username, 'status': real_status, 'last_login': agent.last_login, 'local': f"{agent.grupo.nome} / {current_work[0] if current_work else 'Nenhum'}", 'calls_today': calls_today, 'conversions_today': conversions_today})
    agents_data.sort(key=lambda x: (x['conversions_today'], x['calls_today']), reverse=True)
    return render_template('admin/monitor.html', title="Monitor Global", agents_data=agents_data)

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
            df = pd.read_csv(uploaded_file.stream, sep=None, engine='python', encoding='latin1', dtype=str)
        else:
            df = pd.read_excel(uploaded_file.stream, dtype=str)
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
    produto_id = request.form.get('produto_id')
    if not all([temp_filename, produto_id]):
        flash('Erro: informações da importação foram perdidas.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    temp_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
    if not os.path.exists(temp_filepath):
        flash('Erro: arquivo temporário não encontrado.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    
    leads_importados = 0
    try:
        mapping = {}
        layout_mapping_to_save = {}
        df_headers = pd.read_excel(temp_filepath, nrows=0) if temp_filepath.endswith('.xlsx') else pd.read_csv(temp_filepath, nrows=0, sep=None, engine='python', encoding='latin1', dtype=str)
        for i in range(len(df_headers.columns)):
            if f'include_column_{i}' in form_data:
                selected_system_field = form_data.get(f'mapping_{i}')
                if selected_system_field and selected_system_field != 'Ignorar':
                    original_header_name = form_data.get(f'header_name_{i}')
                    if original_header_name:
                        if selected_system_field in mapping:
                            flash(f'Erro: O campo do sistema "{selected_system_field}" foi mapeado para mais de uma coluna.', 'danger')
                            return redirect(url_for('main.admin_dashboard'))
                        mapping[selected_system_field] = original_header_name.lower().strip()
                        layout_mapping_to_save[selected_system_field] = original_header_name
        if 'cpf' not in mapping or 'nome' not in mapping:
            flash("Erro de mapeamento: As colunas 'CPF' e 'Nome' são obrigatórias.", 'danger')
            return redirect(url_for('main.admin_dashboard'))
        if form_data.get('save_layout') and form_data.get('layout_name'):
            existing_layout = LayoutMailing.query.filter_by(name=form_data.get('layout_name')).first()
            if existing_layout:
                flash(f'Erro: Já existe um layout salvo com o nome "{form_data.get("layout_name")}".', 'danger')
            else:
                new_layout = LayoutMailing(name=form_data.get('layout_name'), produto_id=int(produto_id), mapping=layout_mapping_to_save)
                db.session.add(new_layout)
                flash('Novo layout de mapeamento salvo com sucesso!', 'info')
        df = pd.read_excel(temp_filepath, dtype=str) if temp_filepath.endswith('.xlsx') else pd.read_csv(temp_filepath, sep=None, engine='python', encoding='latin1', dtype=str)
        original_headers = df.columns.copy()
        df.columns = [str(col).lower().strip() for col in df.columns]
        inversed_mapping = {v: k for k, v in mapping.items()}
        existing_cpfs = {lead.cpf for lead in Lead.query.with_entities(Lead.cpf).all()}
        leads_para_adicionar = []
        leads_ignorados = 0
        campos_do_modelo_lead = ['nome', 'cpf', 'telefone', 'telefone_2', 'cidade','rg','estado', 'bairro', 'cep', 'convenio', 'orgao', 'nome_mae', 'sexo', 'nascimento', 'idade', 'tipo_vinculo', 'rmc', 'valor_liberado', 'beneficio', 'logradouro', 'numero', 'complemento', 'extra_1', 'extra_2', 'extra_3', 'extra_4', 'extra_5', 'extra_6', 'extra_7', 'extra_8', 'extra_9', 'extra_10']
        
        for index, row in df.iterrows():
            row_data = {} 
            additional_data = {}

            for system_field, original_header_lower in mapping.items():
                valor = row.get(original_header_lower)
                if system_field in campos_do_modelo_lead: 
                    if 'telefone' in system_field:
                        row_data[system_field] = re.sub(r'\D', '', str(valor)) if pd.notna(valor) else None
                    elif system_field == 'estado':
                        row_data[system_field] = str(valor).strip().upper()[:2] if pd.notna(valor) else None
                    elif system_field == 'nascimento': 
                        if pd.notna(valor):
                            try:
                                row_data[system_field] = pd.to_datetime(valor).strftime('%Y-%m-%d')
                            except ValueError:
                                row_data[system_field] = str(valor).strip()
                        else:
                            row_data[system_field] = None
                    elif system_field == 'idade': 
                         row_data[system_field] = int(valor) if pd.notna(valor) and str(valor).isdigit() else None
                    else:
                        row_data[system_field] = str(valor).strip() if pd.notna(valor) else None
            
            for original_header in original_headers:
                original_header_lower = original_header.lower().strip()
                if original_header_lower not in mapping.values():
                    valor = row.get(original_header_lower)
                    if pd.notna(valor):
                        if original_header_lower not in [f.lower() for f in campos_do_modelo_lead] and \
                           original_header_lower not in [mapping['cpf'].lower(), mapping['nome'].lower()]:
                            additional_data[original_header.title()] = str(valor).strip()

            cpf_digits = re.sub(r'\D', '', str(row_data.get('cpf', '')))
            if not cpf_digits or len(cpf_digits) != 11 or cpf_digits in existing_cpfs:
                leads_ignorados += 1
                continue
            
            final_lead_data = {
                'produto_id': produto_id,
                'cpf': cpf_digits,
                'status': 'Novo',
                'data_criacao': datetime.utcnow(),
                'additional_data': additional_data 
            }
            final_lead_data.update(row_data) 
            
            if 'nome' not in final_lead_data:
                final_lead_data['nome'] = str(row_data.get('nome', 'Sem Nome')).strip()


            novo_lead = Lead(**final_lead_data)
            leads_para_adicionar.append(novo_lead)
            existing_cpfs.add(cpf_digits)

        if leads_para_adicionar:
            db.session.bulk_save_objects(leads_para_adicionar)
            leads_importados = len(leads_para_adicionar)
            flash(f'{leads_importados} leads importados com sucesso! {leads_ignorados} foram ignorados.', 'success')
        else:
            flash('Nenhum novo lead válido para importar foi encontrado na planilha.', 'warning')
        db.session.commit()
        log_system_action('LEAD_IMPORT', entity_type='Product', entity_id=int(produto_id), 
                          description=f"Importação de {leads_importados} leads para o produto '{Produto.query.get(int(produto_id)).name}'. {leads_ignorados} ignorados.",
                          details={'filename': temp_filename, 'total_imported': leads_importados, 'total_ignored': leads_ignorados})
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro crítico durante o processamento: {e}', 'danger')
        log_system_action('LEAD_IMPORT_FAILED', entity_type='Product', entity_id=int(produto_id), 
                          description=f"Erro crítico ao importar leads para o produto '{Produto.query.get(int(produto_id)).name}'.",
                          details={'filename': temp_filename, 'error': str(e)})
    finally:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
    return redirect(url_for('main.admin_dashboard'))

@bp.route('/admin/teams')
@login_required
@require_role('super_admin')
def manage_teams():
    teams_with_counts = db.session.query(Grupo, func.count(User.id)).outerjoin(User, Grupo.id == User.grupo_id).group_by(Grupo.id).order_by(Grupo.nome).all()
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

    return render_template(
        'admin/team_details.html', 
        title=f"Detalhes - {grupo.nome}", 
        grupo=grupo, 
        admins=admins, 
        consultores=consultores,
        total_logins_group=total_logins_group,
        available_users=available_users 
    )

@bp.route('/admin/groups/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_group():
    nome = request.form.get('name')
    color = request.form.get('color', '#6c757d')
    logo_file = request.files.get('logo_file')
    
    logo_filename = None
    if logo_file and logo_file.filename:
        logo_filename = save_partner_logo(logo_file)
        if not logo_filename:
            flash('Formato de arquivo de logo inválido ou erro ao salvar.', 'danger')
            log_system_action('GROUP_LOGO_UPLOAD_FAILED', entity_type='Group', description=f"Tentativa de upload de logo para novo grupo '{nome}' falhou.")
            return redirect(url_for('main.manage_teams'))

    if nome:
        existing_group = Grupo.query.filter_by(nome=nome).first()
        if existing_group:
            flash('Uma equipe com este nome já existe.', 'danger')
            log_system_action('GROUP_CREATE_FAILED', entity_type='Group', description=f"Tentativa de criar grupo com nome duplicado: '{nome}'.")
            if logo_filename:
                delete_partner_logo(logo_filename)
        else:
            new_group = Grupo(nome=nome, color=color, logo_filename=logo_filename)
            db.session.add(new_group)
            db.session.commit()
            flash('Equipe adicionada com sucesso!', 'success')
            log_system_action('GROUP_CREATED', entity_type='Group', entity_id=new_group.id, 
                              description=f"Grupo '{new_group.nome}' criado.",
                              details={'color': new_group.color, 'logo_filename': new_group.logo_filename})
    return redirect(url_for('main.manage_teams'))

@bp.route('/admin/groups/edit/<int:group_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def edit_group_name_color(group_id):
    grupo = Grupo.query.get_or_404(group_id)
    old_name = grupo.nome
    old_color = grupo.color
    old_logo_filename = grupo.logo_filename

    new_name = request.form.get('name')
    new_color = request.form.get('color')
    new_logo_file = request.files.get('logo_file')
    remove_logo = request.form.get('remove_logo') == 'on'

    changes = {}

    if new_name and new_name != grupo.nome:
        if Grupo.query.filter_by(nome=new_name).first():
            flash(f'Erro: Já existe uma equipe com o nome "{new_name}".', 'danger')
            log_system_action('GROUP_UPDATE_FAILED', entity_type='Group', entity_id=grupo.id, 
                              description=f"Tentativa de renomear grupo '{old_name}' para nome duplicado: '{new_name}'.")
            return redirect(url_for('main.team_details', group_id=group_id))
        grupo.nome = new_name
        changes['name'] = {'old': old_name, 'new': new_name}
    
    if new_color and new_color != grupo.color: 
        grupo.color = new_color
        changes['color'] = {'old': old_color, 'new': new_color}
    
    if remove_logo:
        if grupo.logo_filename:
            if delete_partner_logo(grupo.logo_filename):
                changes['logo'] = {'old': grupo.logo_filename, 'new': 'removido'}
                grupo.logo_filename = None
            else:
                flash('Erro ao remover arquivo de logo existente.', 'warning')
                log_system_action('GROUP_LOGO_DELETE_FAILED', entity_type='Group', entity_id=grupo.id, 
                                  description=f"Erro ao remover arquivo de logo '{grupo.logo_filename}' para o grupo '{grupo.nome}'.")
    elif new_logo_file and new_logo_file.filename:
        if allowed_file(new_logo_file.filename):
            saved_filename = save_partner_logo(new_logo_file)
            if saved_filename:
                if grupo.logo_filename:
                    delete_partner_logo(grupo.logo_filename)
                changes['logo'] = {'old': old_logo_filename, 'new': saved_filename}
                grupo.logo_filename = saved_filename
            else:
                flash('Erro ao salvar o novo arquivo de logo.', 'danger')
                log_system_action('GROUP_LOGO_UPLOAD_FAILED', entity_type='Group', entity_id=grupo.id, 
                                  description=f"Erro ao salvar novo logo para o grupo '{grupo.nome}'.")
        else:
            flash('Formato de arquivo de logo inválido. Use PNG, JPG, JPEG ou GIF.', 'danger')
            log_system_action('GROUP_LOGO_UPLOAD_FAILED', entity_type='Group', entity_id=grupo.id, 
                              description=f"Tentativa de upload de logo com formato inválido para o grupo '{grupo.nome}'.")

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
        log_system_action('GROUP_DELETE_FAILED', entity_type='Group', entity_id=grupo.id, 
                          description=f"Tentativa de excluir grupo '{group_name}' falhou: contém usuários.")
        return redirect(url_for('main.manage_teams'))
    
    db.session.delete(grupo)
    db.session.commit()
    
    if logo_to_delete:
        delete_partner_logo(logo_to_delete)
        log_system_action('GROUP_LOGO_DELETED_FILE', entity_type='Group', entity_id=group_id, 
                          description=f"Arquivo de logo '{logo_to_delete}' excluído do disco para o grupo '{group_name}'.")

    flash(f'Equipe "{grupo.nome}" excluída com sucesso!', 'success')
    log_system_action('GROUP_DELETED', entity_type='Group', entity_id=group_id, description=f"Grupo '{group_name}' excluído.")
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
        log_system_action('TEAM_MEMBER_ADD_FAILED', entity_type='User', entity_id=user.id, 
                          description=f"Tentativa de adicionar '{user.username}' ao grupo '{grupo.nome}' falhou: já pertence com o mesmo papel.")
        return redirect(url_for('main.team_details', group_id=group_id))
    
    user.grupo_id = group_id
    user.role = new_role
    db.session.commit()
    flash(f'{user.username} adicionado(a) como {new_role} à equipe {grupo.nome}!', 'success')
    log_system_action('TEAM_MEMBER_UPDATED', entity_type='User', entity_id=user.id, 
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
        log_system_action('TEAM_MEMBER_REMOVE_FAILED', entity_type='User', entity_id=user_to_remove.id, 
                          description=f"Tentativa de remover Super Admin '{user_to_remove.username}' da equipe '{grupo.nome}'.")
        return redirect(url_for('main.team_details', group_id=group_id))
    if user_to_remove.grupo_id != group_id:
        flash(f'Erro: {user_to_remove.username} não pertence à equipe {grupo.nome}.', 'danger')
        log_system_action('TEAM_MEMBER_REMOVE_FAILED', entity_type='User', entity_id=user_to_remove.id, 
                          description=f"Tentativa de remover '{user_to_remove.username}' da equipe '{grupo.nome}' falhou: não é membro.")
        return redirect(url_for('main.team_details', group_id=group_id))
    
    equipe_principal = Grupo.query.filter_by(nome="Equipe Principal").first()
    if equipe_principal:
        user_to_remove.grupo_id = equipe_principal.id
        user_to_remove.role = 'consultor'
        db.session.commit()
        flash(f'{user_to_remove.username} removido(a) da equipe {grupo.nome} e movido(a) para Equipe Principal.', 'info')
        log_system_action('TEAM_MEMBER_REMOVED', entity_type='User', entity_id=user_to_remove.id, 
                          description=f"Usuário '{user_to_remove.username}' removido da equipe '{grupo.nome}' e movido para '{equipe_principal.nome}'.",
                          details={'old_group_id': old_group_id, 'old_role': old_role, 
                                   'new_group_id': equipe_principal.id, 'new_role': 'consultor'})
    else:
        flash('Erro: Não foi possível mover o usuário para uma equipe padrão. Crie uma "Equipe Principal".', 'danger')
        log_system_action('TEAM_MEMBER_REMOVE_FAILED', entity_type='User', entity_id=user_to_remove.id, 
                          description=f"Tentativa de remover '{user_to_remove.username}' da equipe '{grupo.nome}' falhou: Equipe Principal não encontrada.")
    return redirect(url_for('main.team_details', group_id=group_id))

@bp.route('/admin/users')
@login_required
@require_role('super_admin')
def manage_users():
    search_query = request.args.get('search_query', '').strip()
    filter_role = request.args.get('filter_role', '').strip()
    filter_group = request.args.get('filter_group', '').strip()
    
    sort_by = request.args.get('sort_by', 'username').strip()
    sort_order = request.args.get('sort_order', 'asc').strip()

    users_query = User.query

    if search_query:
        search_pattern = f"%{search_query}%"
        users_query = users_query.filter(
            or_(
                User.username.ilike(search_pattern),
                User.email.ilike(search_pattern)
            )
        )

    if filter_role and filter_role != 'all':
        users_query = users_query.filter_by(role=filter_role)

    if filter_group and filter_group != 'all':
        try:
            filter_group_id = int(filter_group)
            users_query = users_query.filter_by(grupo_id=filter_group_id)
        except ValueError:
            flash("ID de grupo inválido para filtro.", "warning")

    if sort_by == 'username':
        if sort_order == 'desc':
            users_query = users_query.order_by(User.username.desc())
        else:
            users_query = users_query.order_by(User.username.asc())
    elif sort_by == 'email':
        if sort_order == 'desc':
            users_query = users_query.order_by(User.email.desc())
        else:
            users_query = users_query.order_by(User.email.asc())
    elif sort_by == 'group':
        users_query = users_query.join(Grupo)
        if sort_order == 'desc':
            users_query = users_query.order_by(Grupo.nome.desc())
        else:
            users_query = users_query.order_by(Grupo.nome.asc())
    elif sort_by == 'role':
        if sort_order == 'desc':
            users_query = users_query.order_by(User.role.desc())
        else:
            users_query = users_query.order_by(User.role.asc())

    users = users_query.all()
    
    grupos = Grupo.query.order_by(Grupo.nome).all()

    return render_template(
        'admin/manage_users.html', 
        title="Gerir Utilizadores", 
        users=users, 
        grupos=grupos,
        search_query=search_query,
        filter_role=filter_role,
        filter_group=filter_group,
        sort_by=sort_by,
        sort_order=sort_order
    )

@bp.route('/admin/users/add', methods=['POST'])
@login_required
@require_role('super_admin')
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'consultor')
    grupo_id = request.form.get('grupo_id')
    
    if current_user.role != 'super_admin':
        flash('Você não tem permissão para criar novos usuários.', 'danger')
        log_system_action('USER_CREATE_FAILED', description=f"Tentativa não autorizada de criar usuário por '{current_user.username}'.")
        return redirect(url_for('main.manage_users'))

    if not all([username, email, password, role, grupo_id]):
        flash('Todos os campos são obrigatórios.', 'danger')
        log_system_action('USER_CREATE_FAILED', description=f"Tentativa de criar usuário falhou: campos obrigatórios vazios. Por: '{current_user.username}'.")
        return redirect(url_for('main.manage_users'))
    if User.query.filter_by(username=username).first():
        flash('Esse nome de utilizador já existe.', 'danger')
        log_system_action('USER_CREATE_FAILED', description=f"Tentativa de criar usuário '{username}' falhou: nome de usuário já existe. Por: '{current_user.username}'.")
        return redirect(url_for('main.manage_users'))
    if User.query.filter_by(email=email).first():
        flash('Esse email já está a ser utilizado.', 'danger')
        log_system_action('USER_CREATE_FAILED', description=f"Tentativa de criar usuário '{username}' com email '{email}' falhou: email já utilizado. Por: '{current_user.username}'.")
        return redirect(url_for('main.manage_users'))
    
    new_user = User(username=username, email=email, role=role, grupo_id=int(grupo_id))
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash('Utilizador criado com sucesso!', 'success')
    log_system_action('USER_CREATED', entity_type='User', entity_id=new_user.id, 
                      description=f"Usuário '{new_user.username}' criado com papel '{new_user.role}' no grupo '{new_user.grupo.nome}'.",
                      details={'email': new_user.email, 'role': new_user.role, 'grupo_id': new_user.grupo_id})
    return redirect(url_for('main.manage_users'))

@bp.route('/users/update_name/<int:user_id>', methods=['POST'])
@login_required
@require_role('super_admin', 'admin_parceiro')
def update_user_name(user_id):
    user_to_update = User.query.get_or_404(user_id)

    if current_user.role == 'super_admin':
        pass
    elif current_user.role == 'admin_parceiro':
        if user_to_update.role == 'consultor' and user_to_update.grupo_id == current_user.grupo_id:
            pass
        else:
            flash('Você não tem permissão para editar o nome deste usuário ou ele não pertence ao seu grupo.', 'danger')
            log_system_action('USER_UPDATE_FAILED', entity_type='User', entity_id=user_id, 
                              description=f"Tentativa não autorizada de editar nome de usuário '{user_to_update.username}' por '{current_user.username}'.",
                              details={'reason': 'Permissão negada ou fora do grupo.'})
            return redirect(url_for('main.parceiro_manage_users'))
    else:
        flash('Você não tem permissão para realizar esta ação.', 'danger')
        log_system_action('USER_UPDATE_FAILED', entity_type='User', entity_id=user_id, 
                          description=f"Tentativa não autorizada de editar nome de usuário '{user_to_update.username}' por '{current_user.username}'.",
                          details={'reason': 'Papel não autorizado.'})
        return redirect(url_for('main.index'))

    old_username = user_to_update.username
    new_username = request.form.get('username')

    if not new_username or not new_username.strip():
        flash('O nome de usuário não pode ser vazio.', 'warning')
        log_system_action('USER_UPDATE_FAILED', entity_type='User', entity_id=user_id, 
                          description=f"Tentativa de renomear '{old_username}' falhou: nome vazio. Por: '{current_user.username}'.")
        if current_user.role == 'super_admin':
            return redirect(url_for('main.manage_users'))
        else:
            return redirect(url_for('main.parceiro_manage_users'))

    existing_user_with_name = User.query.filter(
        User.username.ilike(new_username.strip()),
        User.id != user_id
    ).first()

    if existing_user_with_name:
        flash(f'O nome de usuário "{new_username.strip()}" já está em uso por outro usuário.', 'danger')
        log_system_action('USER_UPDATE_FAILED', entity_type='User', entity_id=user_id, 
                          description=f"Tentativa de renomear '{old_username}' para '{new_username}' falhou: nome já em uso. Por: '{current_user.username}'.")
        if current_user.role == 'super_admin':
            return redirect(url_for('main.manage_users'))
        else:
            return redirect(url_for('main.parceiro_manage_users'))

    user_to_update.username = new_username.strip()
    db.session.commit()
    flash('Nome de usuário atualizado com sucesso!', 'success')
    log_system_action('USER_NAME_UPDATED', entity_type='User', entity_id=user_id, 
                      description=f"Nome do usuário '{old_username}' alterado para '{new_username}'.",
                      details={'old_username': old_username, 'new_username': new_username})

    if current_user.role == 'super_admin':
        return redirect(url_for('main.manage_users'))
    else:
        return redirect(url_for('main.parceiro_manage_users'))

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
            log_system_action('USER_LIMITS_UPDATED', entity_type='User', entity_id=user.id, 
                              description=f"Limites de '{user.username}' atualizados.",
                              details=changes)
        else:
            flash('Nenhuma alteração de limite detectada.', 'info')

    except (ValueError, TypeError) as e:
        db.session.rollback()
        flash('Valores de limite inválidos. Por favor, insira apenas números.', 'danger')
        log_system_action('USER_LIMITS_UPDATE_FAILED', entity_type='User', entity_id=user.id, 
                          description=f"Tentativa de atualizar limites de '{user.username}' falhou: valores inválidos.",
                          details={'error': str(e), 'form_data': request.form.to_dict()})
    return redirect(url_for('main.manage_users'))

@bp.route('/admin/users/delete/<int:id>', methods=['POST'])
@login_required
@require_role('super_admin', 'admin_parceiro')
def delete_user(id):
    user_to_delete = User.query.get_or_404(id)

    if id == current_user.id:
        flash('Não pode eliminar a sua própria conta.', 'danger')
        log_system_action('USER_DELETE_FAILED', entity_type='User', entity_id=id, 
                          description=f"Tentativa de auto-excluir a conta '{user_to_delete.username}'.")
        if current_user.role == 'super_admin':
            return redirect(url_for('main.manage_users'))
        else:
            return redirect(url_for('main.parceiro_manage_users'))

    delete_permitted = False
    if current_user.role == 'super_admin':
        delete_permitted = True
    elif current_user.role == 'admin_parceiro':
        if user_to_delete.role == 'consultor' and user_to_delete.grupo_id == current_user.grupo_id:
            delete_permitted = True
    
    if not delete_permitted:
        flash('Você não tem permissão para apagar este usuário ou ele não pertence ao seu grupo.', 'danger')
        log_system_action('USER_DELETE_FAILED', entity_type='User', entity_id=id, 
                          description=f"Tentativa não autorizada de apagar usuário '{user_to_delete.username}' por '{current_user.username}'.",
                          details={'reason': 'Permissão negada ou fora do grupo.'})
        if current_user.role == 'super_admin':
            return redirect(url_for('main.manage_users'))
        return redirect(url_for('main.parceiro_manage_users'))

    username_deleted = user_to_delete.username
    user_email_deleted = user_to_delete.email
    user_role_deleted = user_to_delete.role
    user_group_deleted = user_to_delete.grupo.nome if user_to_delete.grupo else 'N/A'

    db.session.delete(user_to_delete)
    db.session.commit()
    flash('Utilizador eliminado com sucesso!', 'success')
    log_system_action('USER_DELETED', entity_type='User', entity_id=id, 
                      description=f"Usuário '{username_deleted}' (Email: {user_email_deleted}, Perfil: {user_role_deleted}, Equipe: {user_group_deleted}) excluído.",
                      details={'deleted_username': username_deleted, 'deleted_email': user_email_deleted, 
                               'deleted_role': user_role_deleted, 'deleted_group': user_group_deleted})
    
    if current_user.role == 'super_admin':
        return redirect(url_for('main.manage_users'))
    else:
        return redirect(url_for('main.parceiro_manage_users'))

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
            log_system_action('PRODUCT_CREATED', entity_type='Product', entity_id=new_product.id, 
                              description=f"Produto '{new_product.name}' criado.")
        except IntegrityError:
            db.session.rollback()
            flash('Erro: Este produto já existe.', 'danger')
            log_system_action('PRODUCT_CREATE_FAILED', entity_type='Product', 
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
    log_system_action('PRODUCT_DELETE_BACKGROUND_INITIATED', entity_type='Product', entity_id=id, 
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
        log_system_action('LAYOUT_DELETED', entity_type='LayoutMailing', entity_id=layout_id, 
                          description=f"Layout '{layout_name}' excluído.")
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro ao excluir o layout: {e}', 'danger')
        log_system_action('LAYOUT_DELETE_FAILED', entity_type='LayoutMailing', entity_id=layout_id, 
                          description=f"Erro ao excluir layout '{layout_name}'.",
                          details={'error': str(e)})
    return redirect(url_for('main.manage_layouts'))

def delete_leads_in_background(app, task_id, produto_id, estado):
    with app.app_context():
        task = BackgroundTask.query.get(task_id)
        if not task: return
        
        task.status = 'RUNNING'
        task.start_time = datetime.utcnow()
        task.message = f"Iniciando exclusão de leads para Produto {produto_id} e Estado {estado}..."
        db.session.add(task)
        db.session.commit()
        db.session.refresh(task) 
        
        try:
            estado_para_query = None if str(estado).lower() == 'none' else estado

            if estado_para_query is None:
                total_leads_to_delete = Lead.query.filter_by(produto_id=produto_id).filter(Lead.estado.is_(None)).count()
            else:
                total_leads_to_delete = Lead.query.filter_by(produto_id=produto_id, estado=estado_para_query).count()
            
            task.total_items = total_leads_to_delete
            task.items_processed = 0
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)

            if total_leads_to_delete == 0:
                task.status = 'COMPLETED'
                task.progress = 100
                task.message = f"Nenhum lead encontrado para o mailing de Produto {produto_id}, Estado {estado}. Concluído."
                task.end_time = datetime.utcnow()
                db.session.add(task)
                db.session.commit()
                db.session.refresh(task)
                log_system_action('MAILING_DELETE_COMPLETED', entity_type='Mailing', entity_id=produto_id, 
                                  description=f"Exclusão do mailing de produto {produto_id}, estado {estado} concluída (0 leads).",
                                  details={'estado': estado, 'produto_id': produto_id, 'total_leads_deleted': 0})
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
                db.session.add(task)
                db.session.commit()
                db.session.refresh(task)

            task.status = 'COMPLETED'
            task.progress = 100
            task.message = f"Exclusão do mailing de Produto {produto_id}, Estado {estado} concluída. Total de {processed_count} leads excluídos."
            task.end_time = datetime.utcnow()
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)
            log_system_action('MAILING_DELETE_COMPLETED', entity_type='Mailing', entity_id=produto_id, 
                              description=f"Exclusão do mailing de produto {produto_id}, estado {estado} concluída. {processed_count} leads excluídos.",
                              details={'estado': estado, 'produto_id': produto_id, 'total_leads_deleted': processed_count})

        except Exception as e:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Erro na exclusão do mailing: {str(e)}"
            task.end_time = datetime.utcnow()
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)
            log_system_action('MAILING_DELETE_FAILED', entity_type='Mailing', entity_id=produto_id, 
                              description=f"Erro ao excluir mailing de produto {produto_id}, estado {estado}.",
                              details={'estado': estado, 'produto_id': produto_id, 'error': str(e)})
        finally:
            db.session.remove() 

def delete_product_in_background(app, task_id, product_id): 
    with app.app_context(): 
        task = BackgroundTask.query.get(task_id)
        if not task: return

        task.status = 'RUNNING'
        task.start_time = datetime.utcnow()
        task.message = f"Iniciando exclusão do produto e seus leads associados..."
        db.session.add(task)
        db.session.commit()
        db.session.refresh(task)

        try:
            produto = Produto.query.get(product_id)
            if not produto:
                raise ValueError("Produto não encontrado.")

            product_name = produto.name
            
            total_leads_to_delete = Lead.query.filter_by(produto_id=product_id).count()
            task.total_items = total_leads_to_delete
            task.items_processed = 0
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)

            if total_leads_to_delete == 0:
                task.status = 'COMPLETED'
                task.progress = 100
                task.message = f"Produto '{product_name}' excluído. Nenhum lead associado."
                task.end_time = datetime.utcnow()
                db.session.add(task)
                db.session.commit()
                db.session.refresh(task)
                
                produto_final = Produto.query.get(product_id)
                if produto_final:
                    db.session.delete(produto_final)
                    db.session.commit()
                log_system_action('PRODUCT_DELETE_COMPLETED', entity_type='Product', entity_id=product_id, 
                                  description=f"Produto '{product_name}' excluído (0 leads associados).",
                                  details={'product_name': product_name, 'total_leads_deleted': 0})
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
                db.session.add(task)
                db.session.commit()
                db.session.refresh(task)

            db.session.delete(produto)
            db.session.commit()

            task.status = 'COMPLETED'
            task.progress = 100
            task.message = f"Exclusão do produto '{product_name}' e seus {processed_count} leads associados concluída com sucesso."
            task.end_time = datetime.utcnow()
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)
            log_system_action('PRODUCT_DELETE_COMPLETED', entity_type='Product', entity_id=product_id, 
                              description=f"Produto '{product_name}' e seus {processed_count} leads associados excluídos.",
                              details={'product_name': product_name, 'total_leads_deleted': processed_count})

        except Exception as e:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Erro na exclusão do produto: {str(e)}"
            task.end_time = datetime.utcnow()
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)
            log_system_action('PRODUCT_DELETE_FAILED', entity_type='Product', entity_id=product_id, 
                              description=f"Erro ao excluir produto '{product_name}'.",
                              details={'product_name': product_name, 'error': str(e)})
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
    filename = f"relatorio_completo_mailings_{date.today().strftime('%Y-%m-%d')}.csv"
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
            log_system_action('TABULATION_CREATED', entity_type='Tabulation', entity_id=new_tabulation.id, 
                              description=f"Tabulação '{new_tabulation.name}' criada.",
                              details={'color': new_tabulation.color, 'is_recyclable': new_tabulation.is_recyclable, 
                                       'recycle_in_days': new_tabulation.recycle_in_days, 'is_positive_conversion': new_tabulation.is_positive_conversion})
        except IntegrityError:
            db.session.rollback()
            flash('Essa tabulação já existe.', 'danger')
            log_system_action('TABULATION_CREATE_FAILED', entity_type='Tabulation', 
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
        log_system_action('TABULATION_DELETED', entity_type='Tabulation', entity_id=id, 
                          description=f"Tabulação '{tabulation_name}' excluída.")
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro ao excluir a tabulação: {e}', 'danger')
        log_system_action('TABULATION_DELETE_FAILED', entity_type='Tabulation', entity_id=id, 
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
        'end_time': task.end_time.strftime('%Y-%m-%d %H:%M:%S') if task.end_time else None
    })

# ADICIONADO: Nova rota para servir as imagens do volume persistente
@bp.route('/partner_logos/<filename>')
def serve_partner_logo(filename):
    return send_from_directory(current_app.config['PARTNER_LOGOS_FULL_PATH'], filename)

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
        
        # Salva o arquivo temporariamente para processamento em segundo plano
        temp_hygiene_filename = f"hygiene_{uuid.uuid4()}{os.path.splitext(uploaded_file.filename)[1]}"
        temp_hygiene_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_hygiene_filename)
        
        try:
            os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
            uploaded_file.save(temp_hygiene_filepath)
        except Exception as e:
            flash(f"Erro ao salvar arquivo temporário: {e}", 'danger')
            log_system_action('HYGIENE_UPLOAD_FAILED', description=f"Erro ao salvar arquivo de higienização temporário.", details={'error': str(e)})
            return redirect(url_for('main.hygiene_upload_page'))

        # Inicia a tarefa em segundo plano para comparar CPFs
        task_id = start_background_task(
            hygiene_compare_cpfs_background,
            'hygiene_compare',
            current_user.id,
            initial_message="Iniciando comparação de CPFs para higienização...",
            filepath=temp_hygiene_filepath,
            user_id_for_task=current_user.id
        )
        log_system_action('HYGIENE_UPLOAD_INITIATED', description=f"Upload de arquivo para higienização iniciado. Task ID: {task_id}")
        
        return redirect(url_for('main.hygiene_confirm_page', task_id=task_id))

    return render_template('admin/hygiene_upload.html', title='Higienizar Leads')

# Função em segundo plano para comparar CPFs
def hygiene_compare_cpfs_background(app, task_id, filepath, user_id_for_task):
    with app.app_context():
        task = BackgroundTask.query.get(task_id)
        if not task: return

        task.status = 'RUNNING'
        task.message = "Lendo CPFs da planilha e comparando com leads existentes..."
        db.session.add(task)
        db.session.commit()
        db.session.refresh(task)

        cpfs_from_file = set()
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
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)

            batch_size = 5000
            
            existing_lead_cpfs_map = {lead.cpf: {'id': lead.id, 'nome': lead.nome} for lead in db.session.query(Lead.id, Lead.cpf, Lead.nome).all()}


            for i in range(0, total_cpfs_in_file, batch_size):
                batch_df = df[i:i+batch_size]
                for cpf_val in batch_df[cpf_column].dropna():
                    clean_cpf = re.sub(r'\D', '', str(cpf_val))
                    if len(clean_cpf) == 11 and clean_cpf in existing_lead_cpfs_map:
                        lead_info = existing_lead_cpfs_map[clean_cpf]
                        leads_found.append({'id': lead_info['id'], 'cpf': clean_cpf, 'nome': lead_info['nome']})
                
                task.items_processed = min(i + batch_size, total_cpfs_in_file)
                task.progress = min(99, int((task.items_processed / total_cpfs_in_file) * 100))
                task.message = f"Comparando CPFs: {task.progress}% concluído. Encontrados {len(leads_found)} leads para remoção."
                db.session.add(task)
                db.session.commit()
                db.session.refresh(task)
            
            task.status = 'COMPLETED'
            task.progress = 100
            task.message = f"Comparação concluída. {len(leads_found)} leads encontrados para higienização."
            task.end_time = datetime.utcnow()
            task.details = {'leads_to_delete_preview': leads_found}
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)
            log_system_action('HYGIENE_COMPARE_COMPLETED', user_id=user_id_for_task, 
                              description=f"Comparação de higienização de CPFs concluída. {len(leads_found)} leads encontrados.",
                              details={'total_cpfs_in_file': total_cpfs_in_file, 'leads_found_count': len(leads_found), 'task_id': task_id})

        except ValueError as ve:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Erro na planilha: {ve}"
            task.end_time = datetime.utcnow()
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)
            log_system_action('HYGIENE_COMPARE_FAILED', user_id=user_id_for_task, 
                              description=f"Comparação de higienização falhou: {ve}.",
                              details={'error': str(ve), 'task_id': task_id})
        except Exception as e:
            db.session.rollback()
            task.status = 'FAILED'
            task.message = f"Ocorreu um erro inesperado: {str(e)}"
            task.end_time = datetime.utcnow()
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)
            log_system_action('HYGIENE_COMPARE_FAILED', user_id=user_id_for_task, 
                              description=f"Comparação de higienização falhou: {e}.",
                              details={'error': str(e), 'task_id': task_id})
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)
            db.session.remove()

@bp.route('/admin/hygiene/confirm/<string:task_id>', methods=['GET', 'POST'])
@login_required
@require_role('super_admin')
def hygiene_confirm_page(task_id):
    task = BackgroundTask.query.get(task_id)
    if not task:
        flash('Tarefa de higienização não encontrada ou inválida.', 'danger')
        return redirect(url_for('main.hygiene_upload_page'))
    
    if task.status == 'PENDING' or task.status == 'RUNNING':
        return render_template('admin/hygiene_confirm.html', 
                               title='Higienização - Confirmar', 
                               task_id=task.id, 
                               task_status=task.status,
                               task_message=task.message,
                               leads_to_delete=[])
    
    if task.status == 'FAILED':
        flash(f"A comparação de CPFs falhou: {task.message}", 'danger')
        log_system_action('HYGIENE_CONFIRM_FAILED', entity_type='BackgroundTask', entity_id=task_id, description="Acesso à confirmação de higienização falhou: tarefa com status FAILED.")
        return redirect(url_for('main.hygiene_upload_page'))

    leads_to_delete = task.details.get('leads_to_delete_preview', [])
    
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
        log_system_action('HYGIENE_DELETE_INITIATED', entity_type='BackgroundTask', entity_id=new_delete_task_id, 
                          description=f"Higienização de {len(leads_to_delete)} leads confirmada. Task ID: {new_delete_task_id}",
                          details={'leads_count': len(leads_to_delete)})
        
        flash('A higienização dos leads foi iniciada em segundo plano. Você será notificado sobre o progresso.', 'info')
        return redirect(url_for('main.hygiene_confirm_page', task_id=new_delete_task_id))

    return render_template('admin/hygiene_confirm.html', 
                           title='Higienização - Confirmar', 
                           task_id=task.id, 
                           task_status=task.status,
                           task_message=task.message,
                           leads_to_delete=leads_to_delete,
                           total_found=len(leads_to_delete))

# Função em segundo plano para deletar os leads confirmados
def hygiene_delete_leads_in_background(app, task_id, leads_to_delete_ids):
    with app.app_context():
        task = BackgroundTask.query.get(task_id)
        if not task: return

        task.status = 'RUNNING'
        task.message = "Iniciando exclusão dos leads..."
        db.session.add(task)
        db.session.commit()
        db.session.refresh(task)

        total_leads_to_delete = len(leads_to_delete_ids)
        task.total_items = total_leads_to_delete
        task.items_processed = 0
        db.session.add(task)
        db.session.commit()
        db.session.refresh(task)

        if total_leads_to_delete == 0:
            task.status = 'COMPLETED'
            task.progress = 100
            task.message = "Nenhum lead para higienizar. Concluído."
            task.end_time = datetime.utcnow()
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)
            log_system_action('HYGIENE_DELETE_COMPLETED', description="Higienização concluída (0 leads).")
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
            db.session.add(task)
            db.session.commit()
            db.session.refresh(task)

        task.status = 'COMPLETED'
        task.progress = 100
        task.message = f"Higienização concluída. Total de {processed_count} leads removidos do sistema."
        task.end_time = datetime.utcnow()
        db.session.add(task)
        db.session.commit()
        db.session.refresh(task)
        log_system_action('HYGIENE_DELETE_COMPLETED', description=f"Higienização concluída. {processed_count} leads removidos.", details={'total_removed': processed_count})

    except Exception as e:
        db.session.rollback()
        task.status = 'FAILED'
        task.message = f"Erro na higienização: {str(e)}"
        task.end_time = datetime.utcnow()
        db.session.add(task)
        db.session.commit()
        db.session.refresh(task)
        log_system_action('HYGIENE_DELETE_FAILED', description=f"Higienização falhou: {e}.", details={'error': str(e)})
    finally:
        db.session.remove()

# --- ROTAS DE EXPORTAÇÃO FILTRADA DE LEADS (MANTIDAS) ---
# ... (restante do routes.py, incluindo as rotas de exportação filtrada, parceiro, consultor)
# --- ROTAS DE EXPORTAÇÃO FILTRADA DE LEADS (MANTIDAS) ---
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
        leads_query = leads_query.filter(Lead.status == 'Novo', Lead.available_after.isnot(None), Lead.available_after > datetime.now(timezone.utc))
    
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

    filename = f"relatorio_leads_filtrado_{date.today().strftime('%Y-%m-%d')}.xlsx"
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
    return render_template('parceiro/dashboard.html', title=f"Painel - {current_user.grupo.nome}", recent_activity=recent_activity)

@bp.route('/parceiro/monitor')
@login_required
@require_role('admin_parceiro')
def parceiro_monitor():
    consultants = User.query.filter_by(role='consultor', grupo_id=current_user.grupo_id).all()
    start_of_day = datetime.combine(date.today(), time.min)
    agents_data = []
    for agent in consultants:
        inactivity_threshold_minutes = 2 
        if agent.role == 'consultor' and datetime.now(timezone.utc) - agent.last_activity_at > timedelta(minutes=inactivity_threshold_minutes):
            real_status = 'Offline'
            if agent.current_status != 'Offline':
                agent.current_status = 'Offline'
                agent.status_timestamp = datetime.now(timezone.utc)
                db.session.add(agent)
                db.session.commit()
        else:
            real_status = agent.current_status

        time_in_status = datetime.now(timezone.utc) - agent.status_timestamp
        hours, remainder = divmod(time_in_status.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        timer_str = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
        calls_today = ActivityLog.query.filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day).count()
        conversions_today = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day, Tabulation.is_positive_conversion == True).count()
        current_work = Lead.query.join(Produto).filter(Lead.consultor_id == agent.id, Lead.status == 'Em Atendimento').with_entities(Produto.name).first()
        agents_data.append({'id': agent.id, 'name': agent.username, 'status': real_status, 'local': current_work[0] if current_work else "Nenhum", 'calls_today': calls_today, 'conversions_today': conversions_today})
    agents_data.sort(key=lambda x: (x['conversions_today'], x['calls_today']), reverse=True)
    return render_template('parceiro/monitor.html', title="Monitor da Equipe", agents_data=agents_data)

@bp.route('/parceiro/performance_dashboard')
@login_required
@require_role('admin_parceiro')
def parceiro_performance_dashboard():
    period = request.args.get('periodo', 'hoje')
    today = date.today()
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
        # [CORRIGIDO] Filtra as conversões de todos os usuários no grupo, não apenas do admin
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
    
    # [CORRIGIDO] Usa as chaves corretas ('total_conversions', 'total_calls') para ordenação
    performance_data.sort(key=lambda x: (x['total_conversions'], x['total_calls']), reverse=True)
    
    kpis = {"total_calls": total_calls_team, "total_conversions": total_conversions_team, "conversion_rate": team_conversion_rate}
    context = {"title": "Desempenho da Equipe", "kpis": kpis, "pie_chart_html": pie_chart_html, "legend_data": legend_data, "performance_data": performance_data, "selected_period": period}
    
    return render_template('parceiro/performance_dashboard.html', **context)

@bp.route('/parceiro/performance_dashboard/export')
@login_required
@require_role('admin_parceiro')
def parceiro_export_performance():
    period = request.args.get('periodo', 'hoje')
    today = date.today()
    if period == 'ontem':
        start_date = datetime.combine(today - timedelta(days=1), time.min)
        end_date = datetime.combine(today - timedelta(days=1), time.max)
    elif period == '7dias':
        start_date = datetime.combine(today - timedelta(days=6), time.min)
        end_date = datetime.combine(today, time.max)
    else:
        start_date = datetime.combine(today, time.min)
        end_date = datetime.combine(today, time.max)
    user_ids_in_group = [user.id for user in User.query.filter_by(grupo_id=current_user.grupo_id, role='consultor').with_entities(User.id)]
    consultants = User.query.filter(User.id.in_(user_ids_in_group)).all()
    performance_data = []
    for consultant in consultants:
        total_calls = ActivityLog.query.filter(ActivityLog.user_id == consultant.id, ActivityLog.timestamp.between(start_date, end_date)).count()
        total_conversions = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id == consultant.id, ActivityLog.timestamp.between(start_date, end_date), Tabulation.is_positive_conversion == True).count()
        conversion_rate = (total_conversions / total_calls * 100) if total_calls > 0 else 0
        performance_data.append({'Consultor': consultant.username, 'Ligações': total_calls, 'Conversões': total_conversions, 'Taxa de Conversão (%)': round(conversion_rate, 2)})
    performance_data.sort(key=lambda x: x['Conversões'], reverse=True)
    if not performance_data:
        flash('Nenhum dado de desempenho para exportar.', 'warning')
        return redirect(url_for('main.parceiro_performance_dashboard', periodo=period))
    df = pd.DataFrame(performance_data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Desempenho_Equipe')
    output.seek(0)
    filename = f"desempenho_{current_user.grupo.nome}_{period}_{date.today()}.xlsx"
    return Response(output, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f"attachment;filename={filename}"})

@bp.route('/parceiro/users')
@login_required
@require_role('admin_parceiro')
def parceiro_manage_users():
    users = User.query.filter(User.grupo_id == current_user.grupo_id, User.role == 'consultor').order_by(User.username).all()
    return render_template('parceiro/manage_users.html', title="Gerir Nomes da Equipe", users=users)

# --- ROTAS DO CONSULTOR ---
@bp.route('/consultor/dashboard')
@login_required
@require_role('consultor')
def consultor_dashboard():
    start_of_day = datetime.combine(date.today(), time.min)
    leads_em_atendimento = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    leads_consumidos_hoje = LeadConsumption.query.filter(LeadConsumption.user_id == current_user.id, LeadConsumption.timestamp >= start_of_day).count()
    vagas_na_carteira = current_user.wallet_limit - leads_em_atendimento
    vagas_na_puxada_diaria = current_user.daily_pull_limit - leads_consumidos_hoje
    mailings_disponiveis = []
    if vagas_na_carteira > 0 and vagas_na_puxada_diaria > 0:
        mailings_disponiveis = db.session.query(Lead.produto_id, Produto.name.label('produto_nome'), Lead.estado, func.count(Lead.id).label('leads_disponiveis')).join(Produto, Lead.produto_id == Produto.id).filter(Lead.status == 'Novo', Lead.consultor_id == None, or_(Lead.available_after == None, Lead.available_after <= datetime.now(timezone.utc))).group_by(Lead.produto_id, Produto.name, Lead.estado).order_by(Produto.name, Lead.estado).all()
    search_history = request.args.get('search_history', '')
    history_query = ActivityLog.query.options(joinedload(ActivityLog.lead), joinedload(ActivityLog.tabulation)).filter(ActivityLog.user_id == current_user.id)
    if search_history:
        search_term = f"%{search_history}%"
        history_query = history_query.join(Lead).filter(or_(Lead.nome.ilike(search_term), Lead.cpf.ilike(search_term)))
    tabulated_history = history_query.order_by(ActivityLog.timestamp.desc()).all()
    all_tabulations = Tabulation.query.order_by(Tabulation.name).all()
    return render_template('consultor_dashboard.html', title='Meu Painel', vagas_na_carteira=vagas_na_carteira, leads_em_atendimento=leads_em_atendimento, leads_consumidos_hoje=leads_consumidos_hoje, vagas_na_puxada_diaria=vagas_na_puxada_diaria, current_user=current_user, mailings_disponiveis=mailings_disponiveis, tabulated_history=tabulated_history, search_history=search_history, all_tabulations=all_tabulations)

@bp.route('/pegar_leads_selecionados', methods=['POST'])
@login_required
@require_role('consultor')
def pegar_leads_selecionados():
    leads_em_atendimento = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    start_of_day = datetime.combine(date.today(), time.min)
    leads_consumidos_hoje = LeadConsumption.query.filter(LeadConsumption.user_id == current_user.id, LeadConsumption.timestamp >= start_of_day).count()
    vagas_na_carteira = current_user.wallet_limit - leads_em_atendimento
    vagas_na_puxada_diaria = current_user.daily_pull_limit - leads_consumidos_hoje
    limite_total_a_pegar = min(vagas_na_carteira, vagas_na_puxada_diaria)
    leads_pegos_total = 0
    for key, value in request.form.items():
        if key.startswith('leads_') and value.isdigit() and int(value) > 0:
            quantidade_a_pegar = int(value)
            if leads_pegos_total + quantidade_a_pegar > limite_total_a_pegar:
                quantidade_a_pegar = limite_total_a_pegar - leads_pegos_total
            if quantidade_a_pegar <= 0: continue
            try:
                produto_id, estado = key.replace('leads_', '').split('-')
                produto_id = int(produto_id)
            except (ValueError, IndexError):
                continue
            leads_disponiveis = Lead.query.filter(Lead.status == 'Novo', Lead.consultor_id == None, Lead.produto_id == produto_id, Lead.estado == estado, or_(Lead.available_after == None, Lead.available_after <= datetime.now(timezone.utc))).limit(quantidade_a_pegar).all()
            if leads_disponiveis:
                try:
                    for lead in leads_disponiveis:
                        lead.consultor_id = current_user.id
                        lead.status = 'Em Atendimento'
                        consumo = LeadConsumption(user_id=current_user.id, lead_id=lead.id)
                        db.session.add(consumo)
                    db.session.commit()
                    leads_pegos_total += len(leads_disponiveis)
                except Exception as e:
                    db.session.rollback()
                    flash(f'Ocorreu um erro ao atribuir leads: {e}', 'danger')
                    return redirect(url_for('main.consultor_dashboard'))
    if leads_pegos_total > 0:
        flash(f'{leads_pegos_total} novos leads foram adicionados à sua carteira!', 'success')
    else:
        flash('Nenhum lead foi selecionado ou não havia leads disponíveis nos lotes escolhidos.', 'warning')
    return redirect(url_for('main.consultor_dashboard'))

@bp.route('/atendimento')
@login_required
@require_role('consultor')
def atendimento():
    lead_para_atender = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').order_by(Lead.data_criacao).first()
    if not lead_para_atender:
        update_user_status(current_user, 'Ocioso')
        db.session.commit()
        flash('Parabéns, você não tem mais leads pendentes para atender!', 'success')
        return redirect(url_for('main.consultor_dashboard'))
    update_user_status(current_user, 'Falando')
    db.session.commit()
    tabulations = Tabulation.query.order_by(Tabulation.name).all()
    campos_principais_ordenados = [('Nome', lead_para_atender.nome), ('CPF', lead_para_atender.cpf), ('Estado', lead_para_atender.estado), ('Telefone', lead_para_atender.telefone), ('Telefone 2', lead_para_atender.telefone_2)]
    lead_details = {chave.replace('_', ' ').title(): valor for chave, valor in campos_principais_ordenados if valor}
    if lead_para_atender.additional_data:
        for key, value in lead_para_atender.additional_data.items():
            if key.title() not in lead_details:
                lead_details[key.title()] = value
    phone_numbers = []
    processed_numbers = set()
    for label, phone_number in [('Telefone Principal', lead_para_atender.telefone), ('Telefone 2', lead_para_atender.telefone_2)]:
        if phone_number and phone_number.strip():
            clean_phone = re.sub(r'\D', '', phone_number)
            if len(clean_phone) >= 8 and clean_phone not in processed_numbers:
                phone_numbers.append({'label': label, 'number': clean_phone})
                processed_numbers.add(clean_phone)
    if lead_para_atender.additional_data:
        phone_key_fragments = ['tel', 'fone', 'cel', 'whatsapp']
        for key, value in lead_para_atender.additional_data.items():
            if any(fragment in str(key).lower() for fragment in phone_key_fragments):
                if value and str(value).strip():
                    clean_phone = re.sub(r'\D', '', str(value))
                    if len(clean_phone) >= 8 and clean_phone not in processed_numbers:
                        phone_numbers.append({'label': key.title(), 'number': clean_phone})
                        processed_numbers.add(clean_phone)
    return render_template('atendimento.html', title="Atendimento de Lead", lead=lead_para_atender, lead_details=lead_details, tabulations=tabulations, phone_numbers=phone_numbers)

@bp.route('/atender/<int:lead_id>', methods=['POST'])
@login_required
@require_role('consultor')
def atender_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    if lead.consultor_id != current_user.id:
        flash('Este lead não pertence a você.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))
    tabulation_id = request.form.get('tabulation_id')
    if not tabulation_id:
        flash('Selecione uma opção de tabulação.', 'warning')
        return redirect(url_for('main.atendimento'))
    tabulation = Tabulation.query.get(int(tabulation_id))
    if not tabulation:
        flash('Tabulação inválida.', 'danger')
        return redirect(url_for('main.atendimento'))
    action_type = ''
    if tabulation.is_recyclable and tabulation.recycle_in_days is not None:
        recycle_date = datetime.now(timezone.utc) + timedelta(days=tabulation.recycle_in_days)
        lead.status = 'Novo'
        lead.consultor_id = None
        lead.tabulation_id = None
        lead.data_tabulacao = None 
        lead.available_after = recycle_date
        action_type = 'Reciclagem'
        flash(f'Lead de {lead.nome} será reciclado em {tabulation.recycle_in_days} dias.', 'info')
    else:
        lead.tabulation_id = tabulation.id
        lead.status = 'Tabulado'
        lead.data_tabulacao = datetime.now(timezone.utc)
        action_type = 'Tabulação'
        flash(f'Lead de {lead.nome} tabulado com sucesso!', 'success')
    activity_log_entry = ActivityLog(lead_id=lead.id, user_id=current_user.id, tabulation_id=tabulation.id, action_type=action_type)
    db.session.add(activity_log_entry)
    db.session.commit()
    return redirect(url_for('main.atendimento'))

@bp.route('/retabulate/<int:lead_id>', methods=['POST'])
@login_required
@require_role('consultor', 'admin_parceiro', 'super_admin')
def retabulate_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    last_activity = ActivityLog.query.filter_by(lead_id=lead.id).order_by(ActivityLog.timestamp.desc()).first()
    if not last_activity:
        flash('Nenhuma atividade anterior encontrada para este lead.', 'danger')
        return redirect(request.referrer or url_for('main.index'))
    original_consultor = User.query.get(last_activity.user_id)
    if current_user.role == 'consultor' and (not original_consultor or original_consultor.id != current_user.id):
        flash('Não pode editar um lead que não é seu.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))
    if current_user.role == 'admin_parceiro' and (not original_consultor or original_consultor.grupo_id != current_user.grupo_id):
        flash('Não pode editar um lead de outra equipe.', 'danger')
        return redirect(url_for('main.parceiro_dashboard'))
    new_tabulation_id = request.form.get('new_tabulation_id')
    if not new_tabulation_id:
        flash('Nova tabulação não selecionada.', 'warning')
        return redirect(request.referrer or url_for('main.index'))
    new_tabulation = Tabulation.query.get(int(new_tabulation_id))
    if not new_tabulation:
        flash('Tabulação selecionada inválida.', 'danger')
        return redirect(request.referrer or url_for('main.index'))
    lead.tabulation_id = new_tabulation.id
    lead.status = 'Tabulado'
    lead.data_tabulacao = datetime.now(timezone.utc)
    if original_consultor:
        lead.consultor_id = original_consultor.id
    retab_log = ActivityLog(lead_id=lead.id, user_id=current_user.id, tabulation_id=new_tabulation.id, action_type='Retabulação')
    db.session.add(retab_log)
    db.session.commit()
    flash(f'Tabulação do lead {lead.nome} atualizada!', 'success')
    return redirect(request.referrer or url_for('main.index'))

##force push##
##teste##