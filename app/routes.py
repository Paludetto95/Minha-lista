# app/routes.py (VERSÃO FINAL COMPLETA E CORRIGIDA)

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
from flask import render_template, flash, redirect, url_for, request, Blueprint, jsonify, Response, current_app, abort
from flask_login import login_user, logout_user, current_user, login_required
from app import db
from app.models import User, Lead, Proposta, Banco, Convenio, Situacao, TipoDeOperacao, LeadConsumption, Tabulation, Produto, LayoutMailing, ActivityLog, Grupo
from datetime import datetime, date, time, timedelta
from sqlalchemy import func, cast, Date, or_, case
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload

bp = Blueprint('main', __name__)

# --- FUNÇÕES HELPER ---
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
        flash('Conta de Super Administrador criada com sucesso!', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title='Registrar Super Admin')

@bp.route('/logout')
@login_required
def logout():
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
        theme_choice = request.form.get('theme')
        if theme_choice in ['default', 'dark', 'ocean']:
            current_user.theme = theme_choice
            db.session.commit()
            flash_message = """Tema atualizado com sucesso!<script>localStorage.setItem('userTheme', '{new_theme}');window.location.reload();</script>""".format(new_theme=theme_choice)
            flash(flash_message, 'success')
        else:
            flash('Seleção de tema inválida.', 'danger')
        return redirect(url_for('main.profile'))
    return render_template('profile.html', title="Minhas Configurações")

# --- ROTAS DE SUPER ADMIN ---

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
        time_in_status = datetime.utcnow() - agent.status_timestamp
        hours, remainder = divmod(time_in_status.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        timer_str = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
        calls_today = ActivityLog.query.filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day).count()
        conversions_today = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day, Tabulation.is_positive_conversion == True).count()
        current_work = Lead.query.join(Produto).filter(Lead.consultor_id == agent.id, Lead.status == 'Em Atendimento').with_entities(Produto.name).first()
        agents_data.append({'id': agent.id, 'name': agent.username, 'status': agent.current_status, 'last_login': agent.last_login, 'local': f"{agent.grupo.nome} / {current_work[0] if current_work else 'Nenhum'}", 'calls_today': calls_today, 'conversions_today': conversions_today})
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
    produto_id = form_data.get('produto_id')
    if not all([temp_filename, produto_id]):
        flash('Erro: informações da importação foram perdidas.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    temp_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
    if not os.path.exists(temp_filepath):
        flash('Erro: arquivo temporário não encontrado.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
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
        campos_do_modelo_lead = ['nome', 'cpf', 'telefone', 'telefone_2', 'status', 'data_criacao', 'data_tabulacao', 'consultor_id', 'tabulation_id', 'produto_id', 'estado']
        for index, row in df.iterrows():
            row_renamed = row.rename(inversed_mapping)
            cpf_digits = re.sub(r'\D', '', str(row_renamed.get('cpf', '')))
            if not cpf_digits or len(cpf_digits) != 11 or cpf_digits in existing_cpfs:
                leads_ignorados += 1
                continue
            lead_data = {'produto_id': produto_id, 'cpf': cpf_digits, 'status': 'Novo', 'data_criacao': datetime.utcnow()}
            additional_data = {}
            for original_header in original_headers:
                original_header_lower = original_header.lower().strip()
                system_field = inversed_mapping.get(original_header_lower)
                valor = row.get(original_header_lower)
                if system_field and system_field in campos_do_modelo_lead:
                    if 'telefone' in system_field:
                        lead_data[system_field] = re.sub(r'\D', '', str(valor))
                    elif system_field == 'estado':
                        lead_data[system_field] = str(valor).strip().upper()[:2]
                    else:
                        lead_data[system_field] = str(valor).strip()
                else:
                    additional_data[original_header.title()] = valor
            lead_data['additional_data'] = {k: v for k, v in additional_data.items() if pd.notna(v)}
            novo_lead = Lead(**lead_data)
            leads_para_adicionar.append(novo_lead)
            existing_cpfs.add(cpf_digits)
        if leads_para_adicionar:
            db.session.bulk_save_objects(leads_para_adicionar)
            flash(f'{len(leads_para_adicionar)} leads importados com sucesso! {leads_ignorados} foram ignorados.', 'success')
        else:
            flash('Nenhum novo lead válido para importar foi encontrado na planilha.', 'warning')
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro crítico durante o processamento: {e}', 'danger')
    finally:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
    return redirect(url_for('main.admin_dashboard'))

# --- ROTAS DE GESTÃO (SUPER ADMIN) ---

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
    
    # ===== CORREÇÃO APLICADA AQUI =====
    # Busca TODOS os usuários deste grupo
    users_in_group = User.query.filter_by(grupo_id=grupo.id).order_by(User.username).all()

    # Separa em listas de admins e consultores para o template
    admins = [user for user in users_in_group if user.role == 'admin_parceiro']
    consultores = [user for user in users_in_group if user.role == 'consultor']

    # Calcula o total de logins (agora users_in_group está definido)
    total_logins_group = sum(1 for user in users_in_group if user.last_login is not None)
    
    # Para o modal de adicionar usuários, busca todos os usuários que NÃO estão nesse grupo
    # e que NÃO são super_admin (pois super_admins não pertencem a grupos específicos)
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
    if nome:
        if Grupo.query.filter_by(nome=nome).first():
            flash('Uma equipe com este nome já existe.', 'danger')
        else:
            db.session.add(Grupo(nome=nome, color=color))
            db.session.commit()
            flash('Equipe adicionada com sucesso!', 'success')
    return redirect(url_for('main.manage_teams'))

@bp.route('/admin/groups/edit/<int:group_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def edit_group_name_color(group_id):
    grupo = Grupo.query.get_or_404(group_id)
    new_name = request.form.get('name')
    new_color = request.form.get('color')
    if new_name and new_name != grupo.nome:
        if Grupo.query.filter_by(nome=new_name).first():
            flash(f'Erro: Já existe uma equipe com o nome "{new_name}".', 'danger')
            return redirect(url_for('main.team_details', group_id=group_id))
        grupo.nome = new_name
    if new_color: grupo.color = new_color
    db.session.commit()
    flash(f'Equipe "{grupo.nome}" atualizada com sucesso!', 'success')
    return redirect(url_for('main.team_details', group_id=group_id))

@bp.route('/admin/groups/delete/<int:group_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_group(group_id):
    grupo = Grupo.query.get_or_404(group_id)
    if grupo.users.count() > 0:
        flash(f'Erro: Não é possível excluir a equipe "{grupo.nome}" porque ela ainda contém usuários.', 'danger')
        return redirect(url_for('main.manage_teams'))
    db.session.delete(grupo)
    db.session.commit()
    flash(f'Equipe "{grupo.nome}" excluída com sucesso!', 'success')
    return redirect(url_for('main.manage_teams'))

@bp.route('/admin/teams/add_member/<int:group_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def add_member_to_team(group_id):
    grupo = Grupo.query.get_or_404(group_id)
    user_id = request.form.get('user_id')
    new_role = request.form.get('role')
    user = User.query.get_or_404(user_id)
    if user.grupo_id == group_id and user.role == new_role:
        flash(f'Erro: {user.username} já é {new_role} nesta equipe.', 'warning')
        return redirect(url_for('main.team_details', group_id=group_id))
    user.grupo_id = group_id
    user.role = new_role
    db.session.commit()
    flash(f'{user.username} adicionado(a) como {new_role} à equipe {grupo.nome}!', 'success')
    return redirect(url_for('main.team_details', group_id=group_id))

@bp.route('/admin/teams/remove_member/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def remove_member_from_team(group_id, user_id):
    grupo = Grupo.query.get_or_404(group_id)
    user_to_remove = User.query.get_or_404(user_id)
    if user_to_remove.role == 'super_admin':
        flash('Não é possível remover um Super Administrador de uma equipe.', 'danger')
        return redirect(url_for('main.team_details', group_id=group_id))
    if user_to_remove.grupo_id != group_id:
        flash(f'Erro: {user_to_remove.username} não pertence à equipe {grupo.nome}.', 'danger')
        return redirect(url_for('main.team_details', group_id=group_id))
    equipe_principal = Grupo.query.filter_by(nome="Equipe Principal").first()
    if equipe_principal:
        user_to_remove.grupo_id = equipe_principal.id
        user_to_remove.role = 'consultor'
        db.session.commit()
        flash(f'{user_to_remove.username} removido(a) da equipe {grupo.nome} e movido(a) para Equipe Principal.', 'info')
    else:
        flash('Erro: Não foi possível mover o usuário para uma equipe padrão. Crie uma "Equipe Principal".', 'danger')
    return redirect(url_for('main.team_details', group_id=group_id))

@bp.route('/admin/users')
@login_required
@require_role('super_admin')
def manage_users():
    users = User.query.order_by(User.username).all()
    grupos = Grupo.query.order_by(Grupo.nome).all()
    return render_template('admin/manage_users.html', title="Gerir Utilizadores", users=users, grupos=grupos)

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
        return redirect(url_for('main.manage_users'))
    if User.query.filter_by(username=username).first():
        flash('Esse nome de utilizador já existe.', 'danger')
        return redirect(url_for('main.manage_users'))
    if User.query.filter_by(email=email).first():
        flash('Esse email já está a ser utilizado.', 'danger')
        return redirect(url_for('main.manage_users'))
    new_user = User(username=username, email=email, role=role, grupo_id=int(grupo_id))
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash('Utilizador criado com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

@bp.route('/admin/users/update_limits/<int:user_id>', methods=['POST'])
@login_required
@require_role('super_admin')
def update_user_limits(user_id):
    user = User.query.get_or_404(user_id)
    try:
        wallet_limit = int(request.form.get('wallet_limit', user.wallet_limit))
        daily_pull_limit = int(request.form.get('daily_pull_limit', user.daily_pull_limit))
        user.wallet_limit = wallet_limit
        user.daily_pull_limit = daily_pull_limit
        db.session.commit()
        flash(f'Limites do usuário {user.username} atualizados com sucesso!', 'success')
    except (ValueError, TypeError):
        db.session.rollback()
        flash('Valores de limite inválidos. Por favor, insira apenas números.', 'danger')
    return redirect(url_for('main.manage_users'))

@bp.route('/admin/users/delete/<int:id>', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_user(id):
    if id == current_user.id:
        flash('Não pode eliminar a sua própria conta.', 'danger')
        return redirect(url_for('main.manage_users'))
    user_to_delete = User.query.get_or_404(id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('Utilizador eliminado com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

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
            db.session.add(Produto(name=name))
            db.session.commit()
            flash('Produto adicionado com sucesso!', 'success')
        except:
            db.session.rollback()
            flash('Erro: Este produto já existe.', 'danger')
    return redirect(url_for('main.manage_products'))

@bp.route('/admin/products/delete/<int:id>', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_product(id):
    product_to_delete = Produto.query.get_or_404(id)
    try:
        db.session.delete(product_to_delete)
        db.session.commit()
        flash(f'Produto "{product_to_delete.name}" excluído com sucesso!', 'success')
    except IntegrityError:
        db.session.rollback()
        flash(f'Erro: O produto "{product_to_delete.name}" não pode ser excluído porque está em uso.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro inesperado: {e}', 'danger')
    return redirect(url_for('main.manage_products'))

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
    try:
        db.session.delete(layout_to_delete)
        db.session.commit()
        flash(f'Layout "{layout_to_delete.name}" excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro ao excluir o layout: {e}', 'danger')
    return redirect(url_for('main.manage_layouts'))
    
def delete_leads_in_background(app, produto_id, estado):
    with app.app_context():
        try:
            leads_query = Lead.query.filter_by(produto_id=produto_id, estado=estado)
            batch_size = 1000
            while True:
                leads_to_delete_ids = [lead.id for lead in leads_query.limit(batch_size).with_entities(Lead.id).all()]
                if not leads_to_delete_ids: break
                ActivityLog.query.filter(ActivityLog.lead_id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                LeadConsumption.query.filter(LeadConsumption.lead_id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                db.session.query(Lead).filter(Lead.id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                db.session.commit()
        except Exception as e:
            db.session.rollback()

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
        flash('Informações do mailing inválidas.', 'danger')
        return redirect(url_for('main.manage_mailings'))
    thread = threading.Thread(target=delete_leads_in_background, args=(current_app._get_current_object(), produto_id, estado))
    thread.start()
    flash('A exclusão do mailing foi iniciada em segundo plano.', 'info')
    return redirect(url_for('main.manage_mailings'))

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
        except IntegrityError:
            db.session.rollback()
            flash('Essa tabulação já existe.', 'danger')
    return redirect(url_for('main.manage_tabulations'))

@bp.route('/admin/tabulations/delete/<int:id>', methods=['POST'])
@login_required
@require_role('super_admin')
def delete_tabulation(id):
    tabulation_to_delete = Tabulation.query.get_or_404(id)
    db.session.delete(tabulation_to_delete)
    db.session.commit()
    flash('Tabulação eliminada com sucesso!', 'success')
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

# --- ROTAS DO ADMIN DO PARCEIRO ---

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
        time_in_status = datetime.utcnow() - agent.status_timestamp
        hours, remainder = divmod(time_in_status.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        timer_str = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
        calls_today = ActivityLog.query.filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day).count()
        conversions_today = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id == agent.id, ActivityLog.timestamp >= start_of_day, Tabulation.is_positive_conversion == True).count()
        current_work = Lead.query.join(Produto).filter(Lead.consultor_id == agent.id, Lead.status == 'Em Atendimento').with_entities(Produto.name).first()
        agents_data.append({'id': agent.id, 'name': agent.username, 'status': agent.current_status, 'last_login': agent.last_login, 'local': current_work[0] if current_work else "Nenhum", 'calls_today': calls_today, 'conversions_today': conversions_today})
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
    else:
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
    consultants_in_group = User.query.filter(User.id.in_(user_ids_in_group)).all()
    performance_data = []
    for consultant in consultants_in_group:
        total_calls = ActivityLog.query.filter(ActivityLog.user_id == consultant.id, ActivityLog.timestamp.between(start_date, end_date)).count()
        total_conversions = ActivityLog.query.join(Tabulation).filter(ActivityLog.user_id == consultant.id, ActivityLog.timestamp.between(start_date, end_date), Tabulation.is_positive_conversion == True).count()
        conversion_rate = (total_conversions / total_calls * 100) if total_calls > 0 else 0
        performance_data.append({'name': consultant.username, 'status': consultant.current_status, 'total_calls': total_calls, 'total_conversions': total_conversions, 'conversion_rate': conversion_rate})
    performance_data.sort(key=lambda x: x['total_conversions'], reverse=True)
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
    consultants_in_group = User.query.filter(User.id.in_(user_ids_in_group)).all()
    performance_data = []
    for consultant in consultants_in_group:
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

@bp.route('/parceiro/users/edit/<int:user_id>', methods=['POST'])
@login_required
@require_role('admin_parceiro')
def parceiro_edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    if user_to_edit.grupo_id != current_user.grupo_id:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('main.parceiro_manage_users'))
    new_username = request.form.get('username')
    if new_username:
        existing_user = User.query.filter(User.username == new_username, User.id != user_id).first()
        if existing_user:
            flash(f'O nome de usuário "{new_username}" já está em uso.', 'danger')
        else:
            user_to_edit.username = new_username
            db.session.commit()
            flash('Nome do usuário atualizado com sucesso!', 'success')
    return redirect(url_for('main.parceiro_manage_users'))

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
        mailings_disponiveis = db.session.query(Lead.produto_id, Produto.name.label('produto_nome'), Lead.estado, func.count(Lead.id).label('leads_disponiveis')).join(Produto, Lead.produto_id == Produto.id).filter(Lead.status == 'Novo', Lead.consultor_id == None, or_(Lead.available_after == None, Lead.available_after <= datetime.utcnow())).group_by(Lead.produto_id, Produto.name, Lead.estado).order_by(Produto.name, Lead.estado).all()
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
            leads_disponiveis = Lead.query.filter(Lead.status == 'Novo', Lead.consultor_id == None, Lead.produto_id == produto_id, Lead.estado == estado, or_(Lead.available_after == None, Lead.available_after <= datetime.utcnow())).limit(quantidade_a_pegar).all()
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
        recycle_date = datetime.utcnow() + timedelta(days=tabulation.recycle_in_days)
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
        lead.data_tabulacao = datetime.utcnow()
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
    lead.data_tabulacao = datetime.utcnow()
    if original_consultor:
        lead.consultor_id = original_consultor.id
    retab_log = ActivityLog(lead_id=lead.id, user_id=current_user.id, tabulation_id=new_tabulation.id, action_type='Retabulação')
    db.session.add(retab_log)
    db.session.commit()
    flash(f'Tabulação do lead {lead.nome} atualizada!', 'success')
    return redirect(request.referrer or url_for('main.index'))