# app/routes.py (VERSÃO FINAL COM MONITOR INTEGRADO)

import pandas as pd
import io
import re
import os
import uuid
import threading
from collections import defaultdict
from flask import render_template, flash, redirect, url_for, request, Blueprint, jsonify, Response, current_app, abort
from flask_login import login_user, logout_user, current_user, login_required
from app import db
from app.models import User, Lead, Proposta, Banco, Convenio, Situacao, TipoDeOperacao, LeadConsumption, Tabulation, Produto, LayoutMailing, ActivityLog
from datetime import datetime, date, time, timedelta
from sqlalchemy import func, cast, Date, or_, case
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload

bp = Blueprint('main', __name__)

# --- NOVA FUNÇÃO HELPER PARA O MONITOR ---
def update_user_status(user, new_status):
    """Atualiza o status de um usuário e o timestamp no banco de dados."""
    user.current_status = new_status
    user.status_timestamp = datetime.utcnow()
    db.session.add(user)

# --- ROTAS DE AUTENTICAÇÃO E GERAIS (COM ATUALIZAÇÃO DE STATUS) ---
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user is None or not user.check_password(request.form.get('password')):
            flash('Email ou senha inválidos', 'danger')
            return redirect(url_for('main.login'))
        login_user(user, remember=request.form.get('remember_me') is not None)
        
        # ATUALIZA O STATUS DO CONSULTOR AO LOGAR
        if not user.is_admin:
            update_user_status(user, 'Ocioso')
            db.session.commit()
            
        return redirect(url_for('main.index'))
    return render_template('login.html', title='Login')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if User.query.first() is not None:
        flash('O registro de novos usuários está desabilitado.', 'warning')
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if not all([username, email, password]):
            flash('Todos os campos são obrigatórios.', 'danger')
            return redirect(url_for('main.register'))
        user = User(username=username, email=email, is_admin=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Conta de administrador criada com sucesso! Por favor, faça login.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title='Registrar Administrador')

@bp.route('/logout')
@login_required # Garante que temos um current_user
def logout():
    # ATUALIZA O STATUS DO CONSULTOR PARA OFFLINE AO DESLOGAR
    if current_user.is_authenticated and not current_user.is_admin:
        update_user_status(current_user, 'Offline')
        db.session.commit()
    
    logout_user()
    return redirect(url_for('main.login'))

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    if current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))
    return redirect(url_for('main.consultor_dashboard'))

# --- ROTAS DE ADMIN ---

@bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))
    
    all_products = Produto.query.order_by(Produto.name).all()
    all_layouts = LayoutMailing.query.order_by(LayoutMailing.name).all()
    page = request.args.get('page', 1, type=int)
    
    recent_activity = ActivityLog.query.options(
        joinedload(ActivityLog.lead),
        joinedload(ActivityLog.user),
        joinedload(ActivityLog.tabulation)
    ).order_by(
        ActivityLog.timestamp.desc()
    ).paginate(page=page, per_page=10, error_out=False)

    return render_template('admin/admin_dashboard.html', 
                           title='Dashboard do Admin',
                           all_products=all_products,
                           all_layouts=all_layouts,
                           recent_activity=recent_activity)

# --- NOVA ROTA DO MONITOR ---
@bp.route('/admin/monitor')
@login_required
def admin_monitor():
    if not current_user.is_admin:
        abort(403)
        
    start_of_day = datetime.combine(date.today(), time.min)
    consultants = User.query.filter_by(is_admin=False).all()
    
    agents_data = []
    
    for agent in consultants:
        time_in_status = datetime.utcnow() - agent.status_timestamp
        hours, remainder = divmod(time_in_status.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        timer_str = "{:02}:{:02}:{:02}".format(int(hours), int(minutes), int(seconds))

        calls_today = ActivityLog.query.filter(
            ActivityLog.user_id == agent.id,
            ActivityLog.timestamp >= start_of_day
        ).count()

        conversions_today = ActivityLog.query.join(Tabulation).filter(
            ActivityLog.user_id == agent.id,
            ActivityLog.timestamp >= start_of_day,
            Tabulation.is_positive_conversion == True
        ).count()
        
        current_work = Lead.query.join(Produto).filter(
            Lead.consultor_id == agent.id,
            Lead.status == 'Em Atendimento'
        ).with_entities(Produto.name).first()

        agents_data.append({
            'id': agent.id,
            'name': agent.username,
            'status': agent.current_status,
            'timer': timer_str,
            'local': current_work[0] if current_work else "Nenhum",
            'calls_today': calls_today,
            'conversions_today': conversions_today
        })
        
    agents_data.sort(key=lambda x: (x['conversions_today'], x['calls_today']), reverse=True)
    
    return render_template('admin/monitor.html', 
                           title="Monitor de Consultores",
                           agents_data=agents_data)


@bp.route('/upload_step1', methods=['POST'])
@login_required
def upload_step1():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))

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
        
        system_fields = [
            'nome_cliente', 'cpf', 'telefone', 'telefone_2', 'estado', 'bairro', 'cep', 'cidade',
            'convenio', 'orgao', 'nome_mae', 'sexo', 'nascimento', 'idade',
            'tipo_vinculo', 'rmc', 'valor_liberado', 'beneficio', 'logradouro', 'numero', 'complemento',
            'extra_1', 'extra_2', 'extra_3', 'extra_4', 'extra_5',
            'extra_6', 'extra_7', 'extra_8', 'extra_9', 'extra_10'
        ]
        
        existing_mapping = None
        if layout_id:
            layout = LayoutMailing.query.get(layout_id)
            if layout:
                existing_mapping = layout.mapping

        return render_template('admin/map_columns.html',
                               headers=headers,
                               sample_rows=sample_rows,
                               temp_filename=temp_filename,
                               produto_id=produto_id,
                               system_fields=system_fields,
                               existing_mapping=existing_mapping)

    except Exception as e:
        flash(f'Erro ao ler o arquivo: {e}', 'danger')
        return redirect(url_for('main.admin_dashboard'))

@bp.route('/upload_step2_process', methods=['POST'])
@login_required
def upload_step2_process():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))

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
        
        if 'cpf' not in mapping:
            flash("Erro de mapeamento: A coluna 'CPF' é obrigatória e deve ser mapeada.", 'danger')
            return redirect(url_for('main.admin_dashboard'))

        if form_data.get('save_layout') and form_data.get('layout_name'):
            layout_mapping_to_save = {k: v for k, v in mapping.items() if v}
            new_layout = LayoutMailing(name=form_data.get('layout_name'), produto_id=produto_id, mapping=layout_mapping_to_save)
            db.session.add(new_layout)

        df = pd.read_excel(temp_filepath, dtype=str) if temp_filepath.endswith('.xlsx') else pd.read_csv(temp_filepath, sep=None, engine='python', encoding='latin1', dtype=str)
        original_headers = df.columns.copy()
        df.columns = [str(col).lower().strip() for col in df.columns]
        
        inversed_mapping = {v: k for k, v in mapping.items()}
        
        existing_cpfs = {lead.cpf for lead in Lead.query.with_entities(Lead.cpf).all()}
        leads_para_adicionar = []
        leads_ignorados = 0

        campos_do_modelo_lead = [
            'nome_cliente', 'cpf', 'telefone', 'telefone_2', 
            'status', 'data_criacao', 'data_tabulacao', 
            'consultor_id', 'tabulation_id', 'produto_id', 'estado'
        ]
        
        for index, row in df.iterrows():
            row_renamed = row.rename(inversed_mapping)
            cpf_digits = re.sub(r'\D', '', str(row_renamed.get('cpf', '')))
            
            if not cpf_digits or len(cpf_digits) != 11 or cpf_digits in existing_cpfs:
                leads_ignorados += 1
                continue
            
            lead_data = {
                'produto_id': produto_id,
                'cpf': cpf_digits,
                'status': 'Novo',
                'data_criacao': datetime.utcnow()
            }
            
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

# --- ROTAS DE GESTÃO (ADMIN) ---
@bp.route('/admin/products')
@login_required
def manage_products():
    if not current_user.is_admin: return redirect(url_for('main.index'))
    products = Produto.query.order_by(Produto.name).all()
    return render_template('admin/manage_products.html', title="Gerir Produtos", products=products)

@bp.route('/admin/products/add', methods=['POST'])
@login_required
def add_product():
    if not current_user.is_admin: return redirect(url_for('main.index'))
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
def delete_product(id):
    if not current_user.is_admin:
        abort(403)
    product_to_delete = Produto.query.get_or_404(id)
    try:
        db.session.delete(product_to_delete)
        db.session.commit()
        flash(f'Produto "{product_to_delete.name}" excluído com sucesso!', 'success')
    except IntegrityError:
        db.session.rollback()
        flash(f'Erro: O produto "{product_to_delete.name}" não pode ser excluído porque está em uso por leads ou layouts.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro inesperado: {e}', 'danger')
    return redirect(url_for('main.manage_products'))

@bp.route('/admin/layouts')
@login_required
def manage_layouts():
    if not current_user.is_admin: return redirect(url_for('main.index'))
    layouts = LayoutMailing.query.options(joinedload(LayoutMailing.produto)).order_by(LayoutMailing.name).all()
    return render_template('admin/manage_layouts.html', title="Gerir Layouts", layouts=layouts)

@bp.route('/admin/layouts/delete/<int:id>', methods=['POST'])
@login_required
def delete_layout(id):
    if not current_user.is_admin: return redirect(url_for('main.index'))
    layout = LayoutMailing.query.get_or_404(id)
    db.session.delete(layout)
    db.session.commit()
    flash('Layout removido com sucesso!', 'success')
    return redirect(url_for('main.manage_layouts'))
    
def delete_leads_in_background(app, produto_id, estado):
    with app.app_context():
        try:
            print(f"BACKGROUND TASK: Iniciando exclusão para produto {produto_id}, estado {estado}.")
            leads_query = Lead.query.filter_by(produto_id=produto_id, estado=estado)
            total_count = leads_query.count()
            if total_count == 0:
                print("BACKGROUND TASK: Nenhum lead para excluir.")
                return
            batch_size = 1000
            while True:
                leads_to_delete_ids = [lead.id for lead in leads_query.limit(batch_size).with_entities(Lead.id).all()]
                if not leads_to_delete_ids: break
                ActivityLog.query.filter(ActivityLog.lead_id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                LeadConsumption.query.filter(LeadConsumption.lead_id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                db.session.query(Lead).filter(Lead.id.in_(leads_to_delete_ids)).delete(synchronize_session=False)
                db.session.commit()
            print(f"BACKGROUND TASK: Exclusão concluída.")
        except Exception as e:
            print(f"BACKGROUND TASK FAILED: {e}")
            db.session.rollback()

@bp.route('/admin/mailings')
@login_required
def manage_mailings():
    if not current_user.is_admin:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('main.index'))
    mailing_groups = db.session.query(
        Lead.produto_id, Produto.name.label('produto_nome'), Lead.estado,
        func.count(Lead.id).label('total_leads'),
        func.count(case((Lead.status == 'Novo', Lead.id), else_=None)).label('leads_novos')
    ).join(Produto, Lead.produto_id == Produto.id).group_by(
        Lead.produto_id, Produto.name, Lead.estado
    ).order_by(Produto.name, Lead.estado).all()
    mailings_por_produto = defaultdict(list)
    for group in mailing_groups:
        mailings_por_produto[group.produto_nome].append(group)
    return render_template('admin/manage_mailings.html', title="Gerir Mailings", mailings_por_produto=mailings_por_produto)

@bp.route('/admin/mailings/delete', methods=['POST'])
@login_required
def delete_mailing():
    if not current_user.is_admin: abort(403)
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
def export_mailing():
    if not current_user.is_admin: abort(403)
    produto_id = request.args.get('produto_id')
    estado = request.args.get('estado')
    if not produto_id or not estado:
        flash('Informações do mailing inválidas.', 'danger')
        return redirect(url_for('main.manage_mailings'))
    leads = Lead.query.options(joinedload(Lead.produto), joinedload(Lead.tabulation), joinedload(Lead.consultor)).filter_by(produto_id=produto_id, estado=estado).order_by(Lead.data_criacao).all()
    if not leads:
        flash('Nenhum lead encontrado para este grupo.', 'warning')
        return redirect(url_for('main.manage_mailings'))
    data_for_df = []
    for lead in leads:
        lead_info = {
            'ID do Lead': lead.id, 'Nome Cliente': lead.nome_cliente, 'CPF': lead.cpf,
            'Telefone 1': lead.telefone, 'Telefone 2': lead.telefone_2, 'Estado': lead.estado,
            'Produto': lead.produto.name if lead.produto else 'N/A',
            'Status': lead.status, 'Consultor': lead.consultor.username if lead.consultor else 'N/A',
            'Tabulação': lead.tabulation.name if lead.tabulation else 'NÃO TABULADO',
            'Data Tabulação': lead.data_tabulacao.strftime('%d/%m/%Y %H:%M') if lead.data_tabulacao else '',
        }
        if lead.additional_data:
            lead_info.update(lead.additional_data)
        data_for_df.append(lead_info)
    df = pd.DataFrame(data_for_df)
    output = io.StringIO()
    df.to_csv(output, index=False, sep=';', encoding='utf-8-sig')
    csv_data = output.getvalue()
    filename = f"mailing_{leads[0].produto.name}_{leads[0].estado}.csv".replace(" ", "_")
    return Response(csv_data, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={filename}"})

@bp.route('/admin/mailings/export_all')
@login_required
def export_all_mailings():
    if not current_user.is_admin: abort(403)
    leads = Lead.query.options(joinedload(Lead.produto), joinedload(Lead.tabulation), joinedload(Lead.consultor)).order_by(Lead.produto_id, Lead.estado, Lead.data_criacao).all()
    if not leads:
        flash('Nenhum lead encontrado para exportar.', 'warning')
        return redirect(url_for('main.manage_mailings'))
    data_for_df = []
    for lead in leads:
        lead_info = {
            'Produto': lead.produto.name if lead.produto else 'N/A', 'Estado': lead.estado,
            'Status': lead.status, 'Tabulação': lead.tabulation.name if lead.tabulation else 'NÃO TABULADO',
            'Consultor': lead.consultor.username if lead.consultor else 'N/A',
            'Nome Cliente': lead.nome_cliente, 'CPF': lead.cpf,
            'Telefone 1': lead.telefone, 'Telefone 2': lead.telefone_2,
        }
        if lead.additional_data:
            lead_info.update(lead.additional_data)
        data_for_df.append(lead_info)
    df = pd.DataFrame(data_for_df)
    output = io.StringIO()
    df.to_csv(output, index=False, sep=';', encoding='utf-8-sig')
    csv_data = output.getvalue()
    filename = f"relatorio_completo_mailings_{date.today().strftime('%Y-%m-%d')}.csv"
    return Response(csv_data, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={filename}"})

# --- ROTAS DE GESTÃO DE USUÁRIOS ---
@bp.route('/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    users = User.query.order_by(User.username).all()
    return render_template('admin/manage_users.html', title="Gerir Utilizadores", users=users)

@bp.route('/users/add', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin') == 'on'
    if User.query.filter_by(username=username).first():
        flash('Esse nome de utilizador já existe.', 'danger')
        return redirect(url_for('main.manage_users'))
    if User.query.filter_by(email=email).first():
        flash('Esse email já está a ser utilizado.', 'danger')
        return redirect(url_for('main.manage_users'))
    new_user = User(username=username, email=email, is_admin=is_admin)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash('Utilizador criado com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

@bp.route('/users/update_limits/<int:user_id>', methods=['POST'])
@login_required
def update_user_limits(user_id):
    if not current_user.is_admin:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('main.index'))
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Não é possível definir limites para um administrador.', 'warning')
        return redirect(url_for('main.manage_users'))
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

@bp.route('/users/delete/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if not current_user.is_admin:
        return redirect(url_for('main.manage_users'))
    if id == current_user.id:
        flash('Não pode eliminar a sua própria conta.', 'danger')
        return redirect(url_for('main.manage_users'))
    user_to_delete = User.query.get_or_404(id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('Utilizador eliminado com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

# --- ROTAS DO CONSULTOR (COM ATUALIZAÇÃO DE STATUS) ---
@bp.route('/consultor/dashboard')
@login_required
def consultor_dashboard():
    if current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))
        
    start_of_day = datetime.combine(date.today(), time.min)
    leads_em_atendimento = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    leads_consumidos_hoje = LeadConsumption.query.filter(
        LeadConsumption.user_id == current_user.id,
        LeadConsumption.timestamp >= start_of_day
    ).count()
    vagas_na_carteira = current_user.wallet_limit - leads_em_atendimento
    vagas_na_puxada_diaria = current_user.daily_pull_limit - leads_consumidos_hoje
    mailings_disponiveis = []
    if vagas_na_carteira > 0 and vagas_na_puxada_diaria > 0:
        mailings_disponiveis = db.session.query(
            Lead.produto_id, Produto.name.label('produto_nome'), Lead.estado,
            func.count(Lead.id).label('leads_disponiveis')
        ).join(Produto, Lead.produto_id == Produto.id).filter(
            Lead.status == 'Novo', 
            Lead.consultor_id == None,
            or_(
                Lead.available_after == None,
                Lead.available_after <= datetime.utcnow()
            )
        ).group_by(
            Lead.produto_id, Produto.name, Lead.estado
        ).order_by(Produto.name, Lead.estado).all()
        
    search_history = request.args.get('search_history', '')
    history_query = ActivityLog.query.options(
        joinedload(ActivityLog.lead),
        joinedload(ActivityLog.tabulation)
    ).filter(
        ActivityLog.user_id == current_user.id
    )
    if search_history:
        search_term = f"%{search_history}%"
        history_query = history_query.join(Lead).filter(
            or_(Lead.nome_cliente.ilike(search_term), Lead.cpf.ilike(search_term))
        )
    tabulated_history = history_query.order_by(ActivityLog.timestamp.desc()).all()
    all_tabulations = Tabulation.query.order_by(Tabulation.name).all()

    return render_template('consultor_dashboard.html', 
                           title='Meu Painel', 
                           vagas_na_carteira=vagas_na_carteira,
                           leads_em_atendimento=leads_em_atendimento,
                           leads_consumidos_hoje=leads_consumidos_hoje,
                           vagas_na_puxada_diaria=vagas_na_puxada_diaria,
                           current_user=current_user,
                           mailings_disponiveis=mailings_disponiveis,
                           tabulated_history=tabulated_history,
                           search_history=search_history,
                           all_tabulations=all_tabulations)

@bp.route('/pegar_leads_selecionados', methods=['POST'])
@login_required
def pegar_leads_selecionados():
    if current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))
    leads_em_atendimento = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    start_of_day = datetime.combine(date.today(), time.min)
    leads_consumidos_hoje = LeadConsumption.query.filter(
        LeadConsumption.user_id == current_user.id,
        LeadConsumption.timestamp >= start_of_day
    ).count()
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
            leads_disponiveis = Lead.query.filter(
                Lead.status == 'Novo', 
                Lead.consultor_id == None,
                Lead.produto_id == produto_id, 
                Lead.estado == estado,
                or_(
                    Lead.available_after == None,
                    Lead.available_after <= datetime.utcnow()
                )
            ).limit(quantidade_a_pegar).all()

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

# --- ROTAS DE ATENDIMENTO E OUTRAS ---
@bp.route('/atendimento')
@login_required
def atendimento():
    if current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))
    
    lead_para_atender = Lead.query.filter_by(
        consultor_id=current_user.id, 
        status='Em Atendimento'
    ).order_by(Lead.data_criacao).first()
    
    if not lead_para_atender:
        # ATUALIZA O STATUS QUANDO A CARTEIRA ESTÁ VAZIA
        update_user_status(current_user, 'Ocioso')
        db.session.commit()
        flash('Parabéns, você não tem mais leads pendentes para atender!', 'success')
        return redirect(url_for('main.consultor_dashboard'))
        
    # ATUALIZA O STATUS PARA "FALANDO" QUANDO UM LEAD É APRESENTADO
    update_user_status(current_user, 'Falando')
    db.session.commit()

    tabulations = Tabulation.query.order_by(Tabulation.name).all()
    campos_principais_ordenados = [
        ('Nome Cliente', lead_para_atender.nome_cliente), ('CPF', lead_para_atender.cpf),
        ('Estado', lead_para_atender.estado), ('Telefone', lead_para_atender.telefone),
        ('Telefone 2', lead_para_atender.telefone_2)
    ]
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
    
    return render_template('atendimento.html', 
                           title="Atendimento de Lead", 
                           lead=lead_para_atender, 
                           lead_details=lead_details,
                           tabulations=tabulations,
                           phone_numbers=phone_numbers)

@bp.route('/atender/<int:lead_id>', methods=['POST'])
@login_required
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
        flash(f'Lead de {lead.nome_cliente} será reciclado em {tabulation.recycle_in_days} dias.', 'info')
    else:
        lead.tabulation_id = tabulation.id
        lead.status = 'Tabulado'
        lead.data_tabulacao = datetime.utcnow()
        action_type = 'Tabulação'
        flash(f'Lead de {lead.nome_cliente} tabulado com sucesso!', 'success')

    activity_log_entry = ActivityLog(
        lead_id=lead.id,
        user_id=current_user.id,
        tabulation_id=tabulation.id,
        action_type=action_type
    )
    db.session.add(activity_log_entry)
    db.session.commit()
    
    return redirect(url_for('main.atendimento'))

@bp.route('/retabulate/<int:lead_id>', methods=['POST'])
@login_required
def retabulate_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    
    last_activity = ActivityLog.query.filter_by(lead_id=lead.id).order_by(ActivityLog.timestamp.desc()).first()
    original_consultor_id = last_activity.user_id if last_activity else None
    
    if original_consultor_id != current_user.id and not current_user.is_admin:
        flash('Não pode editar um lead que não é seu.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))
    
    new_tabulation_id = request.form.get('new_tabulation_id')
    if not new_tabulation_id:
        flash('Nova tabulação não selecionada.', 'warning')
        return redirect(url_for('main.consultor_dashboard'))

    new_tabulation = Tabulation.query.get(int(new_tabulation_id))
    if not new_tabulation:
        flash('Tabulação selecionada inválida.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))
    
    lead.tabulation_id = new_tabulation.id
    lead.status = 'Tabulado'
    lead.data_tabulacao = datetime.utcnow()
    lead.consultor_id = original_consultor_id

    retab_log = ActivityLog(
        lead_id=lead.id,
        user_id=current_user.id,
        tabulation_id=new_tabulation.id,
        action_type='Retabulação'
    )
    db.session.add(retab_log)
    db.session.commit()

    flash(f'Tabulação do lead {lead.nome_cliente} atualizada!', 'success')
    return redirect(url_for('main.consultor_dashboard'))

@bp.route('/tabulations')
@login_required
def manage_tabulations():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    tabulations = Tabulation.query.order_by(Tabulation.name).all()
    return render_template('admin/manage_tabulations.html', title="Gerir Tabulações", tabulations=tabulations)

@bp.route('/tabulations/add', methods=['POST'])
@login_required
def add_tabulation():
    if not current_user.is_admin: return redirect(url_for('main.index'))
    name = request.form.get('name')
    color = request.form.get('color')
    
    is_recyclable = request.form.get('is_recyclable') == 'on'
    is_positive_conversion = request.form.get('is_positive_conversion') == 'on' # Adicionado para o monitor
    
    recycle_in_days = None
    if is_recyclable:
        try:
            recycle_in_days = int(request.form.get('recycle_in_days', 0))
        except (ValueError, TypeError):
            recycle_in_days = 0

    if name and color:
        new_tabulation = Tabulation(
            name=name, 
            color=color,
            is_recyclable=is_recyclable,
            recycle_in_days=recycle_in_days,
            is_positive_conversion=is_positive_conversion # Adicionado para o monitor
        )
        db.session.add(new_tabulation)
        try:
            db.session.commit()
            flash('Tabulação criada com sucesso!', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Essa tabulação já existe.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Ocorreu um erro: {e}', 'danger')
            
    return redirect(url_for('main.manage_tabulations'))

@bp.route('/tabulations/delete/<int:id>', methods=['POST'])
@login_required
def delete_tabulation(id):
    if not current_user.is_admin: return redirect(url_for('main.index'))
    tabulation_to_delete = Tabulation.query.get_or_404(id)
    db.session.delete(tabulation_to_delete)
    db.session.commit()
    flash('Tabulação eliminada com sucesso!', 'success')
    return redirect(url_for('main.manage_tabulations'))

@bp.route('/export/tabulations')
@login_required
def export_tabulations():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    try:
        results = ActivityLog.query.options(
            joinedload(ActivityLog.lead).joinedload(Lead.produto),
            joinedload(ActivityLog.user),
            joinedload(ActivityLog.tabulation)
        ).order_by(ActivityLog.timestamp.asc()).all()
        
        if not results:
            flash('Nenhum dado encontrado para exportar.', 'warning')
            return redirect(url_for('main.admin_dashboard'))
        data_for_df = []
        for log in results:
            data_for_df.append({
                'Data da Ação': log.timestamp.strftime('%d/%m/%Y %H:%M:%S'),
                'Tipo de Ação': log.action_type,
                'Consultor': log.user.username if log.user else 'N/A',
                'Cliente': log.lead.nome_cliente if log.lead else 'N/A',
                'CPF': log.lead.cpf if log.lead else 'N/A',
                'Produto': log.lead.produto.name if log.lead and log.lead.produto else 'N/A',
                'Tabulação Escolhida': log.tabulation.name if log.tabulation else 'N/A',
            })
        df = pd.DataFrame(data_for_df)
        output = io.StringIO()
        df.to_csv(output, index=False, sep=';', encoding='utf-8-sig')
        csv_data = output.getvalue()
        response = Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename=relatorio_completo_atividades.csv"}
        )
        return response
    except Exception as e:
        flash(f'Ocorreu um erro ao gerar o relatório: {e}', 'danger')
        return redirect(url_for('main.admin_dashboard'))