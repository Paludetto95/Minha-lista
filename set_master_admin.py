"""
Script para definir um usuário como Master Admin
Execute este script para tornar um usuário específico Master Admin

OPÇÃO 1: Execute com Python
    python set_master_admin.py

OPÇÃO 2: Execute via Flask shell
    flask shell
    >>> from app.models import User, db
    >>> user = User.query.filter_by(username='SEU_USUARIO').first()
    >>> user.is_master_admin = True
    >>> db.session.commit()
"""
import sys
import os

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import create_app, db
    from app.models import User

    app = create_app()

    with app.app_context():
        # Listar todos os usuários super_admin
        super_admins = User.query.filter_by(role='super_admin').all()
        
        if not super_admins:
            print("✗ Nenhum usuário Super Admin encontrado!")
            print("\nListando TODOS os usuários:")
            all_users = User.query.all()
            for user in all_users:
                print(f"ID: {user.id} | Username: {user.username} | Role: {user.role} | Master: {user.is_master_admin}")
            sys.exit(1)
        
        print("Usuários Super Admin encontrados:")
        print("-" * 50)
        for user in super_admins:
            status = "✓ JÁ É MASTER ADMIN" if user.is_master_admin else ""
            print(f"ID: {user.id} | Username: {user.username} | Email: {user.email} | Master Admin: {user.is_master_admin} {status}")
        
        print("\n" + "=" * 50)
        
        # Pedir o ID do usuário para tornar Master Admin
        user_input = input("\nDigite o ID ou username do usuário para tornar Master Admin (ou 'todos' para todos os super_admins): ")
        
        if user_input.lower() == 'todos':
            for user in super_admins:
                user.is_master_admin = True
                print(f"✓ {user.username} agora é Master Admin")
            db.session.commit()
            print("\nTodos os Super Admins agora são Master Admins!")
        else:
            # Tentar por ID primeiro
            user = None
            try:
                user = User.query.get(int(user_input))
            except ValueError:
                # Se não for número, tentar por username
                user = User.query.filter_by(username=user_input).first()
            
            if user:
                user.is_master_admin = True
                db.session.commit()
                print(f"\n✓ Usuário '{user.username}' (ID: {user.id}) agora é Master Admin!")
                print(f"  Role: {user.role}")
                print(f"  Email: {user.email}")
            else:
                print(f"\n✗ Usuário '{user_input}' não encontrado!")

except Exception as e:
    print(f"\n✗ ERRO: {e}")
    print("\n" + "="*50)
    print("SOLUÇÃO ALTERNATIVA:")
    print("="*50)
    print("Execute os seguintes comandos no terminal onde sua aplicação está rodando:\n")
    print("flask shell")
    print(">>> from app.models import User, db")
    print(">>> user = User.query.filter_by(username='SEU_USUARIO_AQUI').first()")
    print(">>> user.is_master_admin = True")
    print(">>> db.session.commit()")
    print(">>> exit()")

