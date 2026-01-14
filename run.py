# run.py (VERSÃO EXECUTÁVEL FINAL)

import os
from dotenv import load_dotenv

# Carrega as variáveis de ambiente. Se isso falhar, o problema está aqui.
# Certifique-se de que o arquivo .env está na mesma pasta que este run.py
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    print("--- Arquivo .env encontrado. Carregando... ---")
    load_dotenv(dotenv_path)
else:
    print("--- AVISO: Arquivo .env não encontrado. ---")


# Tenta importar a aplicação. Se falhar aqui, o problema é de instalação.
try:
    from app import create_app
    print("--- 'create_app' importado com sucesso. ---")
except ImportError as e:
    print(f"!!! ERRO FATAL: Falha ao importar 'create_app'. Verifique a instalação das dependências. Erro: {e} !!!")
    exit() # Para o script se não conseguir importar

app = create_app()

if __name__ == '__main__':
    print("--- Iniciando o servidor de desenvolvimento do Flask... ---")
    # Obtém a porta do ambiente ou usa 5000 como padrão
    port = int(os.environ.get('PORT', 5000))
    # debug=False impede que o código rode duas vezes, o que pode causar confusão
    app.run(host='0.0.0.0', port=port, debug=False)