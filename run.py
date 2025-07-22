from dotenv import load_dotenv
import os

# Passo 1: Carrega as variáveis de ambiente do arquivo .env.
# Esta é a linha mais importante, pois garante que a DATABASE_URL seja lida
# antes que a aplicação tente se conectar ao banco de dados.
load_dotenv()

# Passo 2: Importa a função de criação da aplicação.
from app import create_app

# Passo 3: Cria a instância da aplicação.
# Gunicorn (o servidor de produção) irá procurar por esta variável 'app'.
app = create_app()

# Passo 4: Bloco de execução para desenvolvimento local.
# Este bloco só é executado quando você roda o comando 'python run.py' ou 'flask run'.
# Ele é ignorado pelo Gunicorn em produção.
if __name__ == '__main__':
    # Obtém a porta do ambiente ou usa 5000 como padrão.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)