# run.py (VERSÃO ATUALIZADA)
from dotenv import load_dotenv
import os

# Carrega as variáveis de ambiente do .env ANTES de qualquer outra coisa
load_dotenv()

from app import create_app

# Agora, o create_app() será executado depois que as variáveis já foram carregadas
app = create_app()

if __name__ == '__main__':
    # Obtém a porta do ambiente ou usa 5000 como padrão
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)