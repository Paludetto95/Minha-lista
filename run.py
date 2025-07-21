# run.py
# Este arquivo é o ponto de entrada da sua aplicação.
# Ele importa a função create_app e a utiliza para criar e executar a instância do Flask.
# Nenhuma alteração é necessária aqui.

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
