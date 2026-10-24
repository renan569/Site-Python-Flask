import os
import sqlite3

from pathlib import Path
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from flask_wtf.csrf import CSRFProtect
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)



# CONFIGURAÇÃO DO FLASK


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "chave-temporaria-apenas-para-desenvolvimento"
)

# Proteção contra requisições CSRF
CSRFProtect(app)



# CONFIGURAÇÃO DO BANCO DE DADOS


BASE_DIR = Path(__file__).resolve().parent

DATABASE = BASE_DIR / "usuarios.db"


def conectar_banco():
    """Abre uma conexão com o banco SQLite."""

    conexao = sqlite3.connect(DATABASE)

    conexao.row_factory = sqlite3.Row

    return conexao


def criar_tabela():
    """Cria a tabela de usuários caso ela não exista."""

    with conectar_banco() as conexao:

        conexao.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                senha TEXT NOT NULL
            )
        """)


# Cria a tabela quando o aplicativo é iniciado.
criar_tabela()



# PROTEÇÃO DE ROTAS


def login_obrigatorio(funcao):

    @wraps(funcao)
    def verificar_login(*args, **kwargs):

        if "usuario_id" not in session:

            flash(
                "Faça login para acessar esta página.",
                "erro"
            )

            return redirect(url_for("login"))

        return funcao(*args, **kwargs)

    return verificar_login



# PÁGINA INICIAL


@app.route("/")
def inicio():

    if "usuario_id" in session:
        return redirect(url_for("pagina"))

    return redirect(url_for("login"))



# CADASTRO DE USUÁRIOS


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():

    if request.method == "POST":

        nome = request.form.get(
            "nome", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        senha = request.form.get(
            "senha", ""
        )

        # Verifica se os campos foram preenchidos.
        if not nome or not email or not senha:

            flash(
                "Preencha todos os campos.",
                "erro"
            )

        # Verifica o tamanho dos dados.
        elif len(nome) > 100 or len(email) > 254:

            flash(
                "Nome ou e-mail muito longo.",
                "erro"
            )

        # Exige uma senha com pelo menos 8 caracteres.
        elif len(senha) < 8:

            flash(
                "A senha deve ter pelo menos 8 caracteres.",
                "erro"
            )

        else:

            try:

                # Protege a senha antes de armazená-la.
                senha_hash = generate_password_hash(senha)

                with conectar_banco() as conexao:

                    conexao.execute(
                        """
                        INSERT INTO usuarios
                        (nome, email, senha)
                        VALUES (?, ?, ?)
                        """,
                        (nome, email, senha_hash)
                    )

                flash(
                    "Cadastro realizado com sucesso! Entre com sua conta.",
                    "sucesso"
                )

                return redirect(url_for("login"))

            except sqlite3.IntegrityError:

                flash(
                    "Este e-mail já está cadastrado.",
                    "erro"
                )

    return render_template("cadastro.html")



# LOGIN DE USUÁRIOS


@app.route("/login", methods=["GET", "POST"])
def login():

    # Se o formulário foi enviado:
    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        senha = request.form.get(
            "senha", ""
        )

        # Verifica se os campos foram preenchidos.
        if not email or not senha:

            flash(
                "Informe seu e-mail e sua senha.",
                "erro"
            )

            return redirect(url_for("login"))

        # Busca o usuário no banco de dados.
        with conectar_banco() as conexao:

            usuario = conexao.execute(
                """
                SELECT id, nome, email, senha
                FROM usuarios
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

        # Verifica se o usuário existe e se a senha confere.
        if usuario is not None and check_password_hash(
            usuario["senha"],
            senha
        ):

            # Limpa os dados antigos da sessão.
            session.clear()

            # Registra o usuário autenticado.
            session["usuario_id"] = usuario["id"]

            flash(
                "Login realizado com sucesso!",
                "sucesso"
            )

            # Abre o portfólio.
            return redirect(url_for("pagina"))

        else:

            # E-mail inexistente ou senha incorreta.
            flash(
                "E-mail ou senha incorretos.",
                "erro"
            )

            return redirect(url_for("login"))

    # Se a página foi aberta pelo navegador (GET),
    # apresenta o formulário de login.
    return render_template("login.html")



# PÁGINA DO PORTFÓLIO


@app.route("/pagina")
@login_obrigatorio
def pagina():

    # Busca os dados do usuário autenticado.
    with conectar_banco() as conexao:

        usuario = conexao.execute(
            """
            SELECT id, nome, email
            FROM usuarios
            WHERE id = ?
            """,
            (session["usuario_id"],)
        ).fetchone()

    # Se a conta não existir mais, encerra a sessão.
    if usuario is None:

        session.clear()

        flash(
            "Sua conta não foi encontrada. Entre novamente.",
            "erro"
        )

        return redirect(url_for("login"))

    # Envia os dados para o HTML.
    return render_template(
        "pagina.html",
        usuario=usuario
    )



# ENCERRAR SESSÃO


@app.route("/sair", methods=["POST"])
@login_obrigatorio
def sair():

    session.clear()

    flash(
        "Você saiu da sua conta.",
        "sucesso"
    )

    return redirect(url_for("login"))



# EXECUTAR A APLICAÇÃO


if __name__ == "__main__":

    # debug=True somente durante o desenvolvimento.
    app.run(debug=True)
    
