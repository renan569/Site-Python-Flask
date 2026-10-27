
from flask import Flask, render_template

app = Flask(__name__)


# Página principal do portfólio
@app.route("/")
@app.route("/pagina")
def pagina():
    return render_template("pagina.html")


# Executar o servidor Flask
if __name__ == "__main__":
    app.run(debug=True)
