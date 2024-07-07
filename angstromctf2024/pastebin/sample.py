from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/")
def hello():
    param = request.args.get("error", "")
    print(render_template_string("""{{error}}""", error=param))
    return render_template_string("""{{7*7}}""")

@app.post('/shout')
def shout():
    data = request.data

    return "hello"


if __name__ == "__main__":
    app.run(debug=True, port=8888, threaded=True)
