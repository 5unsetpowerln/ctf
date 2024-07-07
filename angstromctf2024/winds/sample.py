from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/")
def hello():
    # return render_template_string("""{{error}}""", error=request.args.get("error", ""))
    param = request.args.get("error", "")
    print(render_template_string("""{{error}}""", error=param))
    return render_template_string("""{{7*7}}""")


if __name__ == "__main__":
    app.run(debug=True, port=8888, threaded=True)
