from flask import Flask, render_template, request
from scanner.headers import analyze_headers

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def dashboard():

    scan_result = None
    target = ""

    if request.method == "POST":

        target = request.form.get("target", "").strip()

        scan_result = analyze_headers(target)

    return render_template(
        "index.html",
        scan_result=scan_result,
        target=target
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)