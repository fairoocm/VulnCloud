from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h1>VulnCloud Test Website</h1>
    <p>This is our local security testing environment.</p>
    <p>Website is running successfully!</p>
    """


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)