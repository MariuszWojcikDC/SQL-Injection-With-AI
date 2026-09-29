from flask import session

from app import app


@app.before_request
def force_vulnerable_mode():
    session["app_mode"] = "VULNERABLE"


if __name__ == "__main__":
    app.run(debug=True, port=5001)
