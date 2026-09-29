from sql_injection_lab import create_default_app

app = create_default_app()


if __name__ == "__main__":
    app.run(debug=False)
