import secrets
from datetime import timedelta

from flask import Flask, g
from flask_wtf.csrf import CSRFProtect

from app.config import (
    FLASK_SECRET_KEY,
    SESSION_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME_MINUTES
)
from app.logging_config import configure_logging
from app.routes import main


# Instancia de protección CSRF para la aplicación
csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    # Configuración de logging estructurado JSON centralizado
    configure_logging(app)

    # Configuración de seguridad de las sesiones
    app.secret_key = FLASK_SECRET_KEY
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
        PERMANENT_SESSION_LIFETIME=timedelta(
            minutes=PERMANENT_SESSION_LIFETIME_MINUTES
        )
    )

    # Inicializar la protección CSRF
    csrf.init_app(app)

    # Generar un identificador único para cada petición
    @app.before_request
    def set_request_id():
        g.request_id = secrets.token_hex(16)

    # Devolver el identificador en la respuesta HTTP
    @app.after_request
    def add_request_id_header(response):
        response.headers["X-Request-ID"] = g.request_id
        return response

    # Registrar las rutas del portal
    app.register_blueprint(main)

    return app