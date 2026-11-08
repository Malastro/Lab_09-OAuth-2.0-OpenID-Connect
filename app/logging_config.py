import json
import logging
import os
import secrets
from datetime import datetime, timezone

from flask import g, has_request_context


class RequestContextFilter(logging.Filter):
    """
    Filtro que añade el request_id al LogRecord si existe contexto de petición activo,
    evitando excepciones cuando se ejecuta fuera del ciclo de vida de Flask.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if has_request_context():
            req_id = getattr(g, "request_id", None)
            if req_id is None:
                req_id = getattr(record, "request_id", None) or secrets.token_hex(16)
                g.request_id = req_id
            record.request_id = req_id
        else:
            record.request_id = getattr(record, "request_id", None)
        return True


class JSONFormatter(logging.Formatter):
    """
    Formateador de registros en JSON estructurado con marca temporal ISO 8601.
    Contiene un esquema estricto y cerrado para evitar la fuga accidental de datos
    mediante campos arbitrarios o argumentos 'extra'.
    """

    def format(self, record: logging.LogRecord) -> str:
        timestamp_iso = datetime.fromtimestamp(
            record.created, tz=timezone.utc
        ).isoformat()

        log_entry = {
            "timestamp": timestamp_iso,
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }

        # request_id únicamente cuando exista
        request_id = getattr(record, "request_id", None)
        if request_id:
            log_entry["request_id"] = request_id

        # error_type únicamente cuando exista una excepción asociada
        if record.exc_info and record.exc_info[0]:
            log_entry["error_type"] = record.exc_info[0].__name__

        return json.dumps(log_entry)


def configure_logging(app=None) -> None:
    """
    Configura el sistema de logging centralizado en formato JSON estándar.
    Idempotente: no añade handlers duplicados al crear múltiples instancias de Flask.
    """
    log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Comprobar si ya existe un handler JSON configurado en el logger raíz
    for handler in root_logger.handlers:
        if getattr(handler, "_is_json_handler", False):
            handler.setLevel(log_level)
            return

    json_handler = logging.StreamHandler()
    json_handler._is_json_handler = True
    json_handler.setLevel(log_level)
    json_handler.setFormatter(JSONFormatter())
    json_handler.addFilter(RequestContextFilter())

    root_logger.addHandler(json_handler)

    # Si se pasa una aplicación Flask, limpiar handlers por defecto para evitar duplicación
    if app is not None:
        app.logger.handlers.clear()
        app.logger.propagate = True
