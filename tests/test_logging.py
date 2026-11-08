import io
import json
import logging
import unittest
from unittest.mock import MagicMock, patch

# Evitar llamadas de red durante la inicialización de MSAL en pruebas
with patch("msal.authority.tenant_discovery") as mock_disc:
    mock_disc.return_value = {
        "authorization_endpoint": (
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize"
        ),
        "token_endpoint": (
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
        ),
        "end_session_endpoint": (
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/logout"
        ),
        "issuer": "https://login.microsoftonline.com/tenant/v2.0"
    }

    from app import create_app
    from app.flow_store import flow_store
    from app.logging_config import (
        JSONFormatter,
        RequestContextFilter
    )


class TestStructuredLogging(unittest.TestCase):

    def setUp(self):
        flow_store.clear()

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Capturar la salida de logging en memoria
        self.log_stream = io.StringIO()
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.setFormatter(JSONFormatter())
        self.handler.addFilter(RequestContextFilter())

        self.root_logger = logging.getLogger()
        self.root_logger.addHandler(self.handler)

    def tearDown(self):
        flow_store.clear()
        self.root_logger.removeHandler(self.handler)
        self.handler.close()

    def _get_logged_records(self):
        self.log_stream.seek(0)

        lines = [
            line.strip()
            for line in self.log_stream.getvalue().splitlines()
            if line.strip()
        ]

        records = []

        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass

        return records

    def test_json_structure_and_iso_timestamp(self):
        """Verifica la estructura JSON estricta y el formato ISO 8601."""
        logger = logging.getLogger("test.json")
        logger.info("test_event_example")

        records = self._get_logged_records()

        target = [
            record for record in records
            if record.get("event") == "test_event_example"
        ][0]

        self.assertIn("timestamp", target)
        self.assertIn("level", target)
        self.assertEqual(target["level"], "INFO")
        self.assertEqual(target["logger"], "test.json")
        self.assertEqual(target["event"], "test_event_example")

        self.assertTrue("T" in target["timestamp"])
        self.assertTrue(
            "+00:00" in target["timestamp"]
            or target["timestamp"].endswith("Z")
        )

    def test_no_arbitrary_extra_attributes_in_json(self):
        """Comprueba que el JSON no incorpora atributos arbitrarios."""
        logger = logging.getLogger("test.extra")

        logger.info(
            "test_extra_blocked",
            extra={
                "arbitrary_field": "val123",
                "other_attr": 456
            }
        )

        records = self._get_logged_records()

        target = [
            record for record in records
            if record.get("event") == "test_extra_blocked"
        ][0]

        self.assertNotIn("arbitrary_field", target)
        self.assertNotIn("other_attr", target)

        self.assertEqual(
            set(target.keys()),
            {"timestamp", "level", "logger", "event"}
        )

    def test_no_sensitive_tokens_or_secrets_via_extra(self):
        """Comprueba que los secretos enviados mediante extra no se registran."""
        logger = logging.getLogger("test.leak")

        logger.info(
            "test_leak_attempt",
            extra={
                "access_token": "secret_access_token_value",
                "client_secret": "secret_client_secret_value",
                "code_verifier": "secret_verifier_value"
            }
        )

        raw_logs = self.log_stream.getvalue()

        self.assertNotIn("secret_access_token_value", raw_logs)
        self.assertNotIn("secret_client_secret_value", raw_logs)
        self.assertNotIn("secret_verifier_value", raw_logs)

    def test_sensitive_data_in_message_is_not_automatically_redacted(self):
        """
        Demuestra que el formatter no censura secretos incluidos directamente
        en el mensaje. Esta prueba documenta una limitación del sistema.
        """
        logger = logging.getLogger("test.message_leak")
        secret = "SECRET_ACCESS_TOKEN_123"

        logger.info("Token obtenido: %s", secret)

        raw_logs = self.log_stream.getvalue()

        # El secreto aparece porque getMessage() incorpora los argumentos.
        # Las llamadas reales de logging deben evitar incluir información sensible.
        self.assertIn(secret, raw_logs)

    def test_logging_without_flask_context_works(self):
        """Comprueba que los registros fuera de Flask siguen funcionando."""
        logger = logging.getLogger("test.standalone")
        logger.info("event_outside_context")

        records = self._get_logged_records()

        target = [
            record for record in records
            if record.get("event") == "event_outside_context"
        ][0]

        self.assertNotIn("request_id", target)
        self.assertEqual(target["event"], "event_outside_context")
        self.assertEqual(target["level"], "INFO")

    def test_request_id_in_flask_context(self):
        """Verifica que el request_id aparece en los logs de una petición."""
        response = self.client.get("/login")

        self.assertEqual(response.status_code, 302)

        records = self._get_logged_records()

        login_records = [
            record for record in records
            if record.get("event") == "login_started"
        ]

        self.assertTrue(len(login_records) >= 1)

        request_id = login_records[0].get("request_id")

        self.assertIsNotNone(request_id)
        self.assertRegex(request_id, r"^[a-f0-9]{32}$")
        self.assertEqual(
            response.headers.get("X-Request-ID"),
            request_id
        )

    def test_server_generates_request_id(self):
        """Comprueba que el servidor ignora el request_id del cliente."""
        supplied_id = "client_supplied_id_123"

        response = self.client.get(
            "/login",
            headers={"X-Request-ID": supplied_id}
        )

        generated_id = response.headers.get("X-Request-ID")

        self.assertIsNotNone(generated_id)
        self.assertRegex(generated_id, r"^[a-f0-9]{32}$")
        self.assertNotEqual(generated_id, supplied_id)

    def test_request_id_is_consistent_within_request(self):
        """Comprueba que los logs de una petición comparten request_id."""
        from flask import g

        with self.app.test_request_context("/test"):
            g.request_id = "request_test_123"

            logger = logging.getLogger("test.correlation")
            logger.info("first_event")
            logger.info("second_event")

        records = self._get_logged_records()

        first = [
            record for record in records
            if record.get("event") == "first_event"
        ][0]

        second = [
            record for record in records
            if record.get("event") == "second_event"
        ][0]

        self.assertEqual(first["request_id"], "request_test_123")
        self.assertEqual(second["request_id"], "request_test_123")

    def test_no_duplicate_handlers_on_multiple_create_app(self):
        """Comprueba que crear varias aplicaciones no duplica handlers JSON."""
        initial_count = len([
            handler
            for handler in logging.getLogger().handlers
            if getattr(handler, "_is_json_handler", False)
        ])

        create_app()
        create_app()
        create_app()

        final_count = len([
            handler
            for handler in logging.getLogger().handlers
            if getattr(handler, "_is_json_handler", False)
        ])

        self.assertEqual(initial_count, final_count)

    def test_expected_403_logged_as_info_not_error(self):
        """Verifica que el 403 esperado de Graph se registra como INFO."""
        from app.graph import probar_acceso_directorio

        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 403

        mock_response.json.return_value = {
            "error": {
                "code": "Authorization_RequestDenied",
                "message": "Insufficient privileges"
            }
        }

        with patch("requests.get", return_value=mock_response):
            status, error = probar_acceso_directorio("fake_token")

            self.assertEqual(status, 403)

        records = self._get_logged_records()

        records_403 = [
            record for record in records
            if record.get("event") == "graph_directory_access_denied"
        ]

        self.assertEqual(len(records_403), 1)
        self.assertEqual(records_403[0]["level"], "INFO")

    def test_error_type_included_when_exception_present(self):
        """Verifica que error_type aparece cuando existe una excepción."""
        logger = logging.getLogger("test.exc")

        try:
            raise ValueError("Error de prueba")
        except ValueError:
            logger.error("error_con_excepcion", exc_info=True)

        records = self._get_logged_records()

        record = [
            item for item in records
            if item.get("event") == "error_con_excepcion"
        ][0]

        self.assertEqual(record["error_type"], "ValueError")

    def test_no_sensitive_data_in_logs(self):
        """
        Comprueba que el flujo de autenticación no registra secretos,
        tokens, parámetros OAuth ni datos sensibles de autenticación.
        """
        secret_pkce = "SUPER_SECRET_PKCE_VERIFIER_123"
        secret_nonce = "SUPER_SECRET_NONCE_ABC"
        secret_token = "SECRET_BEARER_TOKEN_XYZ"
        secret_auth_code = "SECRET_AUTH_CODE_456"
        secret_state = "STATE_RANDOM_SECRET_789"
        secret_binding = "BINDING_SECRET_TOKEN_999"

        mock_flow = {
            "state": secret_state,
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": (
                "https://login.microsoftonline.com/auth"
                f"?state={secret_state}"
            ),
            "code_verifier": secret_pkce,
            "nonce": secret_nonce
        }

        with patch(
            "app.routes.iniciar_login",
            return_value=mock_flow
        ):
            self.client.get("/login")

        with (
            patch("app.routes.obtener_token") as mock_token,
            patch("app.routes.obtener_perfil") as mock_profile,
            patch("app.routes.probar_acceso_directorio") as mock_dir
        ):
            mock_token.return_value = {
                "access_token": secret_token,
                "id_token_claims": {
                    "name": "Antonio Recio",
                    "preferred_username": "arecio@montepinar.com"
                }
            }

            mock_profile.return_value = {
                "displayName": "Antonio Recio",
                "id": "recio-id"
            }

            mock_dir.return_value = (
                403,
                "Authorization_RequestDenied"
            )

            self.client.get(
                f"/getAToken?code={secret_auth_code}&state={secret_state}"
            )

        raw_logs = self.log_stream.getvalue()

        self.assertNotIn(secret_pkce, raw_logs)
        self.assertNotIn(secret_nonce, raw_logs)
        self.assertNotIn(secret_token, raw_logs)
        self.assertNotIn(secret_auth_code, raw_logs)
        self.assertNotIn(secret_state, raw_logs)
        self.assertNotIn(secret_binding, raw_logs)
        self.assertNotIn("Authorization", raw_logs)


if __name__ == "__main__":
    unittest.main()