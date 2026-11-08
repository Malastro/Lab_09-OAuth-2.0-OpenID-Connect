import os
import re
import unittest
from unittest.mock import patch, MagicMock

# Evitar llamadas de red durante la inicialización de MSAL en pruebas
with patch("msal.authority.tenant_discovery") as mock_disc:
    mock_disc.return_value = {
        "authorization_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        "end_session_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/logout",
        "issuer": "https://login.microsoftonline.com/tenant/v2.0"
    }
    from app import create_app
    from app.flow_store import flow_store
    from app.config import (
        validate_flask_secret_key,
        validate_session_cookie_secure,
        validate_permanent_session_lifetime,
    )


class TestPriorityCorrections(unittest.TestCase):
    def setUp(self):
        flow_store.clear()
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        flow_store.clear()

    def test_session_cookie_settings(self):
        """Verifica la configuración de endurecimiento de cookies de sesión (SEC-03)."""
        self.assertTrue(self.app.config.get("SESSION_COOKIE_HTTPONLY"))
        self.assertEqual(self.app.config.get("SESSION_COOKIE_SAMESITE"), "Lax")
        self.assertIn("SESSION_COOKIE_SECURE", self.app.config)
        self.assertIsNotNone(self.app.config.get("PERMANENT_SESSION_LIFETIME"))

    def test_unauthenticated_index_renders_template(self):
        """Verifica que la página principal anónima se renderiza mediante Jinja2 sin f-strings (SEC-01)."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Mirador de Montepinar S.L.", html)
        self.assertIn("Portal interno de empleados", html)
        self.assertIn("/login", html)

    def test_xss_autoescape_in_user_data_and_claims(self):
        """Verifica que datos dinámicos maliciosos son escapados automáticamente por Jinja2 (SEC-01)."""
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "name": "<script>alert('xss-name')</script>",
                "preferred_username": "<img src=x onerror=alert('xss-user')>",
                "oid": "<b>oid-tag</b>",
                "tid": "tenant-123",
                "iss": "https://issuer.com",
                "aud": "client-abc",
                "exp": 1700000000
            }
            sess["graph_profile"] = {
                "displayName": "<script>alert('xss-graph')</script>",
                "userPrincipalName": "test@montepinar.com",
                "id": "graph-id-123"
            }
            sess["graph_test_status"] = None
            sess["graph_test_error"] = "<svg onload=alert('xss-error')>"

        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)

        # Los scripts NO deben aparecer sin escapar
        self.assertNotIn("<script>alert('xss-name')</script>", html)
        self.assertNotIn("<img src=x onerror=alert('xss-user')>", html)
        self.assertNotIn("<b>oid-tag</b>", html)
        self.assertNotIn("<script>alert('xss-graph')</script>", html)
        self.assertNotIn("<svg onload=alert('xss-error')>", html)

        # Deben aparecer escapados como entidades HTML seguras
        self.assertIn("&lt;script&gt;alert(&#39;xss-name&#39;)&lt;/script&gt;", html)
        self.assertIn("&lt;img src=x onerror=alert(&#39;xss-user&#39;)&gt;", html)
        self.assertIn("&lt;b&gt;oid-tag&lt;/b&gt;", html)
        self.assertIn("&lt;svg onload=alert(&#39;xss-error&#39;)&gt;", html)

    def test_logout_csrf_protection(self):
        """Verifica que /logout rechaza peticiones GET y requiere token CSRF en POST (SEC-02)."""
        # 1. Petición GET debe ser rechazada con 405 Method Not Allowed
        get_response = self.client.get("/logout")
        self.assertEqual(get_response.status_code, 405)

        # 2. Petición POST sin token CSRF debe ser rechazada con 400 Bad Request
        post_without_csrf = self.client.post("/logout")
        self.assertEqual(post_without_csrf.status_code, 400)
        self.assertIn("CSRF", post_without_csrf.get_data(as_text=True).upper())

    def test_logout_with_csrf_succeeds(self):
        """Verifica que un POST con token CSRF válido cierra sesión y redirige al IdP (SEC-02)."""
        with self.client.session_transaction() as sess:
            sess["user"] = {"name": "Joaquín Arias", "preferred_username": "jarias@montepinar.com"}

        # Cargar index para obtener el token CSRF generado en el formulario
        get_resp = self.client.get("/")
        self.assertEqual(get_resp.status_code, 200)
        html = get_resp.get_data(as_text=True)

        # Extraer el valor del csrf_token
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(match, "No se encontró el token CSRF en el formulario de logout.")
        csrf_token = match.group(1)

        # Enviar POST con el token CSRF
        post_resp = self.client.post("/logout", data={"csrf_token": csrf_token})
        self.assertEqual(post_resp.status_code, 302)
        self.assertIn("login.microsoftonline.com", post_resp.headers["Location"])

        # Verificar que la sesión local ha sido destruida
        with self.client.session_transaction() as sess:
            self.assertNotIn("user", sess)

    def test_session_cleared_and_permanent_flag_set_on_login(self):
        """Verifica que en /getAToken se limpia la sesión previa y se activa session.permanent con TTL (SEC-03)."""
        with patch("app.routes.obtener_token") as mock_get_token, \
             patch("app.routes.obtener_perfil") as mock_get_profile, \
             patch("app.routes.probar_acceso_directorio") as mock_test_dir:

            mock_get_token.return_value = {
                "access_token": "mock-access-token-12345",
                "id_token_claims": {
                    "name": "Joaquín Arias",
                    "preferred_username": "jarias@montepinar.com",
                    "oid": "oid-jarias",
                    "tid": "tid-montepinar",
                    "iss": "https://login.microsoftonline.com/tenant/v2.0",
                    "aud": "aud-app",
                    "exp": 1800000000
                }
            }
            mock_get_profile.return_value = {
                "displayName": "Joaquín Arias",
                "userPrincipalName": "jarias@montepinar.com",
                "id": "graph-id-jarias"
            }
            mock_test_dir.return_value = (403, "Authorization_RequestDenied")

            # Guardar flujo en el almacén de servidor
            binding = flow_store.save_flow("abc-state", {"state": "abc-state", "auth_uri": "https://login.microsoftonline.com"})

            # Guardar la vinculación en la sesión del cliente junto a datos residuales
            with self.client.session_transaction() as sess:
                sess["flows"] = {"abc-state": binding}
                sess["residual_key"] = "stale_session_value"

            resp = self.client.get("/getAToken?code=mock_code&state=abc-state")
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers["Location"], "/")

            # Verificar que la cookie Set-Cookie incluye directivas de expiración (Expires / Max-Age)
            set_cookie_header = resp.headers.get("Set-Cookie", "")
            self.assertTrue(
                "Expires=" in set_cookie_header or "Max-Age=" in set_cookie_header,
                f"La cabecera Set-Cookie debería incluir directivas de expiración permanente: {set_cookie_header}"
            )

            with self.client.session_transaction() as sess:
                # Las claves previas debieron eliminarse al limpiar la sesión
                self.assertNotIn("residual_key", sess)
                self.assertNotIn("abc-state", sess.get("flows", {}))
                # La sesión debe estar marcada como permanente
                self.assertTrue(sess.permanent)
                # La nueva identidad debe estar correctamente establecida
                self.assertIn("user", sess)
                self.assertEqual(sess["user"]["name"], "Joaquín Arias")
                # El resultado 403 intencionado de /users debe persistirse
                self.assertEqual(sess["graph_test_status"], 403)
                self.assertEqual(sess["graph_test_error"], "Authorization_RequestDenied")
                # Tokens sensibles no deben existir en la sesión
                self.assertNotIn("access_token", sess)
                self.assertNotIn("client_secret", sess)

    def test_config_validation_permanent_session_lifetime(self):
        """Verifica que validate_permanent_session_lifetime exige enteros válidos >= 1 y rechaza decimales, booleanos y tipos inválidos (SEC-04)."""
        # Debe aceptar cadenas enteras válidas y números enteros
        self.assertEqual(validate_permanent_session_lifetime("60"), 60)
        self.assertEqual(validate_permanent_session_lifetime(60), 60)
        self.assertEqual(validate_permanent_session_lifetime("30"), 30)

        # Debe rechazar valores decimales (tanto cadenas como floats)
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime("1.5")
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime(1.5)
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime(60.0)

        # Debe rechazar booleanos y None
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime(True)
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime(False)
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime(None)

        # Debe rechazar cero y números negativos
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime("0")
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime(0)
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime("-15")
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime(-15)

        # Debe rechazar cadenas no numéricas
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime("not-a-number")
        with self.assertRaises(ValueError):
            validate_permanent_session_lifetime("")

    def test_config_validation_flask_secret_key(self):
        """Verifica que validate_flask_secret_key rechaza claves cortas, vacías, de plantilla o con patrones repetitivos triviales."""
        # Rechazar vacío, None o solo espacios
        with self.assertRaises(ValueError):
            validate_flask_secret_key("")
        with self.assertRaises(ValueError):
            validate_flask_secret_key(None)
        with self.assertRaises(ValueError):
            validate_flask_secret_key("   ")

        # Rechazar longitud inferior a 32 caracteres
        with self.assertRaises(ValueError):
            validate_flask_secret_key("clave-corta-de-menos-de-32-c")
        with self.assertRaises(ValueError):
            validate_flask_secret_key("1234567890123456789012345678901")  # 31 caracteres

        # Rechazar valores de ejemplo o marcadores de posición
        with self.assertRaises(ValueError):
            validate_flask_secret_key("change-me-to-a-secure-random-key-at-least-32-chars-long")
        with self.assertRaises(ValueError):
            validate_flask_secret_key("GENERA_TU_PROPIA_CLAVE_ALEATORIA_CON_EL_COMANDO_SUPERIOR")
        with self.assertRaises(ValueError):
            validate_flask_secret_key("mi-clave-super-secreta-con-placeholder-123456")
        with self.assertRaises(ValueError):
            validate_flask_secret_key("esto-es-un-ejemplo-your-secret-key-aqui-12345678")

        # Rechazar patrones repetitivos triviales (menos de 8 caracteres distintos)
        with self.assertRaises(ValueError):
            validate_flask_secret_key("a" * 40)
        with self.assertRaises(ValueError):
            validate_flask_secret_key("abcdef" + "a" * 30)  # menos de 8 caracteres distintos

        # Aceptar claves válidas y robustas
        valid_key_48 = "kL9_zP4xQ2wE8rT1yU3iO5pA7sD6fG0hJ-vB9nM2cZ8xY7wV"
        self.assertEqual(validate_flask_secret_key(valid_key_48), valid_key_48)

        valid_hex_64 = "4f8a1c9e2b3d7a6f5e0c8b9d1a2f3e4c5b6a7d8e9f0a1b2c3d4e5f6a7b8c9d0e"
        self.assertEqual(validate_flask_secret_key(valid_hex_64), valid_hex_64)

    def test_character_diversity_is_not_an_entropy_guarantee(self):
        """
        Demuestra que la comprobación de diversidad de caracteres (len(set) >= 8)
        es únicamente un filtro de higiene contra patrones triviales, pero NO constituye
        una garantía de entropía criptográfica.

        Una clave estructurada y predecible como 'abcdefgh' * 4 posee 8 caracteres únicos
        y 32 caracteres de longitud, superando la validación sintáctica a pesar de carecer
        de entropía real. Esto demuestra que los controles sintácticos no sustituyen la generación
        mediante un CSPRNG robusto (secrets.token_urlsafe(48)).
        """
        predictable_key = "abcdefgh" * 4  # 32 caracteres, 8 únicos
        self.assertEqual(len(set(predictable_key)), 8)
        self.assertEqual(len(predictable_key), 32)

        # Supera la validación sintáctica por cumplir longitud y diversidad mínima
        validated = validate_flask_secret_key(predictable_key)
        self.assertEqual(validated, predictable_key)

        # Confirmación de que una clave generada mediante CSPRNG cumple la validación
        import secrets
        csprng_key = secrets.token_urlsafe(48)
        self.assertEqual(validate_flask_secret_key(csprng_key), csprng_key)

    def test_config_validation_session_cookie_secure(self):
        """Verifica que validate_session_cookie_secure admite solo 'true'/'false' y rechaza erratas u otros valores."""
        # Valores válidos
        self.assertTrue(validate_session_cookie_secure("true"))
        self.assertTrue(validate_session_cookie_secure("True"))
        self.assertTrue(validate_session_cookie_secure("TRUE"))
        self.assertTrue(validate_session_cookie_secure("  true  "))

        self.assertFalse(validate_session_cookie_secure("false"))
        self.assertFalse(validate_session_cookie_secure("False"))
        self.assertFalse(validate_session_cookie_secure("FALSE"))
        self.assertFalse(validate_session_cookie_secure("  false  "))

        # Erratas y valores no estrictamente booleanos deben lanzar ValueError
        with self.assertRaises(ValueError):
            validate_session_cookie_secure("treu")
        with self.assertRaises(ValueError):
            validate_session_cookie_secure("flase")
        with self.assertRaises(ValueError):
            validate_session_cookie_secure("yes")
        with self.assertRaises(ValueError):
            validate_session_cookie_secure("no")
        with self.assertRaises(ValueError):
            validate_session_cookie_secure("1")
        with self.assertRaises(ValueError):
            validate_session_cookie_secure("0")
        with self.assertRaises(ValueError):
            validate_session_cookie_secure("")
        with self.assertRaises(ValueError):
            validate_session_cookie_secure("   ")
        with self.assertRaises(ValueError):
            validate_session_cookie_secure(None)
        with self.assertRaises(ValueError):
            validate_session_cookie_secure(True)
        with self.assertRaises(ValueError):
            validate_session_cookie_secure(False)

    def test_full_portal_flow_with_joaquin_arias(self):
        """Prueba automatizada con mocks del ciclo completo con Joaquín Arias: login, callback con claims, perfil Graph, 403 y logout."""
        # 1. Login inicial
        with patch("app.routes.iniciar_login") as mock_init:
            mock_init.return_value = {
                "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=xyz",
                "state": "mock_state_jarias",
                "code_verifier": "verifier_jarias"
            }
            r_login = self.client.get("/login")
            self.assertEqual(r_login.status_code, 302)
            self.assertIn("login.microsoftonline.com", r_login.headers["Location"])

        # 2. Callback de autenticación (/getAToken) desde el mismo cliente
        with patch("app.routes.obtener_token") as mock_token, \
             patch("app.routes.obtener_perfil") as mock_profile, \
             patch("app.routes.probar_acceso_directorio") as mock_dir:

            mock_token.return_value = {
                "access_token": "mock_at_jarias",
                "id_token_claims": {
                    "name": "Joaquín Arias",
                    "preferred_username": "jarias@montepinar.com",
                    "oid": "oid-jarias-123",
                    "tid": "tid-montepinar-456",
                    "iss": "https://login.microsoftonline.com/tid-montepinar-456/v2.0",
                    "aud": "client-id-app",
                    "exp": 1900000000
                }
            }
            mock_profile.return_value = {
                "displayName": "Joaquín Arias",
                "userPrincipalName": "jarias@montepinar.com",
                "id": "graph-user-jarias"
            }
            mock_dir.return_value = (403, "Authorization_RequestDenied")

            r_callback = self.client.get("/getAToken?code=mock_code&state=mock_state_jarias")
            self.assertEqual(r_callback.status_code, 302)
            self.assertEqual(r_callback.headers["Location"], "/")

        # 3. Vista del portal autenticado
        r_index = self.client.get("/")
        self.assertEqual(r_index.status_code, 200)
        html = r_index.get_data(as_text=True)

        self.assertIn("Bienvenido, Joaquín Arias", html)
        self.assertIn("jarias@montepinar.com", html)
        self.assertIn("oid-jarias-123", html)
        self.assertIn("Código HTTP:", html)
        self.assertIn("403", html)
        self.assertIn("Acceso denegado", html)
        self.assertIn("Autenticación correcta.", html)
        self.assertIn("Autorización insuficiente.", html)
        # Comprobar que el texto de diagnóstico se genera dinámicamente con user.name
        self.assertIn("Joaquín Arias ha iniciado sesión correctamente", html)
        # Comprobar que no existen nombres fijos de otros usuarios
        self.assertNotIn("Antonio Recio", html)
        self.assertIn('name="csrf_token"', html)

        # 4. Cierre de sesión protegido con CSRF
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(match)
        csrf_token = match.group(1)

        r_logout = self.client.post("/logout", data={"csrf_token": csrf_token})
        self.assertEqual(r_logout.status_code, 302)
        self.assertIn("logout", r_logout.headers["Location"])

        # 5. Comprobación final tras logout
        r_after = self.client.get("/")
        self.assertIn("Portal interno de empleados", r_after.get_data(as_text=True))
        self.assertNotIn("Bienvenido, Joaquín Arias", r_after.get_data(as_text=True))

    def test_portal_dynamically_renders_sergio_arias(self):
        """Verifica que el portal representa dinámicamente a Sergio Arias y no fija ningún nombre."""
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "name": "Sergio Arias",
                "preferred_username": "sarias@montepinar.com",
                "oid": "oid-sarias-789",
                "tid": "tid-montepinar-456",
                "iss": "https://login.microsoftonline.com/tid-montepinar-456/v2.0",
                "aud": "client-id-app",
                "exp": 1900000000
            }
            sess["graph_profile"] = {
                "displayName": "Sergio Arias",
                "userPrincipalName": "sarias@montepinar.com",
                "id": "graph-user-sarias"
            }
            sess["graph_test_status"] = 403
            sess["graph_test_error"] = "Authorization_RequestDenied"

        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)

        self.assertIn("Bienvenido, Sergio Arias", html)
        self.assertIn("sarias@montepinar.com", html)
        self.assertIn("Sergio Arias ha iniciado sesión correctamente", html)
        self.assertNotIn("Joaquín Arias", html)
        self.assertNotIn("Antonio Recio", html)


if __name__ == "__main__":
    unittest.main()
