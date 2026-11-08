import re
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

# Mock para evitar llamadas de red durante la importación e inicialización de MSAL
with patch("msal.authority.tenant_discovery") as mock_disc:
    mock_disc.return_value = {
        "authorization_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        "end_session_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/logout",
        "issuer": "https://login.microsoftonline.com/tenant/v2.0",
    }
    from app import create_app
    from app.config import (
        AUTHORITY,
        POST_LOGOUT_REDIRECT_URI,
        validate_post_logout_redirect_uri,
        validate_tenant_id,
    )


class TestLogoutOIDC(unittest.TestCase):
    """
    Pruebas automatizadas para el control SEC-06: Cierre de sesión OIDC con Microsoft Entra ID.
    Valida la construcción tenant-specific, la protección CSRF, el método HTTP, la codificación
    segura de parámetros y la validación estricta de la configuración.
    """

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def _get_csrf_token(self) -> str:
        """Obtiene un token CSRF válido desde el formulario renderizado en la página principal."""
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "name": "Joaquín Arias",
                "preferred_username": "jarias@montepinar.com"
            }
        resp = self.client.get("/")
        html = resp.get_data(as_text=True)
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(match, "No se encontró el token CSRF en el formulario HTML.")
        return match.group(1)

    # Caso 1. Endpoint tenant-specific
    def test_case_1_logout_endpoint_is_tenant_specific(self):
        """
        Caso 1: Comprobar que la URL de logout utiliza el tenant configurado en AUTHORITY
        y no utiliza los endpoints genéricos /common/ ni /organizations/.
        """
        csrf_token = self._get_csrf_token()
        response = self.client.post("/logout", data={"csrf_token": csrf_token})
        self.assertEqual(response.status_code, 302)

        location = response.headers.get("Location", "")
        expected_base = f"{AUTHORITY.rstrip('/')}/oauth2/v2.0/logout"

        # La URL debe comenzar por el endpoint específico del tenant
        self.assertTrue(
            location.startswith(expected_base),
            f"La URL de logout '{location}' no utiliza el endpoint tenant-specific '{expected_base}'."
        )

        # No debe haber referencias a /common/ ni /organizations/
        self.assertNotIn("/common/", location)
        self.assertNotIn("/organizations/", location)

    # Caso 2. URL de retorno
    def test_case_2_post_logout_redirect_uri_matches_configuration(self):
        """
        Caso 2: Comprobar que post_logout_redirect_uri contiene exactamente la URL configurada.
        """
        csrf_token = self._get_csrf_token()
        response = self.client.post("/logout", data={"csrf_token": csrf_token})
        self.assertEqual(response.status_code, 302)

        location = response.headers.get("Location", "")
        parsed = urlsplit(location)
        query = parse_qs(parsed.query)

        self.assertIn("post_logout_redirect_uri", query)
        self.assertEqual(query["post_logout_redirect_uri"][0], POST_LOGOUT_REDIRECT_URI)

    # Caso 3. Limpieza de sesión
    def test_case_3_session_cleared_on_logout(self):
        """
        Caso 3: Comprobar que los datos locales de sesión se eliminan después de realizar la petición de logout.
        """
        # Poblar la sesión con datos de usuario autenticado
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "name": "Joaquín Arias",
                "preferred_username": "jarias@montepinar.com",
                "oid": "test-oid-123"
            }
            sess["graph_profile"] = {
                "displayName": "Joaquín Arias",
                "userPrincipalName": "jarias@montepinar.com"
            }
            sess["graph_test_status"] = 403
            sess["flows"] = {"state_1": "token_binding_1"}

        csrf_token = self._get_csrf_token()
        response = self.client.post("/logout", data={"csrf_token": csrf_token})
        self.assertEqual(response.status_code, 302)

        # Comprobar que la sesión ha sido limpiada en su totalidad
        with self.client.session_transaction() as sess:
            self.assertNotIn("user", sess)
            self.assertNotIn("graph_profile", sess)
            self.assertNotIn("graph_test_status", sess)
            self.assertNotIn("flows", sess)
            self.assertEqual(len(sess), 0)

    # Caso 4. Método HTTP
    def test_case_4_http_methods(self):
        """
        Caso 4: Comprobar que POST funciona y GET devuelve HTTP 405 Method Not Allowed.
        """
        # GET debe devolver 405
        get_resp = self.client.get("/logout")
        self.assertEqual(get_resp.status_code, 405)

        # PUT debe devolver 405
        put_resp = self.client.put("/logout")
        self.assertEqual(put_resp.status_code, 405)

        # DELETE debe devolver 405
        delete_resp = self.client.delete("/logout")
        self.assertEqual(delete_resp.status_code, 405)

        # POST con CSRF debe funcionar (302)
        csrf_token = self._get_csrf_token()
        post_resp = self.client.post("/logout", data={"csrf_token": csrf_token})
        self.assertEqual(post_resp.status_code, 302)

    # Caso 5. Protección CSRF
    def test_case_5_csrf_protection_on_logout(self):
        """
        Caso 5: Comprobar que una petición POST sin token CSRF válido es rechazada cuando
        la protección CSRF está activada (sin desactivarla globalmente).
        """
        # POST sin token CSRF -> 400 Bad Request
        resp_no_csrf = self.client.post("/logout")
        self.assertEqual(resp_no_csrf.status_code, 400)
        self.assertIn("CSRF", resp_no_csrf.get_data(as_text=True).upper())

        # POST con token CSRF inválido / manipulado -> 400 Bad Request
        resp_bad_csrf = self.client.post("/logout", data={"csrf_token": "tampered_token_xyz"})
        self.assertEqual(resp_bad_csrf.status_code, 400)
        self.assertIn("CSRF", resp_bad_csrf.get_data(as_text=True).upper())

    # Caso 6. Codificación de URL
    def test_case_6_url_parameter_encoding(self):
        """
        Caso 6: Comprobar que los parámetros de la URL están correctamente codificados
        y no se concatenan manualmente de forma insegura.
        """
        # Probar con una URL configurada que contenga caracteres especiales
        test_redirect_uri = "http://localhost:5000/callback?scope=user&tenant=mirador"
        with patch("app.routes.POST_LOGOUT_REDIRECT_URI", test_redirect_uri):
            csrf_token = self._get_csrf_token()
            response = self.client.post("/logout", data={"csrf_token": csrf_token})
            self.assertEqual(response.status_code, 302)

            location = response.headers.get("Location", "")
            # El parámetro post_logout_redirect_uri debe estar debidamente codificado
            self.assertIn("post_logout_redirect_uri=", location)
            parsed = urlsplit(location)
            query = parse_qs(parsed.query)

            # urlsplit + parse_qs debe recuperar el valor exacto sin romper el query string
            self.assertEqual(query["post_logout_redirect_uri"][0], test_redirect_uri)


class TestConfigHardening(unittest.TestCase):
    """
    Pruebas exhaustivas para las validaciones y endurecimiento de configuración (SEC-06).
    Verifica los requisitos específicos de TENANT_ID y POST_LOGOUT_REDIRECT_URI.
    """

    # --- Pruebas de TENANT_ID ---

    def test_tenant_id_validation_valid_uuid(self):
        """Comprueba que un UUID estándar de tenant es aceptado."""
        sample_uuid = "80a71676-e0e9-4e58-9be5-1f8d4847e09d"
        self.assertEqual(validate_tenant_id(sample_uuid), sample_uuid)

        # UUID en mayúsculas también es válido
        self.assertEqual(validate_tenant_id(sample_uuid.upper()), sample_uuid.upper())

    def test_tenant_id_validation_valid_domain(self):
        """Comprueba que un dominio de tenant válido (FQDN) es aceptado."""
        self.assertEqual(
            validate_tenant_id("montepinar.onmicrosoft.com"),
            "montepinar.onmicrosoft.com"
        )
        self.assertEqual(
            validate_tenant_id("contoso.com"),
            "contoso.com"
        )

    def test_tenant_id_validation_valid_domain_with_hyphens(self):
        """Comprueba que un dominio con guiones válidos dentro de las etiquetas es aceptado."""
        self.assertEqual(
            validate_tenant_id("monte-pinar.onmicrosoft.com"),
            "monte-pinar.onmicrosoft.com"
        )
        self.assertEqual(
            validate_tenant_id("my-company.com"),
            "my-company.com"
        )

    def test_tenant_id_validation_domain_hyphen_at_start_or_end_rejected(self):
        """Comprueba que dominios con etiquetas que empiezan o terminan en guion son rechazados."""
        with self.assertRaises(ValueError):
            validate_tenant_id("-bad.com")

        with self.assertRaises(ValueError):
            validate_tenant_id("bad-.com")

        with self.assertRaises(ValueError):
            validate_tenant_id("sub.-bad.com")

        with self.assertRaises(ValueError):
            validate_tenant_id("sub.bad-.com")

    def test_tenant_id_validation_generic_endpoints_rejected(self):
        """Comprueba que common, organizations y consumers son rechazados expresamente."""
        with self.assertRaises(ValueError):
            validate_tenant_id("common")

        with self.assertRaises(ValueError):
            validate_tenant_id("COMMON")

        with self.assertRaises(ValueError):
            validate_tenant_id("organizations")

        with self.assertRaises(ValueError):
            validate_tenant_id("ORGANIZATIONS")

        with self.assertRaises(ValueError):
            validate_tenant_id("consumers")

        with self.assertRaises(ValueError):
            validate_tenant_id("CONSUMERS")

    def test_tenant_id_validation_slashes_rejected(self):
        """Comprueba que identificadores con barras '/' o '\\' son rechazados."""
        with self.assertRaises(ValueError):
            validate_tenant_id("tenant/segment")

        with self.assertRaises(ValueError):
            validate_tenant_id("/tenant")

        with self.assertRaises(ValueError):
            validate_tenant_id("tenant/")

        with self.assertRaises(ValueError):
            validate_tenant_id("tenant\\segment")

    def test_tenant_id_validation_spaces_rejected(self):
        """Comprueba que identificadores con espacios o caracteres de control son rechazados."""
        with self.assertRaises(ValueError):
            validate_tenant_id("tenant id")

        with self.assertRaises(ValueError):
            validate_tenant_id(" tenant-id")

        with self.assertRaises(ValueError):
            validate_tenant_id("tenant-id\t")

    def test_tenant_id_validation_params_and_fragments_rejected(self):
        """Comprueba que identificadores con parámetros '?' o fragmentos '#' son rechazados."""
        with self.assertRaises(ValueError):
            validate_tenant_id("80a71676-e0e9-4e58-9be5-1f8d4847e09d?param=1")

        with self.assertRaises(ValueError):
            validate_tenant_id("montepinar.onmicrosoft.com#section")

    def test_tenant_id_validation_empty_rejected(self):
        """Comprueba que identificadores vacíos, nulos o de tipo inválido son rechazados."""
        with self.assertRaises(ValueError):
            validate_tenant_id("")

        with self.assertRaises(ValueError):
            validate_tenant_id(None)

        with self.assertRaises(ValueError):
            validate_tenant_id(12345)

    # --- Pruebas de POST_LOGOUT_REDIRECT_URI ---

    def test_post_logout_redirect_uri_localhost_http_accepted(self):
        """Comprueba que HTTP es aceptado para localhost."""
        self.assertEqual(
            validate_post_logout_redirect_uri("http://localhost:5000/"),
            "http://localhost:5000/"
        )
        self.assertEqual(
            validate_post_logout_redirect_uri("http://localhost/"),
            "http://localhost/"
        )

    def test_post_logout_redirect_uri_127_0_0_1_http_accepted(self):
        """Comprueba que HTTP es aceptado para la dirección IPv4 loopback 127.0.0.1."""
        self.assertEqual(
            validate_post_logout_redirect_uri("http://127.0.0.1:5000/"),
            "http://127.0.0.1:5000/"
        )
        self.assertEqual(
            validate_post_logout_redirect_uri("http://127.0.0.1/logout"),
            "http://127.0.0.1/logout"
        )

    def test_post_logout_redirect_uri_ipv6_loopback_http_accepted(self):
        """Comprueba que HTTP es aceptado para la dirección IPv6 loopback [::1]."""
        self.assertEqual(
            validate_post_logout_redirect_uri("http://[::1]:5000/"),
            "http://[::1]:5000/"
        )
        self.assertEqual(
            validate_post_logout_redirect_uri("http://[::1]/"),
            "http://[::1]/"
        )

    def test_post_logout_redirect_uri_https_external_accepted(self):
        """Comprueba que HTTPS es aceptado para dominios externos."""
        self.assertEqual(
            validate_post_logout_redirect_uri("https://portal.montepinar.es/"),
            "https://portal.montepinar.es/"
        )
        self.assertEqual(
            validate_post_logout_redirect_uri("https://login.example.com/logout-callback"),
            "https://login.example.com/logout-callback"
        )

    def test_post_logout_redirect_uri_ipv4_external_https_accepted(self):
        """Comprueba que una dirección IPv4 externa con HTTPS es aceptada."""
        self.assertEqual(
            validate_post_logout_redirect_uri("https://198.51.100.1:5000/"),
            "https://198.51.100.1:5000/"
        )
        self.assertEqual(
            validate_post_logout_redirect_uri("https://198.51.100.1/"),
            "https://198.51.100.1/"
        )

    def test_post_logout_redirect_uri_ipv6_external_https_accepted(self):
        """Comprueba que una dirección IPv6 externa con HTTPS es aceptada."""
        self.assertEqual(
            validate_post_logout_redirect_uri("https://[2001:db8::1]:5000/"),
            "https://[2001:db8::1]:5000/"
        )
        self.assertEqual(
            validate_post_logout_redirect_uri("https://[2001:db8::1]/"),
            "https://[2001:db8::1]/"
        )

    def test_post_logout_redirect_uri_http_external_rejected(self):
        """Comprueba que HTTP es rechazado para dominios externos no loopback (IPv4 e IPv6)."""
        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://portal.montepinar.es/")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://example.com/logout")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://192.168.1.100:5000/")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://[2001:db8::1]:5000/")

    def test_post_logout_redirect_uri_malformed_url_rejected(self):
        """Comprueba que URLs malformadas son interceptadas y rechazadas."""
        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://[invalid-ipv6]/")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://::1:5000/")

    def test_post_logout_redirect_uri_invalid_port_rejected(self):
        """Comprueba que puertos fuera de rango (1-65535) o no numéricos son rechazados."""
        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://localhost:99999/")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://localhost:0/")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://localhost:invalid-port/")

    def test_post_logout_redirect_uri_hostname_spaces_rejected(self):
        """Comprueba que hostnames con espacios o caracteres de control son rechazados."""
        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://local host:5000/")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("https://portal montepinar.es/")

    def test_post_logout_redirect_uri_fragment_rejected(self):
        """Comprueba que URLs con fragmentos (#) son rechazadas."""
        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://localhost:5000/#logout-done")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("https://portal.montepinar.es/callback#top")

    def test_post_logout_redirect_uri_backslash_rejected(self):
        """Comprueba que URLs con barras invertidas '\\' son rechazadas."""
        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://localhost:5000/\\path")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("https://portal.montepinar.es\\logout")

    def test_post_logout_redirect_uri_preserves_query_string(self):
        """Comprueba que query strings legítimos son conservados íntegramente."""
        uri_local = "http://localhost:5000/?post_logout=1&client=web"
        self.assertEqual(validate_post_logout_redirect_uri(uri_local), uri_local)

        uri_ext = "https://portal.montepinar.es/auth?action=logged_out&tenant=montepinar"
        self.assertEqual(validate_post_logout_redirect_uri(uri_ext), uri_ext)

    def test_post_logout_redirect_uri_invalid_schemes_and_relative(self):
        """Comprueba que esquemas no HTTP/HTTPS y URLs relativas son rechazados."""
        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("ftp://localhost:5000/")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("javascript:alert(1)")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("file:///etc/passwd")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("/relative/path")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("index.html")

        with self.assertRaises(ValueError):
            validate_post_logout_redirect_uri("http://admin:secret@localhost:5000/")


if __name__ == "__main__":
    unittest.main()
