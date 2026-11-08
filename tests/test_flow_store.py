import base64
import json
import time
import unittest
from unittest.mock import MagicMock, patch

# Evitar llamadas de red durante la inicialización de MSAL en pruebas
with patch("msal.authority.tenant_discovery") as mock_disc:
    mock_disc.return_value = {
        "authorization_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        "end_session_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/logout",
        "issuer": "https://login.microsoftonline.com/tenant/v2.0"
    }
    from app import create_app
    from app.flow_store import FlowStore, flow_store


class TestFlowStoreLogic(unittest.TestCase):
    """Pruebas unitarias de la lógica interna de FlowStore (aislamiento con mocks)."""

    def setUp(self):
        self.store = FlowStore(ttl_seconds=1)  # TTL corto para pruebas de caducidad

    def test_ttl_seconds_validation(self):
        """Comprueba que FlowStore valida que ttl_seconds sea un entero positivo."""
        with self.assertRaises(ValueError):
            FlowStore(ttl_seconds=0)
        with self.assertRaises(ValueError):
            FlowStore(ttl_seconds=-10)
        with self.assertRaises(ValueError):
            FlowStore(ttl_seconds="600")
        with self.assertRaises(ValueError):
            FlowStore(ttl_seconds=True)
        # Un valor entero positivo debe ser aceptado
        store = FlowStore(ttl_seconds=300)
        self.assertEqual(store._ttl_seconds, 300)

    def test_save_and_pop_flow_success(self):
        """Comprueba que un flujo guardado puede recuperarse si el binding_token coincide."""
        flow_data = {"code_verifier": "secret_pkce_123", "state": "state_abc"}
        binding = self.store.save_flow("state_abc", flow_data)

        flow, error = self.store.pop_flow("state_abc", binding)
        self.assertIsNone(error)
        self.assertEqual(flow, flow_data)

    def test_flow_consumed_cannot_be_reused(self):
        """Comprueba que un flujo consumido no puede ser reutilizado (prevención de repetición / replay)."""
        flow_data = {"code_verifier": "secret_pkce_123", "state": "state_abc"}
        binding = self.store.save_flow("state_abc", flow_data)

        # Primer consumo: exitoso
        flow1, error1 = self.store.pop_flow("state_abc", binding)
        self.assertEqual(flow1, flow_data)
        self.assertIsNone(error1)

        # Segundo intento de consumo con los mismos datos: debe fallar
        flow2, error2 = self.store.pop_flow("state_abc", binding)
        self.assertIsNone(flow2)
        self.assertEqual(error2, "flow_not_found_or_already_consumed")

    def test_invalid_binding_does_not_destroy_flow(self):
        """Comprueba que un binding_token incorrecto NO destruye el flujo legítimo (Req 1)."""
        flow_data = {"code_verifier": "secret_pkce_123", "state": "state_abc"}
        binding = self.store.save_flow("state_abc", flow_data)

        # Intento de acceso con binding erróneo
        flow_bad, error_bad = self.store.pop_flow("state_abc", "wrong_binding_token")
        self.assertIsNone(flow_bad)
        self.assertEqual(error_bad, "browser_binding_mismatch")

        # El flujo original DEBE permanecer intacto en el almacén
        self.assertTrue(self.store.has_flow("state_abc"))

        # El usuario legítimo con su binding_token correcto debe poder consumirlo exitosamente
        flow_good, error_good = self.store.pop_flow("state_abc", binding)
        self.assertIsNone(error_good)
        self.assertEqual(flow_good, flow_data)

        # Una vez consumido legítimamente, ya no debe existir
        self.assertFalse(self.store.has_flow("state_abc"))

    def test_non_string_binding_token_rejected_without_destroying_flow(self):
        """Comprueba que un binding_token no string se rechaza sin destruir el flujo."""
        flow_data = {"code_verifier": "secret_123", "state": "state_abc"}
        binding = self.store.save_flow("state_abc", flow_data)

        for invalid_binding in [None, 12345, [], {}, True]:
            flow, error = self.store.pop_flow("state_abc", invalid_binding)
            self.assertIsNone(flow)
            self.assertEqual(error, "browser_binding_mismatch")
            self.assertTrue(self.store.has_flow("state_abc"))

        flow_ok, err_ok = self.store.pop_flow("state_abc", binding)
        self.assertEqual(flow_ok, flow_data)
        self.assertIsNone(err_ok)

    def test_flow_expired_is_rejected(self):
        """Comprueba que un flujo cuyo TTL ha vencido es rechazado y eliminado (Req 6)."""
        flow_data = {"code_verifier": "secret_pkce_123", "state": "state_abc"}
        binding = self.store.save_flow("state_abc", flow_data)

        # Esperar a que venza el TTL de 1 segundo
        time.sleep(1.1)

        flow, error = self.store.pop_flow("state_abc", binding)
        self.assertIsNone(flow)
        self.assertEqual(error, "flow_expired")
        self.assertFalse(self.store.has_flow("state_abc"))


class TestFlowStoreRoutesIntegration(unittest.TestCase):
    """Pruebas automatizadas de integración web con respuestas simuladas (mocks) de MSAL y Graph."""

    def setUp(self):
        flow_store.clear()
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        flow_store.clear()

    def test_code_verifier_and_nonce_never_in_cookie(self):
        """Verifica que code_verifier y nonce NUNCA se serializan en la cookie de sesión tras /login."""
        mock_flow = {
            "state": "state_random_123",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?state=state_random_123",
            "code_verifier": "SUPER_SECRET_PKCE_VERIFIER_THAT_MUST_NOT_LEAK",
            "nonce": "SUPER_SECRET_NONCE_VALUE"
        }

        with patch("app.routes.iniciar_login", return_value=mock_flow):
            resp = self.client.get("/login")
            self.assertEqual(resp.status_code, 302)

            # Extraer el valor de la cookie 'session' emitida
            cookie_header = resp.headers.get("Set-Cookie", "")
            self.assertIn("session=", cookie_header)

            # Decodificar el contenido en claro del payload de la cookie de Flask
            cookie_val = [c for c in cookie_header.split(";") if "session=" in c][0].split("session=")[1]
            payload_b64 = cookie_val.split(".")[0]

            padding = "=" * (4 - len(payload_b64) % 4)
            decoded_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
            decoded_text = decoded_bytes.decode("utf-8", errors="ignore")

            # Ni code_verifier ni nonce deben aparecer en el contenido de la cookie
            self.assertNotIn("SUPER_SECRET_PKCE_VERIFIER_THAT_MUST_NOT_LEAK", decoded_text)
            self.assertNotIn("SUPER_SECRET_NONCE_VALUE", decoded_text)
            self.assertNotIn("code_verifier", decoded_text)
            self.assertNotIn("nonce", decoded_text)

            # Solo reside el diccionario de flujos opacos
            self.assertIn("flows", decoded_text)

    def test_valid_callback_same_browser_succeeds(self):
        """Verifica que el flujo completo en el mismo navegador se completa correctamente con mocks."""
        mock_flow = {
            "state": "state_valid_browser",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "code_verifier": "pkce_verifier_val",
            "nonce": "nonce_val"
        }

        with patch("app.routes.iniciar_login", return_value=mock_flow):
            self.client.get("/login")

        with patch("app.routes.obtener_token") as mock_token, \
             patch("app.routes.obtener_perfil") as mock_profile, \
             patch("app.routes.probar_acceso_directorio") as mock_dir:

            mock_token.return_value = {
                "access_token": "valid_token",
                "id_token_claims": {
                    "name": "Antonio Recio",
                    "preferred_username": "arecio@montepinar.com",
                    "oid": "oid-recio",
                    "tid": "tid-montepinar",
                    "iss": "iss-test",
                    "aud": "aud-test",
                    "exp": 1800000000
                }
            }
            mock_profile.return_value = {
                "displayName": "Antonio Recio",
                "userPrincipalName": "arecio@montepinar.com",
                "id": "recio-id"
            }
            mock_dir.return_value = (403, "Authorization_RequestDenied")

            resp = self.client.get("/getAToken?code=auth_code_123&state=state_valid_browser")
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers["Location"], "/")

            portal_resp = self.client.get("/")
            html = portal_resp.get_data(as_text=True)
            self.assertIn("Bienvenido, Antonio Recio", html)
            self.assertIn("Acceso denegado", html)

    def test_callback_different_browser_rejected_and_does_not_destroy_flow(self):
        """Verifica que un callback desde otro navegador se rechaza sin destruir el flujo legítimo."""
        mock_flow = {
            "state": "state_browser_a",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "code_verifier": "pkce_verifier_a",
            "nonce": "nonce_a"
        }

        # Navegador A inicia login legítimo
        with patch("app.routes.iniciar_login", return_value=mock_flow):
            self.client.get("/login")

        # Navegador B intenta consumir el state de A sin tener la cookie de A
        browser_b = self.app.test_client()
        resp_b = browser_b.get("/getAToken?code=stolen_code&state=state_browser_a")
        self.assertEqual(resp_b.status_code, 400)
        self.assertIn("Sesión de autenticación no encontrada", resp_b.get_data(as_text=True))

        # El flujo legítimo de A NO debe haber sido destruido por el intento de B
        self.assertTrue(flow_store.has_flow("state_browser_a"))

    def test_invalid_state_callback_does_not_destroy_legitimate_flow(self):
        """Verifica que un callback con state incorrecto no destruye el flujo legítimo (Req 2)."""
        mock_flow = {
            "state": "state_legitimate",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "code_verifier": "pkce_legit",
            "nonce": "nonce_legit"
        }

        # Iniciar login legítimo
        with patch("app.routes.iniciar_login", return_value=mock_flow):
            self.client.get("/login")

        # Llega una petición con un state manipulado / inexistente
        resp_bad = self.client.get("/getAToken?code=some_code&state=state_manipulated_or_wrong")
        self.assertEqual(resp_bad.status_code, 400)

        # El flujo legítimo NO debe haber sido destruido
        self.assertTrue(flow_store.has_flow("state_legitimate"))

        # El callback legítimo con el state correcto debe procesarse sin problemas
        with patch("app.routes.obtener_token") as mock_token, \
             patch("app.routes.obtener_perfil") as mock_profile, \
             patch("app.routes.probar_acceso_directorio") as mock_dir:

            mock_token.return_value = {
                "access_token": "token_ok",
                "id_token_claims": {"name": "Antonio Recio", "preferred_username": "arecio@montepinar.com"}
            }
            mock_profile.return_value = {"displayName": "Antonio Recio", "id": "1"}
            mock_dir.return_value = (403, "Authorization_RequestDenied")

            resp_ok = self.client.get("/getAToken?code=good_code&state=state_legitimate")
            self.assertEqual(resp_ok.status_code, 302)

        # Ahora sí debe haber quedado consumido
        self.assertFalse(flow_store.has_flow("state_legitimate"))

    def test_multiple_concurrent_flows_same_browser_independent(self):
        """Verifica que dos flujos en el mismo navegador se completan independientemente y no se eliminan (Req 3 y 4)."""
        flow1 = {
            "state": "state_tab_1",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?state=state_tab_1",
            "code_verifier": "verifier_tab_1",
            "nonce": "nonce_tab_1"
        }
        flow2 = {
            "state": "state_tab_2",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?state=state_tab_2",
            "code_verifier": "verifier_tab_2",
            "nonce": "nonce_tab_2"
        }

        # Pestaña 1 inicia login
        with patch("app.routes.iniciar_login", return_value=flow1):
            r1 = self.client.get("/login")
            self.assertEqual(r1.status_code, 302)

        # Pestaña 2 inicia login desde la misma sesión
        with patch("app.routes.iniciar_login", return_value=flow2):
            r2 = self.client.get("/login")
            self.assertEqual(r2.status_code, 302)

        # Ambos flujos deben coexistir en el almacén del servidor
        self.assertTrue(flow_store.has_flow("state_tab_1"))
        self.assertTrue(flow_store.has_flow("state_tab_2"))

        # Completar flujo de la Pestaña 1
        with patch("app.routes.obtener_token") as mock_token, \
             patch("app.routes.obtener_perfil") as mock_profile, \
             patch("app.routes.probar_acceso_directorio") as mock_dir:

            mock_token.return_value = {
                "access_token": "token_tab_1",
                "id_token_claims": {"name": "Antonio Recio", "preferred_username": "arecio@montepinar.com"}
            }
            mock_profile.return_value = {"displayName": "Antonio Recio", "id": "1"}
            mock_dir.return_value = (403, "Authorization_RequestDenied")

            resp_cb1 = self.client.get("/getAToken?code=code_tab_1&state=state_tab_1")
            self.assertEqual(resp_cb1.status_code, 302)

        # Comprobar que Flujo 1 fue consumido, pero Flujo 2 SIGUE ACTIVO en flow_store (Req 4)
        self.assertFalse(flow_store.has_flow("state_tab_1"))
        self.assertTrue(flow_store.has_flow("state_tab_2"))

        # Completar flujo de la Pestaña 2
        with patch("app.routes.obtener_token") as mock_token, \
             patch("app.routes.obtener_perfil") as mock_profile, \
             patch("app.routes.probar_acceso_directorio") as mock_dir:

            mock_token.return_value = {
                "access_token": "token_tab_2",
                "id_token_claims": {"name": "Antonio Recio", "preferred_username": "arecio@montepinar.com"}
            }
            mock_profile.return_value = {"displayName": "Antonio Recio", "id": "1"}
            mock_dir.return_value = (403, "Authorization_RequestDenied")

            resp_cb2 = self.client.get("/getAToken?code=code_tab_2&state=state_tab_2")
            self.assertEqual(resp_cb2.status_code, 302)

        # Ahora ambos flujos han sido completados legítimamente
        self.assertFalse(flow_store.has_flow("state_tab_2"))

    def test_eviction_when_exceeding_ten_flows_discards_from_store(self):
        """Verifica que al superar el límite de 10 flujos se desaloja el más antiguo sin dejar huérfanos."""
        # Simular 10 inicios de sesión en distintas pestañas
        for i in range(1, 11):
            mock_flow = {
                "state": f"state_tab_{i}",
                "redirect_uri": "http://localhost:5000/getAToken",
                "scope": ["User.Read"],
                "auth_uri": f"https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?state=state_tab_{i}",
                "code_verifier": f"verifier_{i}",
                "nonce": f"nonce_{i}"
            }
            with patch("app.routes.iniciar_login", return_value=mock_flow):
                self.client.get("/login")

        # Los 10 flujos deben existir en flow_store
        for i in range(1, 11):
            self.assertTrue(flow_store.has_flow(f"state_tab_{i}"))

        # Iniciar el flujo 11 (debe provocar el desalojo del flujo 1)
        mock_flow_11 = {
            "state": "state_tab_11",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?state=state_tab_11",
            "code_verifier": "verifier_11",
            "nonce": "nonce_11"
        }
        with patch("app.routes.iniciar_login", return_value=mock_flow_11):
            self.client.get("/login")

        # El flujo 1 debe haber sido descartado del servidor (sin huérfanos)
        self.assertFalse(flow_store.has_flow("state_tab_1"))

        # Los flujos del 2 al 11 deben seguir presentes en flow_store
        for i in range(2, 12):
            self.assertTrue(flow_store.has_flow(f"state_tab_{i}"))

        # El flujo 2 debe poder completarse exitosamente
        with patch("app.routes.obtener_token") as mock_token, \
             patch("app.routes.obtener_perfil") as mock_profile, \
             patch("app.routes.probar_acceso_directorio") as mock_dir:

            mock_token.return_value = {
                "access_token": "token_tab_2",
                "id_token_claims": {"name": "Antonio Recio", "preferred_username": "arecio@montepinar.com"}
            }
            mock_profile.return_value = {"displayName": "Antonio Recio", "id": "2"}
            mock_dir.return_value = (403, "Authorization_RequestDenied")

            resp = self.client.get("/getAToken?code=code_tab_2&state=state_tab_2")
            self.assertEqual(resp.status_code, 302)

        self.assertFalse(flow_store.has_flow("state_tab_2"))

    def test_consumed_flow_cannot_be_reused_in_routes(self):
        """Verifica que un flujo válido rechaza cualquier intento de replay (Req 5)."""
        mock_flow = {
            "state": "state_single_use",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "code_verifier": "pkce_verifier_su",
            "nonce": "nonce_su"
        }

        with patch("app.routes.iniciar_login", return_value=mock_flow):
            self.client.get("/login")

        with patch("app.routes.obtener_token") as mock_token, \
             patch("app.routes.obtener_perfil") as mock_profile, \
             patch("app.routes.probar_acceso_directorio") as mock_dir:

            mock_token.return_value = {
                "access_token": "token_1",
                "id_token_claims": {"name": "Antonio Recio", "preferred_username": "arecio@montepinar.com"}
            }
            mock_profile.return_value = {"displayName": "Antonio Recio", "id": "1"}
            mock_dir.return_value = (403, "Authorization_RequestDenied")

            # Primera invocación: éxito
            r1 = self.client.get("/getAToken?code=code_1&state=state_single_use")
            self.assertEqual(r1.status_code, 302)

            # Reintento (replay) con los mismos parámetros: debe ser rechazado
            r2 = self.client.get("/getAToken?code=code_1&state=state_single_use")
            self.assertEqual(r2.status_code, 400)

    def test_expired_flow_rejected(self):
        """Verifica que un flujo expirado en el almacén devuelve HTTP 400 (Req 6)."""
        mock_flow = {
            "state": "state_to_expire",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "code_verifier": "pkce_verifier_exp",
            "nonce": "nonce_exp"
        }

        with patch("app.routes.iniciar_login", return_value=mock_flow):
            self.client.get("/login")

        # Modificar artificialmente la fecha de expiración en el store a una pasada
        with flow_store._lock:
            flow_store._store["state_to_expire"]["expires_at"] = time.time() - 10

        resp = self.client.get("/getAToken?code=code_123&state=state_to_expire")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("ha expirado", resp.get_data(as_text=True))

    def test_auth_error_also_purges_flow(self):
        """Verifica que si MSAL devuelve un error OAuth, se responde HTTP 400 y el flujo queda purgado (H-05 Caso A)."""
        mock_flow = {
            "state": "state_error_test",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "code_verifier": "pkce_verifier_err",
            "nonce": "nonce_err"
        }

        with patch("app.routes.iniciar_login", return_value=mock_flow):
            self.client.get("/login")

        # Comprobar que existe en el store antes del callback
        self.assertTrue(flow_store.has_flow("state_error_test"))

        with patch("app.routes.obtener_token") as mock_token:
            mock_token.return_value = {"error": "invalid_grant", "error_description": "El código expiró"}
            resp = self.client.get("/getAToken?code=bad_code&state=state_error_test")
            self.assertEqual(resp.status_code, 400)
            self.assertIn("Error de autenticación", resp.get_data(as_text=True))
            self.assertIn("El código expiró", resp.get_data(as_text=True))

        # El flujo debe haber desaparecido del almacén y no debe haber sesión autenticada
        self.assertFalse(flow_store.has_flow("state_error_test"))
        with self.client.session_transaction() as sess:
            self.assertNotIn("user", sess)

    def test_missing_access_token_returns_502_and_purges_flow(self):
        """Verifica que si MSAL no devuelve access_token, se responde HTTP 502 y se purga el flujo (H-05 Caso B)."""
        mock_flow = {
            "state": "state_no_at_test",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "code_verifier": "pkce_verifier_no_at",
            "nonce": "nonce_no_at"
        }

        with patch("app.routes.iniciar_login", return_value=mock_flow):
            self.client.get("/login")

        self.assertTrue(flow_store.has_flow("state_no_at_test"))

        with patch("app.routes.obtener_token") as mock_token:
            # Respuesta sin error pero sin access_token
            mock_token.return_value = {
                "id_token_claims": {"name": "Joaquín Arias", "preferred_username": "jarias@montepinar.com"}
            }
            resp = self.client.get("/getAToken?code=valid_code&state=state_no_at_test")
            self.assertEqual(resp.status_code, 502)
            self.assertIn("Error de autorización", resp.get_data(as_text=True))
            self.assertIn("No se obtuvo el access token requerido", resp.get_data(as_text=True))

        # El flujo debe haber quedado purgado y no se debe establecer sesión autenticada
        self.assertFalse(flow_store.has_flow("state_no_at_test"))
        with self.client.session_transaction() as sess:
            self.assertNotIn("user", sess)

    def test_missing_id_token_claims_returns_502_and_purges_flow(self):
        """Verifica que si no se reciben claims OIDC, se responde HTTP 502 y se purga el flujo (H-05 Caso C)."""
        mock_flow = {
            "state": "state_no_claims_test",
            "redirect_uri": "http://localhost:5000/getAToken",
            "scope": ["User.Read"],
            "auth_uri": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "code_verifier": "pkce_verifier_no_claims",
            "nonce": "nonce_no_claims"
        }

        with patch("app.routes.iniciar_login", return_value=mock_flow):
            self.client.get("/login")

        self.assertTrue(flow_store.has_flow("state_no_claims_test"))

        with patch("app.routes.obtener_token") as mock_token, \
             patch("app.routes.obtener_perfil") as mock_profile:
            # Token con access_token pero sin id_token_claims
            mock_token.return_value = {
                "access_token": "valid_access_token_xyz"
            }
            mock_profile.return_value = {
                "displayName": "Joaquín Arias",
                "userPrincipalName": "jarias@montepinar.com",
                "id": "graph-id-123"
            }
            resp = self.client.get("/getAToken?code=valid_code&state=state_no_claims_test")
            self.assertEqual(resp.status_code, 502)
            self.assertIn("Error de identidad", resp.get_data(as_text=True))
            self.assertIn("No se recibieron los datos de identidad", resp.get_data(as_text=True))

        # El flujo debe haber quedado purgado y la sesión NO debe contener usuario
        self.assertFalse(flow_store.has_flow("state_no_claims_test"))
        with self.client.session_transaction() as sess:
            self.assertNotIn("user", sess)


if __name__ == "__main__":
    unittest.main()
