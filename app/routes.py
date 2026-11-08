import logging
from urllib.parse import urlencode
from flask import Blueprint, redirect, render_template, request, session

from app.auth import iniciar_login, obtener_token
from app.config import AUTHORITY, POST_LOGOUT_REDIRECT_URI
from app.flow_store import flow_store
from app.graph import obtener_perfil, probar_acceso_directorio

logger = logging.getLogger(__name__)

main = Blueprint("main", __name__)


@main.route("/")
def index():
    user = session.get("user")
    graph_profile = session.get("graph_profile")
    graph_test_status = session.get("graph_test_status")
    graph_test_error = session.get("graph_test_error")

    return render_template(
        "index.html",
        user=user,
        graph_profile=graph_profile,
        graph_test_status=graph_test_status,
        graph_test_error=graph_test_error
    )


@main.route("/login")
def login():
    logger.info("login_started")
    flow = iniciar_login()
    state = flow.get("state")
    if not state:
        logger.error(
            "login_initialization_failed",
            extra={"error_reason": "missing_state_parameter"}
        )
        return render_template(
            "error.html",
            title="Error de inicio de sesión",
            message="No se pudo inicializar el parámetro de estado de autenticación."
        ), 500

    binding_token = flow_store.save_flow(state, flow)

    # En la cookie de sesión solo guardamos identificadores opacos de vinculación (state -> binding_token).
    # Soporta múltiples flujos concurrentes (e.g. login en varias pestañas).
    # El flujo completo (con code_verifier y nonce) se mantiene protegido en el servidor.
    flows = session.get("flows")
    if not isinstance(flows, dict):
        flows = {}

    # Limitar el número de flujos simultáneos en sesión para evitar saturar el tamaño de la cookie.
    # Desalojar de forma autenticada el flujo más antiguo tanto de la cookie como del almacén
    # en el servidor para evitar que queden entradas huérfanas en memoria.
    if len(flows) >= 10:
        oldest_state = next(iter(flows))
        oldest_binding = flows.get(oldest_state)
        if isinstance(oldest_binding, str):
            flow_store.discard_flow(oldest_state, oldest_binding)
        flows.pop(oldest_state, None)

    flows[state] = binding_token
    session["flows"] = flows

    return redirect(flow["auth_uri"])


@main.route("/getAToken")
def obtener_respuesta():
    state = request.args.get("state")
    flows = session.get("flows")

    # 1. Comprobar que el state recibido existe y está registrado en la sesión del navegador
    if not state or not isinstance(flows, dict) or state not in flows:
        # IMPORTANTE: No tocar ni consumir ningún flujo en flow_store ni en la sesión.
        # Un callback erróneo o manipulado no debe invalidar flujos legítimos.
        logger.warning("callback_state_invalid")
        return render_template(
            "error.html",
            title="Sesión de autenticación no encontrada",
            message="No se encontró un flujo de autenticación activo para este navegador o el estado recibido no es válido."
        ), 400

    binding_token = flows[state]

    # 2. Consumir el flujo del almacén en el servidor usando su binding_token
    flow, error_reason = flow_store.pop_flow(state, binding_token)

    if not flow:
        # Si el flujo expiró o ya fue consumido, retirarlo del registro de la sesión
        if error_reason in ("flow_expired", "flow_not_found_or_already_consumed"):
            flows.pop(state, None)
            session["flows"] = flows

        if error_reason == "flow_expired":
            logger.warning("callback_flow_expired")
            msg = "El tiempo para completar el inicio de sesión ha expirado (límite de 10 minutos). Vuelve al inicio para intentarlo de nuevo."
        elif error_reason == "browser_binding_mismatch":
            logger.warning("callback_binding_mismatch")
            msg = "La respuesta de autenticación no coincide con la sesión del navegador que inició el login."
        else:
            logger.warning("callback_flow_not_found")
            msg = "El flujo de autenticación no existe o ya ha sido utilizado."

        return render_template(
            "error.html",
            title="Error de autenticación",
            message=msg
        ), 400

    # En este punto el flujo ha sido validado y consumido con éxito de flow_store.
    # Retiramos este flujo específico de la sesión
    flows.pop(state, None)
    session["flows"] = flows

    # Procesar intercambio de tokens con MSAL
    result = obtener_token(flow, request.args)

    if not result or "error" in result:
        error_code = result.get("error", "unknown_error") if result else "empty_result"
        logger.warning(
            "authentication_failed",
            extra={"error_code": str(error_code)}
        )
        error_desc = result.get("error_description") if result else None
        return render_template(
            "error.html",
            title="Error de autenticación",
            message="Microsoft Entra ID no ha podido completar el inicio de sesión. Vuelve al portal e inténtalo de nuevo.",
            details=error_desc
        ), 400

    access_token = result.get("access_token")

    if not access_token:
        logger.warning("authorization_token_missing")
        return render_template(
            "error.html",
            title="Error de autorización",
            message="No se obtuvo el access token requerido para consultar Microsoft Graph."
        ), 502

    try:
        perfil = obtener_perfil(access_token)
        logger.info("user_profile_loaded")
    except Exception as e:
        logger.error(
            "user_profile_load_failed",
            extra={"error_type": type(e).__name__}
        )
        return render_template(
            "error.html",
            title="Error al consultar Microsoft Graph",
            message="No ha sido posible recuperar el perfil del usuario. Comprueba los permisos de la aplicación o vuelve a iniciar sesión."
        ), 502

    id_token_claims = result.get("id_token_claims")

    if not id_token_claims:
        logger.warning("id_token_claims_missing")
        return render_template(
            "error.html",
            title="Error de identidad",
            message="No se recibieron los datos de identidad (ID token) del usuario."
        ), 502

    status_code, graph_error = probar_acceso_directorio(access_token)
    if status_code == 403:
        logger.info(
            "directory_access_test_denied",
            extra={"status_code": 403}
        )
    elif status_code == 200:
        logger.info(
            "directory_access_test_permitted",
            extra={"status_code": 200}
        )
    else:
        logger.warning(
            "directory_access_test_status",
            extra={"status_code": status_code}
        )

    # Conservar otros flujos pendientes si existieran en otras pestañas
    remaining_flows = session.get("flows", {})

    # En Flask, las sesiones predeterminadas se almacenan en una cookie firmada en el cliente
    # (mediante HMAC/itsdangerous), sin un identificador de sesión gestionado en el servidor.
    # Purgamos los datos de la sesión anterior antes de establecer la nueva identidad confirmada.
    session.clear()

    # Restaurar otros flujos pendientes si existen para que no se invaliden
    if remaining_flows:
        session["flows"] = remaining_flows

    # Activar la persistencia de sesión para que Flask aplique la duración
    # configurada en PERMANENT_SESSION_LIFETIME (Max-Age / Expires en la cookie).
    session.permanent = True

    # Guardamos únicamente los datos de identidad necesarios para la interfaz.
    session["user"] = {
        "name": id_token_claims.get("name", "Empleado"),
        "preferred_username": id_token_claims.get(
            "preferred_username", "No disponible"
        ),
        "oid": id_token_claims.get("oid"),
        "tid": id_token_claims.get("tid"),
        "iss": id_token_claims.get("iss"),
        "aud": id_token_claims.get("aud"),
        "exp": id_token_claims.get("exp")
    }

    # Guardamos solo los atributos del perfil que muestra el portal.
    session["graph_profile"] = {
        "displayName": perfil.get("displayName"),
        "userPrincipalName": perfil.get("userPrincipalName"),
        "id": perfil.get("id")
    }

    session["graph_test_status"] = status_code
    session["graph_test_error"] = graph_error

    logger.info("authentication_succeeded")
    return redirect("/")


@main.route("/logout", methods=["POST"])
def logout():
    logger.info("user_logout")
    session.clear()

    logout_endpoint = f"{AUTHORITY.rstrip('/')}/oauth2/v2.0/logout"
    params = urlencode({"post_logout_redirect_uri": POST_LOGOUT_REDIRECT_URI})

    return redirect(f"{logout_endpoint}?{params}")
