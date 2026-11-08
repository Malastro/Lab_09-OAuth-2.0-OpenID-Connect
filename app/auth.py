import logging
import msal

from app.config import (
    CLIENT_ID,
    CLIENT_SECRET,
    AUTHORITY,
    REDIRECT_URI
)

logger = logging.getLogger(__name__)

# Crear el cliente de autenticación de Microsoft
msal_app = msal.ConfidentialClientApplication(
    client_id=CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=AUTHORITY
)


def iniciar_login():
    """
    Inicia el proceso de autenticación con Microsoft Entra ID.
    """
    flow = msal_app.initiate_auth_code_flow(
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI
    )

    if "error" in flow:
        error_code = flow.get("error", "unknown_error")
        logger.error(
            "auth_flow_initiation_failed",
            extra={"error_code": str(error_code)}
        )
        raise RuntimeError(
            "No se pudo iniciar el flujo de autenticación."
        )

    logger.info("auth_flow_initiated", extra={"scope": "User.Read"})
    return flow


def obtener_token(flow, request_args):
    """
    Procesa la respuesta de Entra ID y obtiene los tokens.
    """
    try:
        result = msal_app.acquire_token_by_auth_code_flow(
            flow,
            request_args
        )

        if result and "error" in result:
            error_code = result.get("error", "unknown_error")
            logger.warning(
                "token_acquisition_failed",
                extra={"error_code": str(error_code)}
            )
        else:
            logger.info("token_acquisition_succeeded")

        return result

    except ValueError:
        logger.warning(
            "token_acquisition_failed",
            extra={
                "error_code": "invalid_auth_response",
                "error_type": "ValueError"
            }
        )
        return {
            "error": "invalid_auth_response",
            "error_description": (
                "La respuesta de autenticación no es válida "
                "o no ha superado las comprobaciones de seguridad."
            )
        }
