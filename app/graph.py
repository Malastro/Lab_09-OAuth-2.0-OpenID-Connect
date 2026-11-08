import logging
import requests

logger = logging.getLogger(__name__)

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


def _obtener_headers(access_token):
    """
    Construye las cabeceras de autorización para Microsoft Graph.
    """
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }


def obtener_perfil(access_token):
    """
    Consulta el perfil del usuario autenticado mediante Microsoft Graph.
    """
    try:
        response = requests.get(
            f"{GRAPH_BASE_URL}/me",
            headers=_obtener_headers(access_token),
            timeout=10
        )
        response.raise_for_status()

        logger.info(
            "graph_profile_retrieved",
            extra={"endpoint": "/me", "status_code": response.status_code}
        )
        return response.json()

    except requests.exceptions.Timeout:
        logger.error(
            "graph_profile_failed",
            extra={"endpoint": "/me", "error_type": "Timeout"}
        )
        raise

    except requests.exceptions.ConnectionError:
        logger.error(
            "graph_profile_failed",
            extra={"endpoint": "/me", "error_type": "ConnectionError"}
        )
        raise

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else None
        logger.error(
            "graph_profile_failed",
            extra={
                "endpoint": "/me",
                "error_type": "HTTPError",
                "status_code": status_code
            }
        )
        raise

    except requests.exceptions.RequestException as e:
        logger.error(
            "graph_profile_failed",
            extra={"endpoint": "/me", "error_type": type(e).__name__}
        )
        raise


def probar_acceso_directorio(access_token):
    """
    Comprueba si el usuario puede consultar el directorio de Entra ID.

    Devuelve el código HTTP y el mensaje de error, si existe.
    """
    try:
        response = requests.get(
            f"{GRAPH_BASE_URL}/users",
            headers=_obtener_headers(access_token),
            timeout=10
        )

        error_message = None

        if not response.ok:
            try:
                error_message = response.json().get("error", {}).get(
                    "message", "Error no especificado"
                )
            except ValueError:
                error_message = "No se pudo interpretar la respuesta de Graph."

        # El HTTP 403 es el resultado intencionado y esperado de este laboratorio (Least Privilege).
        # Se registra con nivel INFO y nunca como ERROR.
        if response.status_code == 403:
            logger.info(
                "graph_directory_access_denied",
                extra={
                    "endpoint": "/users",
                    "status_code": 403,
                    "reason": "insufficient_permissions_expected"
                }
            )
        elif response.status_code == 200:
            logger.info(
                "graph_directory_access_permitted",
                extra={"endpoint": "/users", "status_code": 200}
            )
        else:
            logger.warning(
                "graph_directory_access_unexpected_status",
                extra={"endpoint": "/users", "status_code": response.status_code}
            )

        return response.status_code, error_message

    except requests.exceptions.Timeout:
        logger.warning(
            "graph_directory_request_failed",
            extra={"endpoint": "/users", "error_type": "Timeout"}
        )
        return None, "Tiempo de espera agotado al consultar Microsoft Graph."

    except requests.exceptions.ConnectionError:
        logger.warning(
            "graph_directory_request_failed",
            extra={"endpoint": "/users", "error_type": "ConnectionError"}
        )
        return None, "No se pudo establecer conexión con Microsoft Graph."

    except requests.exceptions.RequestException as e:
        logger.warning(
            "graph_directory_request_failed",
            extra={"endpoint": "/users", "error_type": type(e).__name__}
        )
        return None, "Se produjo un error al realizar la petición a Microsoft Graph."
