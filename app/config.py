
import ipaddress
import os
import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv


# Localizar la carpeta principal del proyecto
BASE_DIR = Path(__file__).resolve().parent.parent

# Cargar las variables del archivo .env
load_dotenv(BASE_DIR / ".env")


# Comprobar que todas las variables necesarias están configuradas
VARIABLES_REQUERIDAS = [
    "CLIENT_ID",
    "TENANT_ID",
    "CLIENT_SECRET",
    "REDIRECT_URI",
    "FLASK_SECRET_KEY"
]

VARIABLES_FALTANTES = [
    variable
    for variable in VARIABLES_REQUERIDAS
    if not os.getenv(variable)
]

if VARIABLES_FALTANTES:
    raise RuntimeError(
        "Faltan variables de configuración en el archivo .env: "
        + ", ".join(VARIABLES_FALTANTES)
    )


# Expresión regular para validar nombres de dominio (FQDN)
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _is_valid_uuid(val: str) -> bool:
    """Comprueba que el valor sea un UUID válido."""
    try:
        parsed_uuid = uuid.UUID(val)
        return str(parsed_uuid).lower() == val.lower()
    except (ValueError, AttributeError, TypeError):
        return False


def validate_tenant_id(tenant_id: str) -> str:
    """
    Valida que el identificador de tenant sea un UUID estándar
    o un nombre de dominio válido (FQDN).

    Rechaza endpoints genéricos y caracteres que puedan alterar
    la estructura de la URL de autoridad.
    """
    if not tenant_id or not isinstance(tenant_id, str):
        raise ValueError(
            "TENANT_ID debe ser una cadena de texto no vacía."
        )

    # Rechazar caracteres de control, espacios y separadores de URL
    if any(
        c in tenant_id
        for c in (" ", "\t", "\n", "\r", "/", "\\", "?", "#", ":", "@")
    ):
        raise ValueError(
            "TENANT_ID contiene caracteres no permitidos "
            "o separadores de ruta."
        )

    tid_lower = tenant_id.lower()

    # Rechazar endpoints genéricos multi-tenant
    if tid_lower in ("common", "organizations", "consumers"):
        raise ValueError(
            f"El laboratorio requiere un tenant específico "
            f"(single-tenant), no '{tenant_id}'."
        )

    # Validar mediante UUID real o FQDN completo
    if (
        _is_valid_uuid(tenant_id)
        or DOMAIN_REGEX.fullmatch(tenant_id)
    ):
        return tenant_id

    raise ValueError(
        "TENANT_ID debe ser un UUID válido o un nombre "
        "de dominio de tenant."
    )


def _is_valid_ip(host: str) -> bool:
    """Comprueba si el hostname representa una dirección IP válida."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# Patrones y marcadores de posición no permitidos en claves secretas
DISALLOWED_SECRET_PATTERNS = (
    "change-me",
    "replace-me",
    "placeholder",
    "your-secret-key",
    "example-key",
    "genera_tu_propia",
    "secret-key",
)


def validate_flask_secret_key(secret_key: str) -> str:
    """
    Valida la clave secreta de Flask (FLASK_SECRET_KEY).

    Exige:
    - Cadena de texto no vacía.
    - Longitud mínima de 32 caracteres (tras recortar espacios).
    - Rechazo de valores de plantilla, ejemplos o marcadores de posición.
    - Control básico de higiene frente a patrones triviales o repetitivos
      (diversidad mínima de caracteres).

    Nota de diseño:
    La comprobación de diversidad de caracteres (al menos 8 distintos) es solo
    un filtro básico de higiene para descartar cadenas obvias o repetitivas;
    no proporciona ni sustituye una garantía de entropía criptográfica real.
    Las claves deben generarse siempre mediante generadores criptográficamente
    seguros (p. ej., secrets.token_urlsafe(48)).
    """
    if not secret_key or not isinstance(secret_key, str):
        raise ValueError(
            "FLASK_SECRET_KEY debe ser una cadena de texto no vacía."
        )

    trimmed = secret_key.strip()
    if not trimmed:
        raise ValueError(
            "FLASK_SECRET_KEY no puede estar vacía o compuesta únicamente de espacios."
        )

    if len(trimmed) < 32:
        raise ValueError(
            "La variable FLASK_SECRET_KEY debe tener al menos "
            "32 caracteres de longitud."
        )

    lower_key = trimmed.lower()
    for pattern in DISALLOWED_SECRET_PATTERNS:
        if pattern in lower_key:
            raise ValueError(
                "FLASK_SECRET_KEY contiene un valor de plantilla o ejemplo "
                f"no seguro ('{pattern}'). Genere una clave criptográfica real."
            )

    if len(set(trimmed)) < 8:
        raise ValueError(
            "FLASK_SECRET_KEY carece de suficiente diversidad de caracteres "
            "(patrón trivial o repetitivo no permitido)."
        )

    return trimmed


def validate_session_cookie_secure(val: object) -> bool:
    """
    Valida la variable SESSION_COOKIE_SECURE.

    Admite de forma estricta únicamente 'true' o 'false' (insensible a mayúsculas
    y tolerante a espacios en los extremos).
    Cualquier otro valor (como 'treu', 'yes', '1', vacíos o tipos no cadena)
    lanza un ValueError.
    """
    if not isinstance(val, str):
        raise ValueError(
            "SESSION_COOKIE_SECURE debe ser una cadena de texto ('true' o 'false')."
        )

    cleaned = val.strip().lower()
    if cleaned == "true":
        return True
    if cleaned == "false":
        return False

    raise ValueError(
        f"SESSION_COOKIE_SECURE debe ser estrictamente 'true' o 'false' "
        f"(valor recibido: '{val}')."
    )


def validate_permanent_session_lifetime(raw_val: object) -> int:
    """
    Valida la variable PERMANENT_SESSION_LIFETIME_MINUTES.

    Exige un número entero positivo mayor o igual a 1.
    Rechaza tipos booleanos, None, números decimales (float o cadenas flotantes como '1.5')
    y cadenas no numéricas.
    """
    if raw_val is None or isinstance(raw_val, (bool, float)):
        raise ValueError(
            "La variable de configuración PERMANENT_SESSION_LIFETIME_MINUTES "
            f"debe ser un número entero mayor o igual a 1 (valor recibido: '{raw_val}')."
        )

    if isinstance(raw_val, int):
        if raw_val < 1:
            raise ValueError(
                "La variable de configuración PERMANENT_SESSION_LIFETIME_MINUTES "
                f"debe ser un número entero mayor o igual a 1 (valor recibido: {raw_val})."
            )
        return raw_val

    if isinstance(raw_val, str):
        trimmed = raw_val.strip()
        try:
            val = int(trimmed)
            if val < 1:
                raise ValueError
            return val
        except ValueError:
            raise ValueError(
                "La variable de configuración PERMANENT_SESSION_LIFETIME_MINUTES "
                f"debe ser un número entero mayor o igual a 1 (valor recibido: '{raw_val}')."
            )

    raise ValueError(
        "La variable de configuración PERMANENT_SESSION_LIFETIME_MINUTES "
        f"debe ser un número entero mayor o igual a 1 (valor recibido: '{raw_val}')."
    )


def validate_post_logout_redirect_uri(url: str) -> str:
    """
    Valida la URL de redirección posterior al logout.

    HTTP se permite exclusivamente para loopback.
    HTTPS es obligatorio para dominios y direcciones IP externas.
    Se rechazan credenciales, fragmentos y caracteres peligrosos.
    """
    if not url or not isinstance(url, str):
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI debe ser una cadena no vacía."
        )

    # Rechazar espacios, caracteres de control y barras invertidas
    if any(
        c.isspace() or ord(c) < 32 or ord(c) == 127 or c == "\\"
        for c in url
    ):
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI no debe contener espacios, "
            "caracteres de control ni barras invertidas."
        )

    # Rechazar fragmentos
    if "#" in url:
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI no debe contener fragmentos (#)."
        )

    # Analizar la URL
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI contiene una URL malformada."
        ) from exc

    # Permitir exclusivamente HTTP y HTTPS
    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI debe utilizar HTTP o HTTPS."
        )

    # Exigir URL absoluta con hostname
    if not parsed.netloc:
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI debe ser una URL absoluta con host."
        )

    # Rechazar credenciales embebidas
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI no debe contener credenciales."
        )

    # Validar hostname y puerto
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI contiene un hostname "
            "o puerto inválido."
        ) from exc

    if not hostname:
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI carece de un hostname válido."
        )

    hostname = hostname.lower()

    # Validar rango del puerto
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(
            "POST_LOGOUT_REDIRECT_URI contiene un puerto "
            "fuera del rango permitido (1-65535)."
        )

    # HTTP exclusivamente para loopback
    if scheme == "http":
        if hostname not in LOOPBACK_HOSTS:
            raise ValueError(
                "HTTP únicamente se permite para loopback local. "
                "Los destinos externos requieren HTTPS."
            )

    # HTTPS para loopback, dominios o direcciones IP válidas
    else:
        if (
            hostname not in LOOPBACK_HOSTS
            and not (
                DOMAIN_REGEX.fullmatch(hostname)
                or _is_valid_ip(hostname)
            )
        ):
            raise ValueError(
                f"Hostname no válido en POST_LOGOUT_REDIRECT_URI: "
                f"'{hostname}'."
            )

    return url


# Leer y validar la configuración de Microsoft Entra y seguridad Flask
CLIENT_ID = os.getenv("CLIENT_ID")
TENANT_ID = validate_tenant_id(os.getenv("TENANT_ID", ""))
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
FLASK_SECRET_KEY = validate_flask_secret_key(os.getenv("FLASK_SECRET_KEY"))

# Configuración de seguridad para cookies de sesión
SESSION_COOKIE_SECURE = validate_session_cookie_secure(
    os.getenv("SESSION_COOKIE_SECURE", "false")
)

# Duración de sesión en minutos (por defecto: 60)
PERMANENT_SESSION_LIFETIME_MINUTES = validate_permanent_session_lifetime(
    os.getenv("PERMANENT_SESSION_LIFETIME_MINUTES", "60")
)


# Dirección de autenticación de nuestro tenant
# Se construye únicamente después de validar TENANT_ID
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"


# URL de redirección posterior al cierre de sesión
raw_post_logout_uri = os.getenv(
    "POST_LOGOUT_REDIRECT_URI",
    "http://localhost:5000/"
)

POST_LOGOUT_REDIRECT_URI = validate_post_logout_redirect_uri(
    raw_post_logout_uri
)
