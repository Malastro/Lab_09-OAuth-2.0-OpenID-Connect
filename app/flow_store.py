import secrets
import threading
import time
from typing import Any, Dict, Optional, Tuple

# Tiempo de vida de los flujos de autenticación pendientes (10 minutos)
FLOW_TTL_SECONDS = 600


class FlowStore:
    """
    Almacén en memoria sincronizado para flujos de autenticación de MSAL.
    
    Protege los secretos PKCE (code_verifier) y parámetros de repetición (nonce)
    evitando que se almacenen en cookies de cliente firmadas pero no cifradas.
    """

    def __init__(self, ttl_seconds: int = FLOW_TTL_SECONDS):
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("El parámetro ttl_seconds debe ser un número entero positivo.")
        self._ttl_seconds = ttl_seconds
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _purge_expired(self, now: float) -> None:
        """Elimina de forma interna flujos cuya validez temporal haya expirado."""
        expired_keys = [
            key for key, entry in self._store.items()
            if entry["expires_at"] <= now
        ]
        for key in expired_keys:
            del self._store[key]

    def save_flow(self, state: str, flow: Dict[str, Any]) -> str:
        """
        Almacena el flujo completo en memoria y genera un identificador criptográfico
        de vinculación (binding_token) que se entrega a la sesión del navegador.
        """
        binding_token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._purge_expired(now)
            self._store[state] = {
                "flow": flow,
                "binding_token": binding_token,
                "expires_at": now + self._ttl_seconds
            }
        return binding_token

    def pop_flow(
        self, state: str, binding_token: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Recupera y elimina de forma atómica un flujo comprobando su vigencia y su
        vinculación con la sesión del navegador.

        Devuelve una tupla (flow, error_reason):
        - Si es válido y el binding coincide: elimina el flujo del almacén y devuelve (flow, None).
        - Si no existe: (None, "flow_not_found_or_already_consumed").
        - Si está caducado: elimina el flujo expirado y devuelve (None, "flow_expired").
        - Si el binding_token NO coincide o no es una cadena: NO elimina el flujo (para no permitir
          que un atacante destruya un flujo legítimo) y devuelve (None, "browser_binding_mismatch").
        """
        now = time.time()
        with self._lock:
            # Purgar flujos expirados ajenos al estado actual
            expired_keys = [
                key for key, entry in self._store.items()
                if entry["expires_at"] <= now and key != state
            ]
            for key in expired_keys:
                del self._store[key]

            # 1. Comprobar que el flujo existe
            if not state or state not in self._store:
                return None, "flow_not_found_or_already_consumed"

            entry = self._store[state]

            # 2. Comprobar su caducidad
            if entry["expires_at"] <= now:
                del self._store[state]
                return None, "flow_expired"

            # 3. Comprobar que el binding_token es una cadena válida y coincide
            if not isinstance(binding_token, str):
                return None, "browser_binding_mismatch"

            if not secrets.compare_digest(entry["binding_token"], binding_token):
                # Un binding incorrecto NO destruye el flujo legítimo
                return None, "browser_binding_mismatch"

            # 4. Solo cuando el binding es válido y se va a consumir, se elimina el flujo
            del self._store[state]
            return entry["flow"], None

    def discard_flow(self, state: str, binding_token: str) -> bool:
        """
        Descarta de forma segura un flujo del almacén si el binding_token coincide,
        evitando entradas huérfanas cuando una sesión desaloja flujos antiguos.
        Devuelve True si el flujo existía y fue descartado con éxito.
        """
        flow, error = self.pop_flow(state, binding_token)
        return flow is not None

    def has_flow(self, state: str) -> bool:
        """Comprueba de forma sincronizada si un flujo reside en el almacén."""
        with self._lock:
            return state in self._store

    def clear(self) -> None:
        """Vacía todo el almacén. Utilizado para el aislamiento de pruebas unitarias."""
        with self._lock:
            self._store.clear()


# Instancia única del almacén para el ciclo de vida del proceso Flask
flow_store = FlowStore()
