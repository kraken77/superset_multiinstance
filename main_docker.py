"""
Tento modul poskytuje FastAPI aplikaci, která funguje jako Multi-Superset MCP server.

Umožňuje spravovat více Superset instancí prostřednictvím jediného API rozhraní.
Aplikace se stará o autentizaci, správu tokenů a poskytuje proxy přístup
k API jednotlivých Superset serverů.
"""
import httpx
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Path
from pydantic import BaseModel
import os
import json
import uvicorn
import asyncio
import logging
import sys
import base64
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional, Dict, Any, Callable
from urllib.parse import urlparse, urlunparse
from fastapi_mcp import FastApiMCP

# --- Základní nastavení ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

# --- Datové struktury ---
@dataclass
class SupersetServerConfig:
    """
    Dataclass pro konfiguraci jednoho Superset serveru.

    Atributy:
        base_url (Optional[str]): Základní URL adresa Superset instance.
        base_url_env (Optional[str]): Název env proměnné pro base_url.
        auth_method (str): Metoda autentizace ('db' nebo 'keycloak').
        username (Optional[str]): Uživatelské jméno pro 'db' přihlášení.
        password (Optional[str]): Heslo pro 'db' přihlášení.
        provider (Optional[str]): Poskytovatel pro přihlášení (např. 'db', 'oidc').
        token_url (Optional[str]): URL pro získání tokenu (pro Keycloak).
        token_url_env (Optional[str]): Název env proměnné pro token_url.
        client_id_env (Optional[str]): Název env proměnné pro Client ID.
        client_secret_env (Optional[str]): Název env proměnné pro Client Secret.
        keycloak_username_env (Optional[str]): Název env proměnné pro Keycloak username.
        keycloak_password_env (Optional[str]): Název env proměnné pro Keycloak password.
    """
    base_url: Optional[str] = None
    base_url_env: Optional[str] = None
    auth_method: str = "db"
    username: Optional[str] = None
    password: Optional[str] = None
    username_env: Optional[str] = None
    password_env: Optional[str] = None
    provider: Optional[str] = "db"
    token_url: Optional[str] = None
    token_url_env: Optional[str] = None
    client_id_env: Optional[str] = None
    client_secret_env: Optional[str] = None
    keycloak_username_env: Optional[str] = None
    keycloak_password_env: Optional[str] = None
    cookie_file_path: Optional[str] = None
    http_username: Optional[str] = None
    http_password: Optional[str] = None

@dataclass
class SupersetContext:
    """
    Dataclass pro uchování kontextu jednoho Superset serveru.

    Atributy:
        config (SupersetServerConfig): Konfigurace serveru.
        client (httpx.AsyncClient): Asynchronní HTTP klient pro komunikaci se serverem.
            server_id (str): Unikátní identifikátor serveru.
            access_token (Optional[str]): Přístupový token pro API.
            session_cookie (Optional[str]): Session cookie pro 'cookie' auth.
            csrf_token (Optional[str]): CSRF token pro bezpečné požadavky.
            token_path (Optional[str]): Cesta k souboru s uloženým tokenem.    """
    config: SupersetServerConfig
    client: httpx.AsyncClient
    server_id: str
    access_token: Optional[str] = None
    csrf_token: Optional[str] = None
    token_path: Optional[str] = None

# --- Správce spojení ---
class ConnectionManager:
    """
    Správce spojení a kontextů pro všechny nakonfigurované Superset servery.

    Tato třída se stará o:
    - Načítání konfigurace serverů ze souboru.
    - Vytváření a uchovávání kontextů pro každý server.
    - Správu (načítání, ukládání, mazání) autentizačních tokenů.
    - Zavírání spojení při ukončení aplikace.
    """
    def __init__(self, token_dir: str = "."):
        """
        Inicializuje ConnectionManager.

        Args:
            token_dir (str): Adresář pro ukládání souborů s tokeny.
        """
        self._contexts: Dict[str, SupersetContext] = {}
        self._token_dir = token_dir
        os.makedirs(self._token_dir, exist_ok=True)

    def get_token_path(self, server_id: str) -> str:
        """
        Vrátí cestu k souboru s tokenem pro daný server.

        Args:
            server_id (str): ID serveru.

        Returns:
            str: Absolutní cesta k souboru s tokenem.
        """
        return os.path.join(self._token_dir, f".superset_token_{server_id}")

    def load_servers(self, config_path: str = "servers.json"):
        """
        Načte a zpracuje konfiguraci serverů z JSON souboru.

        Pro každý server v konfiguračním souboru vytvoří SupersetContext
        a inicializuje HTTP klienta.

        Args:
            config_path (str): Cesta ke konfiguračnímu JSON souboru.
        """
        logger.info(f"Načítám konfiguraci serverů z {config_path}")
        try:
            with open(config_path, 'r') as f:
                servers_config = json.load(f)

            for server_id, config_data in servers_config.items():
                base_url = None
                base_url_env = config_data.get("base_url_env")
                if base_url_env:
                    base_url = os.getenv(base_url_env)
                    if not base_url:
                        logger.error(f"Env proměnná '{base_url_env}' pro base_url serveru '{server_id}' není nastavena.")
                        sys.exit(1)
                else:
                    base_url = config_data.get("base_url")

                if not base_url:
                    logger.error(f"Pro server '{server_id}' není definován 'base_url' ani 'base_url_env'.")
                    sys.exit(1)
                
                http_username = None
                http_password = None
                auth_method = config_data.get("auth_method")
                if auth_method == 'cookie_http_auth':
                    parsed_url = urlparse(base_url)
                    if parsed_url.username and parsed_url.password:
                        logger.info(f"Nalezena HTTP Basic Auth v URL pro server '{server_id}'.")
                        http_username = parsed_url.username
                        http_password = parsed_url.password
                        # Remove credentials from the URL for clean base_url
                        base_url = urlunparse(parsed_url._replace(netloc=parsed_url.hostname + (f":{parsed_url.port}" if parsed_url.port else "")))

                # Aktualizujeme config_data s načtenou base_url pro konzistentní předání do dataclass
                config_data['base_url'] = base_url
                config_data['http_username'] = http_username
                config_data['http_password'] = http_password

                config = SupersetServerConfig(**config_data)
                client = httpx.AsyncClient(base_url=config.base_url, timeout=30.0)
                token_path = self.get_token_path(server_id)
                self._contexts[server_id] = SupersetContext(config=config, client=client, server_id=server_id, token_path=token_path)
                logger.info(f"Server '{server_id}' nakonfigurován pro URL: {config.base_url}")

        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Chyba při načítání konfigurace: {e}")
            sys.exit(1)

    async def load_tokens_for_all_servers(self):
        logger.info("Načítám uložené tokeny/cookies pro všechny servery...")
        for context in self._contexts.values():
            if context.config.auth_method == 'cookie' or context.config.auth_method == 'cookie_http_auth':
                self.load_cookie(context)
            else:
                self.load_token(context)

    def load_cookie(self, ctx: SupersetContext):
        """Načte session cookie ze souboru."""
        if ctx.config.cookie_file_path and os.path.exists(ctx.config.cookie_file_path):
            try:
                with open(ctx.config.cookie_file_path, 'r') as f:
                    ctx.session_cookie = f.read().strip()
                if ctx.session_cookie:
                    logger.info(f"Cookie pro server '{ctx.server_id}' úspěšně načten.")
                else:
                    logger.warning(f"Soubor s cookie pro '{ctx.server_id}' je prázdný.")
            except IOError as e:
                logger.error(f"Chyba při načítání cookie pro server '{ctx.server_id}': {e}")
        else:
            logger.warning(f"Soubor s cookie '{ctx.config.cookie_file_path}' pro server '{ctx.server_id}' nebyl nalezen.")


    def load_token(self, ctx: SupersetContext):
        """
        Načte access a CSRF token z lokálního souboru pro daný kontext.

        Pokud soubor s tokenem existuje, načte z něj tokeny a nastaví je
        do kontextu a do hlaviček HTTP klienta.

        Args:
            ctx (SupersetContext): Kontext Superset serveru.
        """
        if ctx.token_path and os.path.exists(ctx.token_path):
            try:
                with open(ctx.token_path, 'r') as f:
                    tokens = json.load(f)
                ctx.access_token = tokens.get("access_token")
                ctx.csrf_token = tokens.get("csrf_token")
                if ctx.access_token:
                    ctx.client.headers.update({"Authorization": f"Bearer {ctx.access_token}"})
                    logger.info(f"Token pro server '{ctx.server_id}' úspěšně načten.")
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Chyba při načítání tokenu pro server '{ctx.server_id}': {e}")

    def save_token(self, ctx: SupersetContext):
        """
        Uloží access a CSRF token z kontextu do lokálního souboru.

        Args:
            ctx (SupersetContext): Kontext Superset serveru.
        """
        if ctx.token_path:
            try:
                with open(ctx.token_path, 'w') as f:
                    json.dump({
                        "access_token": ctx.access_token,
                        "csrf_token": ctx.csrf_token
                    }, f)
                logger.info(f"Token pro server '{ctx.server_id}' úspěšně uložen.")
            except IOError as e:
                logger.error(f"Chyba při ukládání tokenu pro server '{ctx.server_id}': {e}")

    def clear_token(self, ctx: SupersetContext):
        ctx.access_token = None
        ctx.csrf_token = None
        ctx.session_cookie = None
        ctx.client.headers.clear()
        if ctx.token_path and os.path.exists(ctx.token_path):
            try:
                os.remove(ctx.token_path)
                logger.info(f"Token soubor pro server '{ctx.server_id}' úspěšně smazán.")
            except OSError as e:
                logger.error(f"Chyba při mazání token souboru pro server '{ctx.server_id}': {e}")

    async def close_all(self):
        """Asynchronně zavře všechny HTTP klienty v kontextech."""
        logger.info("Zavírám všechna spojení...")
        for context in self._contexts.values():
            await context.client.aclose()

    def get_context(self, server_id: str) -> SupersetContext:
        """
        Vrátí kontext pro daný server.

        Args:
            server_id (str): ID Superset serveru.

        Returns:
            SupersetContext: Kontext pro daný server.

        Raises:
            HTTPException: Pokud server s daným ID nebyl nalezen.
        """
        context = self._contexts.get(server_id)
        if not context:
            raise HTTPException(status_code=404, detail=f"Server s ID '{server_id}' nebyl nalezen.")
        return context

connection_manager = ConnectionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Asynchronní správce kontextu pro životní cyklus FastAPI aplikace.

    Při startu aplikace:
    - Načte konfiguraci serverů.
    - Načte uložené tokeny.

    Při ukončení aplikace:
    - Zavře všechna otevřená spojení.

    Args:
        app (FastAPI): Instance FastAPI aplikace.
    """
    connection_manager.load_servers()
    await connection_manager.load_tokens_for_all_servers()
    yield
    await connection_manager.close_all()

app = FastAPI(title="Multi-Superset MCP Server", version="2.0.0", lifespan=lifespan)
api_router = APIRouter()

# --- Závislosti a pomocné funkce ---
def get_server_context(server_id: str = Path(..., title="ID Superset serveru")) -> SupersetContext:
    """
    Závislost (dependency) pro FastAPI, která získá kontext serveru.

    Args:
        server_id (str): ID Superset serveru z URL cesty.

    Returns:
        SupersetContext: Kontext pro požadovaný server.
    """
    return connection_manager.get_context(server_id)

async def make_api_request(
    method: str,
    endpoint: str,
    _superset_context: SupersetContext,
    data: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Univerzální funkce pro provádění API požadavků na Superset server.

    Tato funkce se stará o:
    - Získání CSRF tokenu, pokud je potřeba.
    - Přidání autentizačních a CSRF hlaviček.
    - Automatickou re-autentizaci v případě vypršení platnosti tokenu (HTTP 401).
    - Zpracování chyb a vracení vhodných HTTP výjimek.

    Args:
        method (str): HTTP metoda (get, post, put, delete).
        endpoint (str): Cílový endpoint API (např. '/api/v1/dashboard/').
        _superset_context (SupersetContext): Kontext serveru, na který se požadavek posílá.
        data (Optional[Dict[str, Any]]): Tělo požadavku (pro POST, PUT).
        params (Optional[Dict[str, Any]]): Query parametry požadavku.

    Returns:
        Dict[str, Any]: Odpověď ze Superset API ve formátu JSON.

    Raises:
        HTTPException: V případě chyby při komunikaci s API.
        TypeError: Pokud je předán neplatný kontextový objekt.
    """
    if not isinstance(_superset_context, SupersetContext):
        logger.error(f"Expected SupersetContext, but got {type(_superset_context)}. Value: {_superset_context}")
        raise TypeError("Invalid context object passed to make_api_request.")

    client = _superset_context.client
    config = _superset_context.config

    # Zajištění autentizace před prvním požadavkem
    if not _superset_context.access_token and not _superset_context.session_cookie:
        logger.info(f"Pro server '{_superset_context.server_id}' není aktivní sezení. Pokouším se o autentizaci.")
        await _perform_authentication(_superset_context)

    # Příprava hlaviček
    headers = {}
    headers["User-Agent"] = "curl/7.81.0" # Mimic curl's user agent

    if config.auth_method == 'cookie_http_auth' and config.http_username:
        creds = f"{config.http_username}:{config.http_password}"
        encoded_creds = base64.b64encode(creds.encode()).decode()
        headers["Authorization"] = f"Basic {encoded_creds}"

    if config.auth_method in ['cookie', 'cookie_http_auth']:
        if _superset_context.session_cookie:
            headers["Cookie"] = f"session={_superset_context.session_cookie}"
        else:
            # Pokud ani po autentizaci nemáme cookie, je to chyba
            raise HTTPException(status_code=401, detail="Chybí session cookie pro autentizaci.")
    elif config.auth_method != 'cookie_http_auth': # Pro 'db' a 'keycloak'
        if _superset_context.access_token:
            headers["Authorization"] = f"Bearer {_superset_context.access_token}"
        else:
            raise HTTPException(status_code=401, detail="Chybí access token pro autentizaci.")

    if method.lower() != "get":
        if not _superset_context.csrf_token:
            await get_csrf_token(_superset_context) # CSRF token může být potřeba i pro cookie auth
        if _superset_context.csrf_token:
            headers["X-CSRFToken"] = _superset_context.csrf_token

    # Construct the full URL for logging
    request_url = str(client.base_url) + endpoint
    if params:
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        request_url += f"?{query_string}"

    # Construct curl command for logging
    curl_command = f"curl -i -X {method.upper()} \"{request_url}\""
    for header_name, header_value in headers.items():
        # Mask sensitive info for logging
        if header_name.lower() == "authorization":
            if header_value.lower().startswith("bearer"):
                 curl_command += f" --header \"{header_name}: Bearer [MASKED_TOKEN]\""
            else:
                 curl_command += f" --header \"{header_name}: Basic [MASKED_CREDS]\""
        elif header_name.lower() == "cookie":
            curl_command += f" --header \"{header_name}: session=[MASKED_COOKIE]\""
        else:
            curl_command += f" --header \"{header_name}: {header_value}\""
    
    if data:
        curl_command += f" --data-raw '{json.dumps(data)}'"

    logger.info(f"Executing API request (curl equivalent): {curl_command}")

    try:
        response = await client.request(method, endpoint, json=data, params=params, headers=headers)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401 and config.auth_method not in ['cookie', 'cookie_http_auth']:
            logger.info(f"Chyba 401 na serveru {_superset_context.config.base_url}. Pokouším se o re-autentizaci...")
            await _perform_authentication(_superset_context)
            
            # Opakování požadavku s novými hlavičkami
            new_headers = {}
            if _superset_context.access_token:
                new_headers["Authorization"] = f"Bearer {_superset_context.access_token}"
            if method.lower() != "get" and _superset_context.csrf_token:
                 new_headers["X-CSRFToken"] = _superset_context.csrf_token
            
            response = await client.request(method, endpoint, json=data, params=params, headers=new_headers)
            response.raise_for_status()
            return response.json()
        elif e.response.status_code == 401 and config.auth_method in ['cookie', 'cookie_http_auth']:
             logger.error(f"Chyba 401 při cookie autentizaci. Cookie je pravděpodobně neplatná nebo vypršela. Soubor: '{config.cookie_file_path}'")
             raise HTTPException(status_code=401, detail=f"Cookie autentizace selhala. Zkontrolujte platnost cookie v souboru '{config.cookie_file_path}'.")
        
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text) from e
    except Exception as e:
        logger.error(f"Neočekávaná chyba v API požadavku: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def _perform_authentication(ctx: SupersetContext):
    """
    Provede autentizaci na základě metody definované v konfiguraci serveru.

    Args:
        ctx (SupersetContext): Kontext serveru.
    """
    logger.info(f"Provádím autentizaci pro server '{ctx.server_id}' metodou '{ctx.config.auth_method}'")
    if ctx.config.auth_method == "keycloak":
        await _perform_keycloak_authentication(ctx)
    elif ctx.config.auth_method == "db":
        await _perform_db_authentication(ctx)
    elif ctx.config.auth_method in ["cookie", "cookie_http_auth"]:
        await _perform_cookie_authentication(ctx)
    else:
        logger.error(f"Neznámá metoda autentizace: {ctx.config.auth_method}")
        raise HTTPException(status_code=500, detail=f"Neznámá metoda autentizace: {ctx.config.auth_method}")

async def _perform_cookie_authentication(ctx: SupersetContext):
    """
    Načte session cookie ze souboru a ověří jeho platnost.
    """
    logger.info(f"Pokouším se o 'cookie' autentizaci pro server '{ctx.server_id}'")
    config = ctx.config
    if not config.cookie_file_path:
        raise HTTPException(status_code=500, detail=f"Chybí 'cookie_file_path' v konfiguraci pro server '{ctx.server_id}'")
    
    if not os.path.exists(config.cookie_file_path):
        raise HTTPException(status_code=500, detail=f"Soubor s cookie '{config.cookie_file_path}' nebyl nalezen.")

    try:
        with open(config.cookie_file_path, 'r') as f:
            session_cookie = f.read().strip()
        if not session_cookie:
            raise HTTPException(status_code=500, detail=f"Soubor s cookie '{config.cookie_file_path}' je prázdný.")
        
        ctx.session_cookie = session_cookie
        # Po načtení cookie je potřeba získat CSRF token pro další operace
        await get_csrf_token(ctx)
        logger.info(f"Úspěšně načten cookie a CSRF token pro server '{ctx.server_id}'.")

    except IOError as e:
        raise HTTPException(status_code=500, detail=f"Chyba při čtení souboru s cookie: {e}")


async def _perform_db_authentication(ctx: SupersetContext):
    """
    Provede autentizaci proti Superset API pomocí jména a hesla a uloží tokeny.

    Args:
        ctx (SupersetContext): Kontext serveru, ke kterému se přihlašuje.

    Raises:
        HTTPException: Pokud se přihlášení nepodaří.
    """
    logger.info(f"Pokouším se o 'db' přihlášení pro server '{ctx.server_id}'")
    if not ctx.config.username or not ctx.config.password:
        raise HTTPException(status_code=500, detail=f"Chybí username nebo password pro 'db' authentizaci na serveru '{ctx.server_id}'")

    try:
        response = await ctx.client.post("/api/v1/security/login", json={
            "username": ctx.config.username,
            "password": ctx.config.password,
            "provider": ctx.config.provider or "db",
            "refresh": True
        })
        response.raise_for_status()
        data = response.json()
        ctx.access_token = data.get("access_token")
        ctx.client.headers.update({"Authorization": f"Bearer {ctx.access_token}"})
        await get_csrf_token(ctx) # Tím se získá i CSRF
        connection_manager.save_token(ctx)
        logger.info(f"Úspěšně přihlášen k serveru '{ctx.config.base_url}' pomocí 'db'.")
    except httpx.HTTPStatusError as e:
        logger.error(f"Chyba při 'db' přihlášení k serveru '{ctx.server_id}': {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text) from e

async def _perform_keycloak_authentication(ctx: SupersetContext):
    """
    Provede autentizaci proti Keycloak a získá access token.

    Args:
        ctx (SupersetContext): Kontext serveru.

    Raises:
        HTTPException: Pokud se získání tokenu nepodaří.
    """
    logger.info(f"Pokouším se o 'keycloak' přihlášení pro server '{ctx.server_id}'")
    config = ctx.config
    required_envs = {
        'username': config.keycloak_username_env,
        'password': config.keycloak_password_env,
        'client_id': config.client_id_env,
        'client_secret': config.client_secret_env
    }
    creds = {}
    for key, env_var in required_envs.items():
        if not env_var:
            raise HTTPException(status_code=500, detail=f"Chybí env proměnná pro '{key}' v konfiguraci serveru '{ctx.server_id}'")
        value = os.getenv(env_var)
        if not value:
            raise HTTPException(status_code=500, detail=f"Nenalezena env proměnná '{env_var}' pro '{key}'")
        creds[key] = value

    token_url = None
    if config.token_url_env:
        token_url = os.getenv(config.token_url_env)
        if not token_url:
            raise HTTPException(status_code=500, detail=f"Env proměnná '{config.token_url_env}' pro token_url serveru '{ctx.server_id}' není nastavena.")
    else:
        token_url = config.token_url

    if not token_url:
        raise HTTPException(status_code=500, detail=f"Pro server '{ctx.server_id}' není definován 'token_url' ani 'token_url_env'.")

    payload = {
        "grant_type": "password",
        "client_id": creds['client_id'],
        "client_secret": creds['client_secret'],
        "username": creds['username'],
        "password": creds['password'],
        "scope": "openid offline_access",
    }

    logger.info(f"Získávám token z Keycloak na URL: {token_url}")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=payload)
            response.raise_for_status()
            token_data = response.json()

        access_token = token_data.get("access_token")
        if not access_token:
            logger.error("V odpovědi od Keycloak serveru nebyl nalezen access_token.")
            raise HTTPException(status_code=500, detail="V odpovědi od Keycloak serveru nebyl nalezen access_token.")

        logger.info("Úspěšně získán token z Keycloak.")
        ctx.access_token = access_token
        ctx.client.headers.update({"Authorization": f"Bearer {ctx.access_token}"})

        # Po získání tokenu z Keycloak je stále potřeba získat CSRF token od Supersetu
        await get_csrf_token(ctx)
        connection_manager.save_token(ctx)
        logger.info(f"Úspěšně nastaven Keycloak token a CSRF token pro server '{ctx.server_id}'.")

    except httpx.HTTPStatusError as err:
        logger.error(f"HTTP Chyba při komunikaci s Keycloak: {err.response.text}")
        raise HTTPException(status_code=err.response.status_code, detail=f"Keycloak HTTP Chyba: {err.response.text}") from err
    except httpx.RequestError as err:
        logger.error(f"Chyba při spojení s Keycloak: {err}")
        raise HTTPException(status_code=503, detail=f"Chyba při spojení s Keycloak: {err}") from err

async def get_csrf_token(ctx: SupersetContext):
    """
    Získá a uloží CSRF token ze Superset API. Používá správnou autentizační metodu.
    """
    headers = {}
    if ctx.config.auth_method in ['cookie', 'cookie_http_auth']:
        if ctx.config.http_username:
            creds = f"{ctx.config.http_username}:{ctx.config.http_password}"
            encoded_creds = base64.b64encode(creds.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_creds}"
        if ctx.session_cookie:
            headers['Cookie'] = f'session={ctx.session_cookie}'
    elif ctx.access_token:
        headers['Authorization'] = f'Bearer {ctx.access_token}'
    # Pokud nemáme ani jedno, zkusíme to bez auth, což může fungovat pro veřejné endpointy,
    # ale pro csrf_token to pravděpodobně selže, pokud není sezení již aktivní.

    try:
        # Vytvoříme dočasného klienta pro tento požadavek, abychom neovlivnili globální hlavičky
        async with httpx.AsyncClient(base_url=ctx.config.base_url) as client:
            response = await client.get("/api/v1/security/csrf_token/", headers=headers)
            response.raise_for_status()
            data = response.json()
            ctx.csrf_token = data.get("result")
            if ctx.csrf_token:
                logger.info(f"Úspěšně získán CSRF token pro server '{ctx.server_id}'.")
            else:
                logger.warning(f"Nepodařilo se získat CSRF token pro '{ctx.server_id}', odpověď neobsahovala 'result'.")
    except Exception as e:
        logger.error(f"Nepodařilo se získat CSRF token pro {ctx.config.base_url}: {e}")

# --- API Endpoints ---

@api_router.post("/{server_id}/auth/login", summary="Authenticate with a Superset instance", operation_id="superset_auth_authenticate_user")
async def superset_auth_authenticate_user(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
    """Přihlásí uživatele k dané instanci Supersetu."""
    await _perform_authentication(ctx)
    return {"message": f"Úspěšně přihlášen k serveru '{ctx.config.base_url}'."}

@api_router.post("/{server_id}/auth/logout", summary="Log out from a Superset instance", operation_id="superset_auth_logout")
async def superset_auth_logout(server_id: str, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
    """Odhlásí uživatele z dané instance Supersetu a smaže lokální token."""
    connection_manager.clear_token(ctx)
    return {"message": f"Úspěšně odhlášen ze serveru '{server_id}'."}


# --- Dynamically created endpoints ---
def create_dynamic_endpoints():
    """Dynamicky vytváří a registruje všechny API endpointy pro APIRouter."""
    # Autentizační nástroje
    @api_router.get("/{server_id}/auth/check", summary="Check token validity", operation_id="superset_auth_check_token_validity")
    async def superset_auth_check_token_validity(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Zkontroluje platnost aktuálního access tokenu provedením testovacího API volání."""
        if not ctx.access_token:
            return {"valid": False, "error": "Chybí lokální access token."}
        try:
            # Použijeme endpoint, který vyžaduje autentizaci
            await make_api_request("get", "/api/v1/me/", ctx)
            return {"valid": True}
        except HTTPException as e:
            return {"valid": False, "status_code": e.status_code, "error": e.detail}

    @api_router.post("/{server_id}/auth/refresh", summary="Refresh access token", operation_id="superset_auth_refresh_token")
    async def superset_auth_refresh_token(server_id: str, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Obnoví access token pomocí refresh tokenu."""
        try:
            response = await ctx.client.post("/api/v1/security/refresh")
            response.raise_for_status()
            data = response.json()
            ctx.access_token = data.get("access_token")
            ctx.client.headers.update({"Authorization": f"Bearer {ctx.access_token}"})
            connection_manager.save_token(ctx)
            return {"message": "Token úspěšně obnoven.", "access_token": ctx.access_token}
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text) from e

    # Dashboard Tools
    @api_router.get("/{server_id}/dashboards", summary="List dashboards", operation_id="superset_dashboard_list")
    async def superset_dashboard_list(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá seznam všech dashboardů."""
        return await make_api_request("get", "/api/v1/dashboard/", ctx)

    @api_router.get("/{server_id}/dashboards/{dashboard_id}", summary="Get dashboard by ID", operation_id="superset_dashboard_get_by_id")
    async def superset_dashboard_get_by_id(dashboard_id: int, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá detaily konkrétního dashboardu podle jeho ID."""
        return await make_api_request("get", f"/api/v1/dashboard/{dashboard_id}", ctx)

    class DashboardCreate(BaseModel):
        dashboard_title: str
        json_metadata: Optional[Dict[str, Any]] = None

    @api_router.post("/{server_id}/dashboards", summary="Create a dashboard", operation_id="superset_dashboard_create")
    async def superset_dashboard_create(payload: DashboardCreate, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Vytvoří nový dashboard."""
        return await make_api_request("post", "/api/v1/dashboard/", ctx, data=payload.model_dump())

    @api_router.put("/{server_id}/dashboards/{dashboard_id}", summary="Update a dashboard", operation_id="superset_dashboard_update")
    async def superset_dashboard_update(dashboard_id: int, payload: Dict[str, Any], ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Aktualizuje existující dashboard."""
        return await make_api_request("put", f"/api/v1/dashboard/{dashboard_id}", ctx, data=payload)

    @api_router.delete("/{server_id}/dashboards/{dashboard_id}", summary="Delete a dashboard", operation_id="superset_dashboard_delete")
    async def superset_dashboard_delete(dashboard_id: int, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Smaže dashboard podle jeho ID."""
        response = await make_api_request("delete", f"/api/v1/dashboard/{dashboard_id}", ctx)
        if not response.get("error"):
            return {"message": f"Dashboard {dashboard_id} smazán úspěšně."}
        return response

    # Chart Tools
    @api_router.get("/{server_id}/charts", summary="List charts", operation_id="superset_chart_list")
    async def superset_chart_list(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá seznam všech grafů."""
        return await make_api_request("get", "/api/v1/chart/", ctx)

    @api_router.get("/{server_id}/charts/{chart_id}", summary="Get chart by ID", operation_id="superset_chart_get_by_id")
    async def superset_chart_get_by_id(chart_id: int, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá detaily konkrétního grafu podle jeho ID."""
        return await make_api_request("get", f"/api/v1/chart/{chart_id}", ctx)

    class ChartCreate(BaseModel):
        slice_name: str
        datasource_id: int
        datasource_type: str
        viz_type: str
        params: Dict[str, Any]

    @api_router.post("/{server_id}/charts", summary="Create a chart", operation_id="superset_chart_create")
    async def superset_chart_create(payload: ChartCreate, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Vytvoří nový graf."""
        return await make_api_request("post", "/api/v1/chart/", ctx, data=payload.model_dump())

    @api_router.put("/{server_id}/charts/{chart_id}", summary="Update a chart", operation_id="superset_chart_update")
    async def superset_chart_update(chart_id: int, payload: Dict[str, Any], ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Aktualizuje existující graf."""
        return await make_api_request("put", f"/api/v1/chart/{chart_id}", ctx, data=payload)

    @api_router.delete("/{server_id}/charts/{chart_id}", summary="Delete a chart", operation_id="superset_chart_delete")
    async def superset_chart_delete(chart_id: int, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Smaže graf podle jeho ID."""
        response = await make_api_request("delete", f"/api/v1/chart/{chart_id}", ctx)
        if not response.get("error"):
            return {"message": f"Graf {chart_id} smazán úspěšně."}
        return response

    # Database Tools
    class DatabaseCreate(BaseModel):
        engine: str
        configuration_method: str
        database_name: str
        sqlalchemy_uri: str

    class ValidateSQL(BaseModel):
        sql: str

    @api_router.get("/{server_id}/databases", summary="List databases", operation_id="superset_database_list")
    async def superset_database_list(server_id: str = Path(..., title="ID Superset serveru")) -> Dict:
        """Získá seznam všech databázových připojení."""
        # Get the SupersetContext directly from the connection_manager
        superset_ctx = connection_manager.get_context(server_id)
        if not superset_ctx:
            raise HTTPException(status_code=404, detail=f"Server with ID '{server_id}' not found.")

        logger.info(f"Type of superset_ctx in superset_database_list (direct access): {type(superset_ctx)}")
        logger.info(f"Type of superset_ctx.client in superset_database_list (direct access): {type(superset_ctx.client)}")

        query_params_for_q = {
            "page_size": 1000,
            "page": 0
        }
        q_param_value = json.dumps(query_params_for_q)
        params = {"q": q_param_value}

        logger.info(f"Making API request for databases with params: {params}")
        return await make_api_request("get", "/api/v1/database/", superset_ctx, params=params)

    @api_router.get("/{server_id}/databases/{database_id}", summary="Get database by ID", operation_id="superset_database_get_by_id")
    async def superset_database_get_by_id(database_id: int, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá detaily konkrétního databázového připojení podle jeho ID."""
        return await make_api_request("get", f"/api/v1/database/{database_id}", ctx)

    @api_router.post("/{server_id}/databases", summary="Create a database connection", operation_id="superset_database_create")
    async def superset_database_create(payload: DatabaseCreate, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Vytvoří nové databázové připojení."""
        return await make_api_request("post", "/api/v1/database/", ctx, data=payload.model_dump())

    @api_router.get("/{server_id}/databases/{database_id}/tables", summary="Get database tables", operation_id="superset_database_get_tables")
    async def superset_database_get_tables(database_id: int, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá seznam tabulek v konkrétní databázi."""
        return await make_api_request("get", f"/api/v1/database/{database_id}/tables/", ctx)

    @api_router.get("/{server_id}/databases/{database_id}/schemas", summary="Get database schemas", operation_id="superset_database_schemas")
    async def superset_database_schemas(database_id: int, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá seznam schémat v konkrétní databázi."""
        return await make_api_request("get", f"/api/v1/database/{database_id}/schemas/", ctx)

    @api_router.post("/{server_id}/databases/test_connection", summary="Test a database connection", operation_id="superset_database_test_connection")
    async def superset_database_test_connection(payload: Dict[str, Any], ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Otestuje zadané databázové připojení."""
        return await make_api_request("post", "/api/v1/database/test_connection", ctx, data=payload)

    @api_router.put("/{server_id}/databases/{database_id}", summary="Update a database connection", operation_id="superset_database_update")
    async def superset_database_update(database_id: int, payload: Dict[str, Any], ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Aktualizuje existující databázové připojení."""
        return await make_api_request("put", f"/api/v1/database/{database_id}", ctx, data=payload)

    @api_router.delete("/{server_id}/databases/{database_id}", summary="Delete a database connection", operation_id="superset_database_delete")
    async def superset_database_delete(database_id: int, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Smaže databázové připojení podle jeho ID."""
        response = await make_api_request("delete", f"/api/v1/database/{database_id}", ctx)
        if not response.get("error"):
            return {"message": f"Databáze {database_id} smazána úspěšně."}
        return response

    @api_router.post("/{server_id}/databases/{database_id}/validate_sql", summary="Validate SQL", operation_id="superset_database_validate_sql")
    async def superset_database_validate_sql(database_id: int, payload: ValidateSQL, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Zvaliduje SQL dotaz v kontextu konkrétní databáze."""
        return await make_api_request("post", f"/api/v1/database/{database_id}/validate_sql/", ctx, data=payload.model_dump())

    # Dataset Tools
    class DatasetCreate(BaseModel):
        database: int
        table_name: str
        schema: Optional[str] = None

    @api_router.get("/{server_id}/datasets", summary="List datasets", operation_id="superset_dataset_list")
    async def superset_dataset_list(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá seznam všech datasetů."""
        return await make_api_request("get", "/api/v1/dataset/", ctx)

    @api_router.get("/{server_id}/datasets/{dataset_id}", summary="Get dataset by ID", operation_id="superset_dataset_get_by_id")
    async def superset_dataset_get_by_id(dataset_id: int, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá detaily konkrétního datasetu podle jeho ID."""
        return await make_api_request("get", f"/api/v1/dataset/{dataset_id}", ctx)

    @api_router.post("/{server_id}/datasets", summary="Create a dataset", operation_id="superset_dataset_create")
    async def superset_dataset_create(payload: DatasetCreate, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Vytvoří nový dataset."""
        return await make_api_request("post", "/api/v1/dataset/", ctx, data=payload.model_dump())

    # SQL Lab Tools
    class ExecuteSQL(BaseModel):
        database_id: int
        sql: str

    class FormatSQL(BaseModel):
        sql: str

    @api_router.post("/{server_id}/sqllab/execute", summary="Execute SQL query", operation_id="superset_sqllab_execute_query")
    async def superset_sqllab_execute_query(payload: ExecuteSQL, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Spustí SQL dotaz v SQL Labu a vrátí klíč pro sledování výsledků."""
        return await make_api_request("post", "/api/v1/sqllab/execute/", ctx, data=payload.model_dump())

    @api_router.get("/{server_id}/sqllab/saved_queries", summary="Get saved queries", operation_id="superset_sqllab_get_saved_queries")
    async def superset_sqllab_get_saved_queries(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá seznam uložených dotazů v SQL Labu."""
        return await make_api_request("get", "/api/v1/saved_query/", ctx)

    @api_router.post("/{server_id}/sqllab/format_sql", summary="Format SQL query", operation_id="superset_sqllab_format_sql")
    async def superset_sqllab_format_sql(payload: FormatSQL, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Zformátuje SQL dotaz podle standardů."""
        return await make_api_request("post", "/api/v1/sqllab/format_sql", ctx, data=payload.model_dump())

    @api_router.get("/{server_id}/sqllab/results/{key}", summary="Get query results", operation_id="superset_sqllab_get_results")
    async def superset_sqllab_get_results(key: str, ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá výsledky spuštěného SQL dotazu pomocí jeho klíče."""
        return await make_api_request("get", f"/api/v1/sqllab/results/", ctx, params={"key": key})

    # Ostatní nástroje
    @api_router.get("/{server_id}/activity/recent", summary="Get recent activity", operation_id="superset_activity_get_recent")
    async def superset_activity_get_recent(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá seznam nedávné aktivity na serveru."""
        return await make_api_request("get", "/api/v1/log/recent_activity/", ctx)

    @api_router.get("/{server_id}/user/current", summary="Get current user", operation_id="superset_user_get_current")
    async def superset_user_get_current(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá informace o aktuálně přihlášeném uživateli."""
        return await make_api_request("get", "/api/v1/me/", ctx)

    @api_router.get("/{server_id}/user/roles", summary="Get user roles", operation_id="superset_user_get_roles")
    async def superset_user_get_roles(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá role aktuálně přihlášeného uživatele."""
        return await make_api_request("get", "/api/v1/me/roles/", ctx)

    @api_router.get("/{server_id}/tags", summary="List tags", operation_id="superset_tag_list")
    async def superset_tag_list(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Získá seznam všech dostupných tagů."""
        return await make_api_request("get", "/api/v1/tag/", ctx)

    @api_router.get("/{server_id}/config/base_url", summary="Get base URL", operation_id="superset_config_get_base_url")
    async def superset_config_get_base_url(ctx: SupersetContext = Depends(get_server_context)) -> Dict:
        """Vrátí základní URL adresu nakonfigurovaného serveru."""
        return {"base_url": ctx.config.base_url}

    @api_router.get("/config/server_info", summary="Get information about configured Superset servers", operation_id="superset_config_get_server_info")
    async def superset_config_get_server_info() -> Dict:
        """Vrátí informace o všech nakonfigurovaných Superset serverech."""
        servers_info = []
        for server_id, context in connection_manager._contexts.items():
            servers_info.append({"id": server_id, "base_url": context.config.base_url})
        return {"server_count": len(servers_info), "servers": servers_info}

create_dynamic_endpoints()
app.include_router(api_router)
mcp_server = FastApiMCP(app)
mcp_server.mount(app)

@app.get("/")
async def root():
    """Kořenový endpoint, který vrací uvítací zprávu."""
    return {"message": "Multi-Superset MCP Server je spuštěn."}

if __name__ == "__main__":
    uvicorn.run("main_docker:app", host="0.0.0.0", port=8900, reload=True)
