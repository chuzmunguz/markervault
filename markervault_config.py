import ipaddress
import math
import os
import re
import secrets

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class BackendConfiguration:
    environment: str
    database_path: str
    photos_path: str
    thumbs_path: str
    avatars_path: str
    temp_path: str
    access_token_secret: str
    access_token_secret_is_ephemeral: bool
    access_token_duration: int
    refresh_token_duration: int
    bind_token_to_ip: bool
    cookie_secure: bool
    trusted_proxies: tuple[str, ...]
    allowed_ip_ranges: tuple[str, ...]
    canonical_hosts: tuple[str, ...]
    temporary_lan_hosts: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    max_content_length: int
    max_kml_photo_bytes: int
    max_image_dimension: int
    max_image_pixels: int
    kml_max_workers: int
    kml_jobs_per_user: int
    kml_jobs_global: int
    kml_max_bytes: int
    kml_max_elements: int
    kml_max_depth: int
    kml_max_placemarks: int
    kml_max_photos_per_spot: int
    kml_max_download_bytes: int
    kml_max_fetch_attempts: int
    kml_max_job_seconds: int
    notif_history_cap: int
    private_refill_interval: float
    auth_refill_interval: float
    public_refill_interval: float
    rate_burst: int
    private_rate_burst: int
    email_delivery_enabled: bool
    require_email_verification: bool
    public_origin: str | None
    email_verification_token_duration: int
    password_reset_token_duration: int
    email_resend_cooldown: int
    smtp_host: str | None
    smtp_port: int
    smtp_timeout: float
    smtp_security: str
    smtp_from_address: str | None
    smtp_envelope_from: str | None
    smtp_username: str | None = field(repr=False)
    smtp_password: str | None = field(repr=False)
    smtp_allow_unauthenticated_local: bool


def _value(
    environ: Mapping[str, str],
    name: str,
    default: str | None = None,
) -> str | None:
    if name not in environ:
        return default
    value = environ[name]
    value = value.strip()
    if not value:
        raise ConfigurationError(f"{name} must not be empty")
    return value


def _choice(
    environ: Mapping[str, str],
    name: str,
    default: str,
    choices: tuple[str, ...],
) -> str:
    value = _value(environ, name, default)
    if value not in choices:
        allowed = ", ".join(sorted(choices))
        raise ConfigurationError(f"{name} must be one of: {allowed}")
    return value


def _boolean(environ: Mapping[str, str], name: str, default: bool) -> bool:
    value = _value(environ, name)
    if value is None:
        return default
    normalized = value.lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ConfigurationError(f"{name} must be a boolean (true/false)")


def _integer(
    environ: Mapping[str, str],
    name: str,
    default: int,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    value = _value(environ, name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if parsed < minimum:
        raise ConfigurationError(f"{name} must be at least {minimum}")
    if maximum is not None and parsed > maximum:
        raise ConfigurationError(f"{name} must be at most {maximum}")
    return parsed


def _number(
    environ: Mapping[str, str],
    name: str,
    default: float,
    minimum: float = 0,
) -> float:
    value = _value(environ, name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if not math.isfinite(parsed) or parsed <= minimum:
        raise ConfigurationError(f"{name} must be greater than {minimum}")
    return parsed


def _path(environ: Mapping[str, str], name: str, default: str) -> str:
    value = _value(environ, name, default)
    if "\x00" in value:
        raise ConfigurationError(f"{name} must not contain a NUL byte")
    return value


def _secret_value(environ: Mapping[str, str], name: str) -> str | None:
    if name not in environ:
        return None
    value = environ[name]
    if not value or not value.strip():
        raise ConfigurationError(f"{name} must not be empty")
    if "\x00" in value:
        raise ConfigurationError(f"{name} must not contain a NUL byte")
    return value


def _email_address(
    environ: Mapping[str, str],
    name: str,
) -> str | None:
    value = _value(environ, name)
    if value is None:
        return None
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        raise ConfigurationError(f"{name} must be a valid email address")
    return value


def _list(
    environ: Mapping[str, str],
    name: str,
    default: tuple[str, ...],
) -> tuple[str, ...]:
    raw = _value(environ, name)
    if raw is None:
        return tuple(default)
    values = tuple(value.strip() for value in raw.split(",") if value.strip())
    if not values:
        raise ConfigurationError(f"{name} must contain at least one value")
    return values


def _trusted_proxies(environ: Mapping[str, str]) -> tuple[str, ...]:
    values = _list(environ, "MARKERVAULT_TRUSTED_PROXIES", ("127.0.0.1",))
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ConfigurationError(
                f"MARKERVAULT_TRUSTED_PROXIES contains an invalid IP address: {value}"
            ) from exc
    return values


def _allowed_ip_ranges(environ: Mapping[str, str]) -> tuple[str, ...]:
    values = _list(environ, "MARKERVAULT_ALLOWED_IP_RANGES", ("0.0.0.0",))
    for value in values:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ConfigurationError(
                f"MARKERVAULT_ALLOWED_IP_RANGES contains an invalid range: {value}"
            ) from exc
    return values


def _hosts(
    environ: Mapping[str, str],
    name: str,
    default: tuple[str, ...],
) -> tuple[str, ...]:
    values = _list(environ, name, default)
    normalized = []
    for value in values:
        host = value.lower().rstrip(".")
        if host == "*" or "://" in host or "/" in host:
            raise ConfigurationError(f"{name} contains an invalid hostname: {value}")
        ip_candidate = host
        if host.startswith("[") and host.endswith("]"):
            ip_candidate = host[1:-1]
        try:
            normalized.append(str(ipaddress.ip_address(ip_candidate)))
            continue
        except ValueError:
            pass
        labels = host.split(".")
        if (len(host) > 253
                or any(not label or len(label) > 63 for label in labels)
                or any(not label[0].isalnum() or not label[-1].isalnum()
                       for label in labels)
                or any(not all(character.isascii()
                               and (character.isalnum() or character == "-")
                               for character in label)
                       for label in labels)):
            raise ConfigurationError(f"{name} contains an invalid hostname: {value}")
        normalized.append(host)
    return tuple(normalized)


def _smtp_host(environ: Mapping[str, str]) -> str | None:
    value = _value(environ, "MARKERVAULT_SMTP_HOST")
    if value is None:
        return None
    return _hosts(
        {"MARKERVAULT_SMTP_HOST": value},
        "MARKERVAULT_SMTP_HOST",
        (),
    )[0]


def _public_origin(
    environ: Mapping[str, str],
    environment: str,
    allowed_hosts: tuple[str, ...],
) -> str | None:
    value = _value(environ, "MARKERVAULT_PUBLIC_ORIGIN")
    if value is None:
        return None
    try:
        parsed = urlparse(value)
        parsed.port
    except ValueError as error:
        raise ConfigurationError(
            "MARKERVAULT_PUBLIC_ORIGIN must contain a valid host and port"
        ) from error
    if (parsed.scheme not in ("http", "https")
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")):
        raise ConfigurationError(
            "MARKERVAULT_PUBLIC_ORIGIN must be an http(s) origin without "
            "credentials, path, query, or fragment"
        )
    if environment == "production" and parsed.scheme != "https":
        raise ConfigurationError(
            "MARKERVAULT_PUBLIC_ORIGIN must use https in production"
        )
    host = (parsed.hostname or "").lower().rstrip(".")
    if host not in allowed_hosts:
        raise ConfigurationError(
            "MARKERVAULT_PUBLIC_ORIGIN host must be present in the configured "
            "canonical or temporary LAN host allowlist"
        )
    return f"{parsed.scheme}://{parsed.netloc}"


def _is_loopback_host(host: str | None) -> bool:
    if host is None:
        return False
    if host == "localhost":
        return True
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def database_path(environ: Mapping[str, str] | None = None) -> str:
    source = os.environ if environ is None else environ
    return _path(source, "MARKERVAULT_DB_PATH", "spots.db")


def load_backend_configuration(
    environ: Mapping[str, str] | None = None,
    secret_factory: Callable[[int], str] | None = None,
) -> BackendConfiguration:
    source = os.environ if environ is None else environ
    factory = secrets.token_hex if secret_factory is None else secret_factory

    environment = _choice(
        source,
        "MARKERVAULT_ENVIRONMENT",
        "development",
        ("development", "production"),
    )
    secret = _value(source, "MARKERVAULT_ACCESS_TOKEN_SECRET")
    secret_is_ephemeral = secret is None
    if secret_is_ephemeral:
        if environment == "production":
            raise ConfigurationError(
                "MARKERVAULT_ACCESS_TOKEN_SECRET is required in production"
            )
        secret = factory(32)

    canonical_hosts = _hosts(source, "MARKERVAULT_CANONICAL_HOSTS", ())
    temporary_lan_hosts = _hosts(
        source,
        "MARKERVAULT_TEMPORARY_LAN_HOSTS",
        ("markervault.lan",),
    )
    # Every Host value the backend itself accepts (S-12). Production trusts only the
    # explicit canonical + temporary LAN lists; development additionally trusts
    # loopback so local runs and the test client work without configuration.
    allowed_hosts = canonical_hosts
    for host in temporary_lan_hosts:
        if host not in allowed_hosts:
            allowed_hosts = allowed_hosts + (host,)
    if environment == "development":
        for host in ("localhost", "127.0.0.1", "::1"):
            if host not in allowed_hosts:
                allowed_hosts = allowed_hosts + (host,)
    cookie_secure = _boolean(source, "MARKERVAULT_COOKIE_SECURE", True)
    email_delivery_enabled = _boolean(
        source,
        "MARKERVAULT_EMAIL_DELIVERY_ENABLED",
        False,
    )
    require_email_verification = _boolean(
        source,
        "MARKERVAULT_REQUIRE_EMAIL_VERIFICATION",
        False,
    )
    public_origin = _public_origin(source, environment, allowed_hosts)
    smtp_host = _smtp_host(source)
    smtp_security = _choice(
        source,
        "MARKERVAULT_SMTP_SECURITY",
        "starttls",
        ("implicit_tls", "plaintext", "starttls"),
    )
    smtp_from_address = _email_address(
        source,
        "MARKERVAULT_SMTP_FROM_ADDRESS",
    )
    smtp_envelope_from = _email_address(
        source,
        "MARKERVAULT_SMTP_ENVELOPE_FROM",
    )
    if smtp_envelope_from is None:
        smtp_envelope_from = smtp_from_address
    smtp_username = _value(source, "MARKERVAULT_SMTP_USERNAME")
    smtp_password = _secret_value(source, "MARKERVAULT_SMTP_PASSWORD")
    smtp_allow_unauthenticated_local = _boolean(
        source,
        "MARKERVAULT_SMTP_ALLOW_UNAUTHENTICATED_LOCAL",
        False,
    )

    runtime_paths = (
        ("MARKERVAULT_DB_PATH", database_path(source)),
        ("MARKERVAULT_PHOTOS_PATH", _path(source, "MARKERVAULT_PHOTOS_PATH", "photos")),
        ("MARKERVAULT_THUMBS_PATH", _path(source, "MARKERVAULT_THUMBS_PATH", "thumbs")),
        ("MARKERVAULT_AVATARS_PATH", _path(source, "MARKERVAULT_AVATARS_PATH", "avatars")),
        ("MARKERVAULT_TEMP_PATH", _path(source, "MARKERVAULT_TEMP_PATH", "temp")),
    )

    if environment == "production":
        if len(secret) < 32:
            raise ConfigurationError(
                "MARKERVAULT_ACCESS_TOKEN_SECRET must contain at least 32 characters in production"
            )
        if not canonical_hosts:
            raise ConfigurationError(
                "MARKERVAULT_CANONICAL_HOSTS is required in production"
            )
        if not cookie_secure:
            raise ConfigurationError(
                "MARKERVAULT_COOKIE_SECURE must be true in production"
            )
        # The deployment boundary (S-01) keeps runtime state outside the public tree;
        # relative working-directory paths would silently recreate the shared root.
        for name, value in runtime_paths:
            if not os.path.isabs(value):
                raise ConfigurationError(
                    f"{name} must be an absolute path in production"
                )
    if require_email_verification and not email_delivery_enabled:
        raise ConfigurationError(
            "MARKERVAULT_REQUIRE_EMAIL_VERIFICATION requires "
            "MARKERVAULT_EMAIL_DELIVERY_ENABLED=true"
        )
    if require_email_verification and public_origin is None:
        raise ConfigurationError(
            "MARKERVAULT_REQUIRE_EMAIL_VERIFICATION requires "
            "MARKERVAULT_PUBLIC_ORIGIN"
        )
    if (smtp_username is None) != (smtp_password is None):
        raise ConfigurationError(
            "MARKERVAULT_SMTP_USERNAME and MARKERVAULT_SMTP_PASSWORD "
            "must be set together"
        )
    if smtp_username is not None and smtp_security == "plaintext":
        raise ConfigurationError(
            "authenticated SMTP requires starttls or implicit_tls"
        )
    if smtp_allow_unauthenticated_local:
        if smtp_username is not None:
            raise ConfigurationError(
                "MARKERVAULT_SMTP_ALLOW_UNAUTHENTICATED_LOCAL cannot be used "
                "with SMTP credentials"
            )
        if not _is_loopback_host(smtp_host):
            raise ConfigurationError(
                "MARKERVAULT_SMTP_ALLOW_UNAUTHENTICATED_LOCAL requires a "
                "loopback SMTP host"
            )
    if email_delivery_enabled:
        missing = []
        if smtp_host is None:
            missing.append("MARKERVAULT_SMTP_HOST")
        if smtp_from_address is None:
            missing.append("MARKERVAULT_SMTP_FROM_ADDRESS")
        if missing:
            raise ConfigurationError(
                "email delivery requires: " + ", ".join(missing)
            )
        if smtp_username is None and not smtp_allow_unauthenticated_local:
            raise ConfigurationError(
                "email delivery requires SMTP credentials or explicit "
                "unauthenticated loopback configuration"
            )

    return BackendConfiguration(
        environment=environment,
        database_path=runtime_paths[0][1],
        photos_path=runtime_paths[1][1],
        thumbs_path=runtime_paths[2][1],
        avatars_path=runtime_paths[3][1],
        temp_path=runtime_paths[4][1],
        access_token_secret=secret,
        access_token_secret_is_ephemeral=secret_is_ephemeral,
        access_token_duration=_integer(
            source,
            "MARKERVAULT_ACCESS_TOKEN_DURATION",
            15 * 60,
        ),
        refresh_token_duration=_integer(
            source,
            "MARKERVAULT_REFRESH_TOKEN_DURATION",
            4 * 60 * 60,
        ),
        bind_token_to_ip=_boolean(
            source,
            "MARKERVAULT_BIND_TOKEN_TO_IP",
            True,
        ),
        cookie_secure=cookie_secure,
        trusted_proxies=_trusted_proxies(source),
        allowed_ip_ranges=_allowed_ip_ranges(source),
        canonical_hosts=canonical_hosts,
        temporary_lan_hosts=temporary_lan_hosts,
        allowed_hosts=allowed_hosts,
        max_content_length=_integer(
            source,
            "MARKERVAULT_MAX_CONTENT_LENGTH",
            20 * 1024 * 1024,
        ),
        max_kml_photo_bytes=_integer(
            source,
            "MARKERVAULT_MAX_KML_PHOTO_BYTES",
            20 * 1024 * 1024,
        ),
        max_image_dimension=_integer(
            source,
            "MARKERVAULT_MAX_IMAGE_DIMENSION",
            10000,
        ),
        max_image_pixels=_integer(
            source,
            "MARKERVAULT_MAX_IMAGE_PIXELS",
            40 * 1000 * 1000,
        ),
        kml_max_workers=_integer(
            source,
            "MARKERVAULT_KML_MAX_WORKERS",
            2,
        ),
        kml_jobs_per_user=_integer(
            source,
            "MARKERVAULT_KML_JOBS_PER_USER",
            1,
        ),
        kml_jobs_global=_integer(
            source,
            "MARKERVAULT_KML_JOBS_GLOBAL",
            4,
        ),
        kml_max_bytes=_integer(
            source,
            "MARKERVAULT_KML_MAX_BYTES",
            20 * 1024 * 1024,
        ),
        kml_max_elements=_integer(
            source,
            "MARKERVAULT_KML_MAX_ELEMENTS",
            100000,
        ),
        kml_max_depth=_integer(
            source,
            "MARKERVAULT_KML_MAX_DEPTH",
            50,
        ),
        kml_max_placemarks=_integer(
            source,
            "MARKERVAULT_KML_MAX_PLACEMARKS",
            2000,
        ),
        kml_max_photos_per_spot=_integer(
            source,
            "MARKERVAULT_KML_MAX_PHOTOS_PER_SPOT",
            20,
        ),
        kml_max_download_bytes=_integer(
            source,
            "MARKERVAULT_KML_MAX_DOWNLOAD_BYTES",
            2 * 1024 * 1024 * 1024,
        ),
        kml_max_fetch_attempts=_integer(
            source,
            "MARKERVAULT_KML_MAX_FETCH_ATTEMPTS",
            500,
        ),
        kml_max_job_seconds=_integer(
            source,
            "MARKERVAULT_KML_MAX_JOB_SECONDS",
            900,
        ),
        notif_history_cap=_integer(
            source,
            "MARKERVAULT_NOTIF_HISTORY_CAP",
            200,
        ),
        private_refill_interval=_number(
            source,
            "MARKERVAULT_PRIVATE_REFILL_INTERVAL",
            0.05,
        ),
        auth_refill_interval=_number(
            source,
            "MARKERVAULT_AUTH_REFILL_INTERVAL",
            5,
        ),
        public_refill_interval=_number(
            source,
            "MARKERVAULT_PUBLIC_REFILL_INTERVAL",
            10,
        ),
        rate_burst=_integer(source, "MARKERVAULT_RATE_BURST", 14),
        private_rate_burst=_integer(source, "MARKERVAULT_PRIVATE_RATE_BURST", 60),
        email_delivery_enabled=email_delivery_enabled,
        require_email_verification=require_email_verification,
        public_origin=public_origin,
        email_verification_token_duration=_integer(
            source,
            "MARKERVAULT_EMAIL_VERIFICATION_TOKEN_DURATION",
            24 * 60 * 60,
        ),
        password_reset_token_duration=_integer(
            source,
            "MARKERVAULT_PASSWORD_RESET_TOKEN_DURATION",
            30 * 60,
        ),
        email_resend_cooldown=_integer(
            source,
            "MARKERVAULT_EMAIL_RESEND_COOLDOWN",
            60,
        ),
        smtp_host=smtp_host,
        smtp_port=_integer(
            source,
            "MARKERVAULT_SMTP_PORT",
            587,
            maximum=65535,
        ),
        smtp_timeout=_number(
            source,
            "MARKERVAULT_SMTP_TIMEOUT",
            10,
        ),
        smtp_security=smtp_security,
        smtp_from_address=smtp_from_address,
        smtp_envelope_from=smtp_envelope_from,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        smtp_allow_unauthenticated_local=smtp_allow_unauthenticated_local,
    )
