import html
import logging
import re
import smtplib
import ssl

from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage


LOGGER = logging.getLogger("markervault.email")
MAILBOX_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
KNOWN_TEMPLATES = {
    "account_verification",
    "delivery_test",
    "password_reset",
}


class EmailDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class EmailContent:
    template: str
    subject: str
    text_body: str
    html_body: str | None = None


@dataclass(frozen=True)
class DeliveryResult:
    delivered: bool
    status: str


def test_email_content() -> EmailContent:
    return EmailContent(
        template="delivery_test",
        subject="MarkerVault email delivery test",
        text_body=(
            "MarkerVault successfully connected to the configured SMTP server.\n"
            "No account or verification behavior was changed."
        ),
    )


def verification_email_content(display_name: str, verification_url: str) -> EmailContent:
    name = display_name.strip() or "there"
    escaped_name = html.escape(name)
    escaped_url = html.escape(verification_url, quote=True)
    return EmailContent(
        template="account_verification",
        subject="Verify your MarkerVault email address",
        text_body=(
            f"Hello {name},\n\n"
            "Use this link to verify your MarkerVault email address:\n"
            f"{verification_url}\n\n"
            "If you did not request this, you can ignore this message."
        ),
        html_body=(
            f"<p>Hello {escaped_name},</p>"
            "<p>Use this link to verify your MarkerVault email address:</p>"
            f'<p><a href="{escaped_url}">Verify email address</a></p>'
            "<p>If you did not request this, you can ignore this message.</p>"
        ),
    )


def password_reset_email_content(display_name: str, reset_url: str) -> EmailContent:
    name = display_name.strip() or "there"
    escaped_name = html.escape(name)
    escaped_url = html.escape(reset_url, quote=True)
    return EmailContent(
        template="password_reset",
        subject="Reset your MarkerVault password",
        text_body=(
            f"Hello {name},\n\n"
            "Use this link to reset your MarkerVault password:\n"
            f"{reset_url}\n\n"
            "If you did not request this, you can ignore this message."
        ),
        html_body=(
            f"<p>Hello {escaped_name},</p>"
            "<p>Use this link to reset your MarkerVault password:</p>"
            f'<p><a href="{escaped_url}">Reset password</a></p>'
            "<p>If you did not request this, you can ignore this message.</p>"
        ),
    )


def _safe_log_token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)[:48] or "unknown"


def _validate_mailbox(value: str) -> str:
    if "\r" in value or "\n" in value or not MAILBOX_PATTERN.fullmatch(value):
        raise ValueError("recipient must be a valid email address")
    return value


class SMTPDelivery:
    def __init__(
        self,
        *,
        enabled: bool,
        host: str | None,
        port: int,
        timeout: float,
        security: str,
        from_address: str | None,
        envelope_from: str | None,
        username: str | None,
        password: str | None,
        smtp_factory: Callable = smtplib.SMTP,
        smtp_ssl_factory: Callable = smtplib.SMTP_SSL,
        ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
    ):
        self.enabled = enabled
        self.host = host
        self.port = port
        self.timeout = timeout
        self.security = security
        self.from_address = from_address
        self.envelope_from = envelope_from
        self.username = username
        self._password = password
        self._smtp_factory = smtp_factory
        self._smtp_ssl_factory = smtp_ssl_factory
        self._ssl_context_factory = ssl_context_factory

    @classmethod
    def from_backend_configuration(cls, configuration):
        return cls(
            enabled=configuration.email_delivery_enabled,
            host=configuration.smtp_host,
            port=configuration.smtp_port,
            timeout=configuration.smtp_timeout,
            security=configuration.smtp_security,
            from_address=configuration.smtp_from_address,
            envelope_from=configuration.smtp_envelope_from,
            username=configuration.smtp_username,
            password=configuration.smtp_password,
        )

    def _log_status(
        self,
        status: str,
        content: EmailContent,
        *,
        error_type: str | None = None,
    ) -> None:
        template = content.template if content.template in KNOWN_TEMPLATES else "custom"
        if error_type is None:
            LOGGER.info(
                "email_delivery status=%s template=%s",
                status,
                template,
            )
            return
        LOGGER.error(
            "email_delivery status=%s template=%s error_type=%s",
            status,
            template,
            _safe_log_token(error_type),
        )

    def _message(self, recipient: str, content: EmailContent) -> EmailMessage:
        recipient = _validate_mailbox(recipient)
        if "\r" in content.subject or "\n" in content.subject:
            raise ValueError("email subject must not contain newlines")
        message = EmailMessage()
        message["From"] = self.from_address
        message["To"] = recipient
        message["Subject"] = content.subject
        message.set_content(content.text_body)
        if content.html_body is not None:
            message.add_alternative(content.html_body, subtype="html")
        return message

    def _send_with_client(
        self,
        client,
        recipient: str,
        message: EmailMessage,
    ) -> None:
        if self.username is not None:
            client.login(self.username, self._password)
        client.send_message(
            message,
            from_addr=self.envelope_from,
            to_addrs=(recipient,),
        )

    def send(self, recipient: str, content: EmailContent) -> DeliveryResult:
        if not self.enabled:
            self._log_status("disabled", content)
            return DeliveryResult(delivered=False, status="disabled")

        message = self._message(recipient, content)
        try:
            if self.security == "implicit_tls":
                context = self._ssl_context_factory()
                with self._smtp_ssl_factory(
                    self.host,
                    self.port,
                    timeout=self.timeout,
                    context=context,
                ) as client:
                    self._send_with_client(client, recipient, message)
            else:
                with self._smtp_factory(
                    self.host,
                    self.port,
                    timeout=self.timeout,
                ) as client:
                    if self.security == "starttls":
                        context = self._ssl_context_factory()
                        client.ehlo()
                        client.starttls(context=context)
                        client.ehlo()
                    self._send_with_client(client, recipient, message)
        except (OSError, smtplib.SMTPException, TimeoutError) as exc:
            self._log_status("failed", content, error_type=type(exc).__name__)
            raise EmailDeliveryError("Email delivery failed") from None

        self._log_status("sent", content)
        return DeliveryResult(delivered=True, status="sent")
