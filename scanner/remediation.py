from __future__ import annotations

from typing import Dict

from .types import Remediation


def default_remediations() -> Dict[str, Remediation]:
    return {
        "HS001": Remediation(
            rule_id="HS001",
            title="Hardcoded password detected",
            suggestion="Move passwords to environment variables or a secrets manager. Never commit them to source control.",
            secure_alternative='password = os.environ.get("APP_PASSWORD")',
            references=["OWASP Secrets Management Cheat Sheet"],
        ),
        "HS002": Remediation(
            rule_id="HS002",
            title="Hardcoded API/secret key detected",
            suggestion="Remove the key from code, rotate the leaked credential, and load it from environment/secret manager.",
            secure_alternative='api_key = os.environ.get("API_KEY")',
            references=["OWASP Secrets Management Cheat Sheet"],
        ),
        "HS003": Remediation(
            rule_id="HS003",
            title="Possible AWS Access Key ID in code",
            suggestion="Remove credential from code and rotate it immediately. Use IAM roles or env-based configuration.",
            references=["AWS IAM Best Practices"],
        ),
        "WC001": Remediation(
            rule_id="WC001",
            title="Weak crypto algorithm used",
            suggestion="Avoid md5/sha1 for security purposes. Use SHA-256+ or modern password hashing like bcrypt/argon2.",
            secure_alternative="hashlib.sha256(data).hexdigest()",
            references=["OWASP Cryptographic Storage Cheat Sheet"],
        ),
        "IR001": Remediation(
            rule_id="IR001",
            title="Insecure random used",
            suggestion="Use the secrets module for security-sensitive randomness (tokens, passwords, IDs).",
            secure_alternative="import secrets\nsecrets.token_urlsafe(32)",
            references=["Python secrets module documentation"],
        ),
        "W8-TAINT-SINK": Remediation(
            rule_id="W8-TAINT-SINK",
            title="Sensitive/tainted data reaches sink",
            suggestion="Do not print/log/send secrets. Mask sensitive data and avoid exfiltration via logs/HTTP.",
            secure_alternative='logger.info("token=%s", token[:4] + "****")',
            references=["OWASP Logging Cheat Sheet"],
        ),
    }