"""Application error types.

``public_message`` is the only text that may be shown to users. Internal detail goes to the
server log, never to the UI.
"""

from __future__ import annotations


class ThreatLensError(Exception):
    public_message = "The operation could not be completed."

    def __init__(self, public_message: str | None = None, *, detail: str | None = None) -> None:
        if public_message is not None:
            self.public_message = public_message
        self.detail = detail
        super().__init__(detail or self.public_message)


class AuthenticationError(ThreatLensError):
    public_message = "Invalid username or password."


class SessionExpiredError(ThreatLensError):
    public_message = "Your session has expired. Please sign in again."


class AuthorizationError(ThreatLensError):
    public_message = "You do not have permission to perform this action."


class RateLimitedError(ThreatLensError):
    public_message = "Too many attempts. Please wait and try again."


class SetupError(ThreatLensError):
    public_message = "Initial setup is not available."


class ValidationFailedError(ThreatLensError):
    public_message = "The input failed validation."


class NotFoundError(ThreatLensError):
    public_message = "The requested item was not found."


class ConflictError(ThreatLensError):
    public_message = "The item was changed by another action. Refresh and try again."


class DatabaseUnavailableError(ThreatLensError):
    public_message = "The database is unavailable. Check the health page for recovery steps."


class AIUnavailableError(ThreatLensError):
    public_message = "The local AI model is unavailable. A deterministic summary is shown instead."
