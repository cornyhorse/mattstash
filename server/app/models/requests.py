"""Pydantic request models for API endpoints."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

# KeePass has no hard limit; these keep a single request (and the stored entry) reasonable.
MAX_SECRET_LENGTH = 65_536


class CreateCredentialRequest(BaseModel):
    """Request model for creating/updating a credential."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"value": "my-secret-value"},
                {
                    "username": "admin",
                    "password": "secret123",
                    "url": "postgres.example.com:5432",
                    "notes": "Production database",
                },
            ]
        }
    )

    # Simple mode (just a value)
    value: str | None = Field(None, max_length=MAX_SECRET_LENGTH, description="Simple credential value")

    # Full mode
    username: str | None = Field(None, max_length=255, description="Username for the credential")
    password: str | None = Field(None, max_length=MAX_SECRET_LENGTH, description="Password for the credential")
    url: str | None = Field(None, max_length=2048, description="URL/host for the credential")
    notes: str | None = Field(None, max_length=65_535, description="Additional notes")
    tags: list[Annotated[str, Field(max_length=100)]] | None = Field(
        None, max_length=50, description="Tags to attach to the credential"
    )

    @model_validator(mode="after")
    def validate_mode(self) -> "CreateCredentialRequest":
        """Require either simple-value mode or full-credential fields, not both."""
        full_fields = [self.username, self.password, self.url]
        has_value = self.value is not None
        has_full_field = any(field is not None for field in full_fields)
        if has_value and has_full_field:
            raise ValueError("value cannot be combined with username, password, or url")
        if not has_value and not has_full_field:
            raise ValueError("provide value or at least one credential field")
        return self


class _AdminRequest(BaseModel):
    """Admin request bodies refuse unknown fields: a typo such as ``"admn": true`` must not be silently ignored."""

    model_config = ConfigDict(extra="forbid")


class CreatePrincipalRequest(_AdminRequest):
    name: str = Field(..., max_length=64)
    kind: str = Field(..., max_length=32)
    description: str = Field("", max_length=500)
    admin: bool = False


class UpdatePrincipalRequest(_AdminRequest):
    disabled: bool | None = None
    admin: bool | None = None
    description: str | None = Field(None, max_length=500)


class IssueTokenRequest(_AdminRequest):
    expires: str | None = Field(None, max_length=64, description="Duration (90d, 24h) or date (2027-01-01)")
    description: str = Field("", max_length=500)


class RotateTokenRequest(_AdminRequest):
    grace: str | None = Field(None, max_length=64, description="How long the old token keeps working (24h)")
    expires: str | None = Field(None, max_length=64)
    description: str = Field("", max_length=500)


class CreateGrantRequest(_AdminRequest):
    principal: str = Field(..., max_length=64)
    key: str | None = Field(None, max_length=300)
    tag: str | None = Field(None, max_length=100)
    actions: list[Annotated[str, Field(max_length=16)]] | None = Field(None, max_length=8)
    expires: str | None = Field(None, max_length=64)
    description: str = Field("", max_length=500)


class CheckRequest(_AdminRequest):
    principal: str = Field(..., max_length=64)
    action: str = Field(..., max_length=16)
    name: str = Field(..., max_length=300)
    tags: list[Annotated[str, Field(max_length=100)]] = Field(default_factory=list, max_length=50)
