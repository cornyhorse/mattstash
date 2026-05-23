"""Pydantic request models for API endpoints."""
from pydantic import BaseModel, Field, model_validator


class CreateCredentialRequest(BaseModel):
    """Request model for creating/updating a credential."""
    
    # Simple mode (just a value)
    value: str | None = Field(None, description="Simple credential value")
    
    # Full mode
    username: str | None = Field(None, description="Username for the credential")
    password: str | None = Field(None, description="Password for the credential")
    url: str | None = Field(None, description="URL/host for the credential")
    notes: str | None = Field(None, description="Additional notes")
    tags: list[str] | None = Field(None, description="Tags to attach to the credential")

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
    
    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "value": "my-secret-value"
                },
                {
                    "username": "admin",
                    "password": "secret123",
                    "url": "postgres.example.com:5432",
                    "notes": "Production database"
                }
            ]
        }
