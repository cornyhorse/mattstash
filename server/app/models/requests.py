"""Pydantic request models for API endpoints."""
from pydantic import BaseModel, Field


class CreateCredentialRequest(BaseModel):
    """Request model for creating/updating a credential."""
    
    # Simple mode (just a value)
    value: str | None = Field(None, description="Simple credential value")
    
    # Full mode
    username: str | None = Field(None, description="Username for the credential")
    password: str | None = Field(None, description="Password for the credential")
    url: str | None = Field(None, description="URL/host for the credential")
    notes: str | None = Field(None, description="Additional notes")
    
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
