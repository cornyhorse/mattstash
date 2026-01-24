"""Pydantic response models for API endpoints."""
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")


class CredentialResponse(BaseModel):
    """Response model for a single credential."""
    name: str = Field(..., description="Credential name")
    username: str | None = Field(None, description="Username")
    password: str = Field(..., description="Password (masked or revealed)")
    url: str | None = Field(None, description="URL/host")
    notes: str | None = Field(None, description="Additional notes")
    version: str | None = Field(None, description="Credential version")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "db-prod",
                "username": "admin",
                "password": "*****",
                "url": "postgres.example.com:5432",
                "notes": "Production database",
                "version": "0000000001"
            }
        }


class CredentialListResponse(BaseModel):
    """Response model for listing credentials."""
    credentials: list[CredentialResponse] = Field(..., description="List of credentials")
    count: int = Field(..., description="Total count")
    
    class Config:
        json_schema_extra = {
            "example": {
                "credentials": [
                    {
                        "name": "db-prod",
                        "username": "admin",
                        "password": "*****",
                        "url": "postgres.example.com:5432",
                        "notes": None,
                        "version": "0000000001"
                    }
                ],
                "count": 1
            }
        }


class VersionListResponse(BaseModel):
    """Response model for listing credential versions."""
    name: str = Field(..., description="Credential name")
    versions: list[str] = Field(..., description="List of version identifiers")
    latest: str = Field(..., description="Latest version identifier")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "db-prod",
                "versions": ["0000000001", "0000000002", "0000000003"],
                "latest": "0000000003"
            }
        }


class DatabaseUrlResponse(BaseModel):
    """Response model for database URL."""
    url: str = Field(..., description="Constructed database URL")
    
    class Config:
        json_schema_extra = {
            "example": {
                "url": "postgresql+psycopg://user:*****@host:5432/mydb"
            }
        }


class CreateCredentialResponse(BaseModel):
    """Response model for credential creation/update."""
    name: str = Field(..., description="Credential name")
    version: str = Field(..., description="Version identifier")
    created: bool = Field(..., description="True if created, False if updated")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "db-prod",
                "version": "0000000001",
                "created": True
            }
        }


class ErrorResponse(BaseModel):
    """Error response model."""
    detail: str = Field(..., description="Error message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "detail": "Credential not found: db-prod"
            }
        }
