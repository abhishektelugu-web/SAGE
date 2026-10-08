"""Health check endpoint for SAGE AI Backend."""

from fastapi import APIRouter
from backend.schemas.api_schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def health_check():
    """Verify backend system status and operational health."""
    return HealthResponse(
        status="ok",
        service="SAGE AI Security Engine",
        version="1.0.0",
    )
