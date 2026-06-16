from fastapi import APIRouter, HTTPException
from app.models import FuzzGenerateRequest, FuzzReport
from app.fuzz import generate_and_validate

router = APIRouter(prefix="/api/fuzz", tags=["fuzz"])


@router.post("/generate", response_model=FuzzReport)
async def generate_fuzz_samples(body: FuzzGenerateRequest):
    try:
        report = await generate_and_validate(
            template_id=body.template_id,
            count=body.count,
            strategy_distribution=body.strategy_distribution,
            template_version=body.template_version,
        )
        return report
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
