"""
NitiQ - PDF Report Generation API Router
"""

from fastapi import APIRouter, Response, status, Query
from backend.app.reports.pdf_generator import generate_readiness_pdf_report

router = APIRouter(prefix="/reports", tags=["PDF Reports"])


@router.get("/readiness-pdf")
def download_readiness_pdf_report(profile_id: str = Query(default="weak_org")):
    """Generates and downloads the executive PDF assessment report."""
    try:
        pdf_bytes = generate_readiness_pdf_report(profile_id=profile_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=NitiQ_Readiness_Report_{profile_id}.pdf"
            },
        )
    except Exception as e:
        return Response(
            content=f"PDF generation error: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
