"""
NitiQ - Comprehensive PDF Assessment Report Generator
Generates an executive PDF report containing organization readiness headline metrics,
NIST CSF maturity scores, What-If remediations, and ML Early-Warning detector safe evaluation metrics.
Uses ReportLab PDF Library.
"""

import io
import datetime
from typing import Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.app.api.assessment import run_comprehensive_assessment, AssessmentRequest
from backend.app.ml.evaluator import run_safe_evaluation
from backend.app.ml.trainer import load_model_bundle


def generate_readiness_pdf_report(profile_id: str = "weak_org") -> bytes:
    """
    Generates PDF bytes for comprehensive NitiQ Ransomware Readiness Report.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "SubTitleStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        textColor=colors.HexColor("#06b6d4"),
        spaceAfter=14,
    )
    h2_style = ParagraphStyle(
        "H2Style",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
        spaceAfter=8,
    )
    disclaimer_style = ParagraphStyle(
        "DisclaimerStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#475569"),
    )

    story = []

    # 1. Header & Title Block
    story.append(Paragraph("NitiQ — Ransomware Readiness & ML Early-Warning Assessment", title_style))
    story.append(Paragraph("Executive Defensive Risk Report | Modeled Simulation & ML Anomaly Detection", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#06b6d4"), spaceAfter=14))

    # Fetch Comprehensive Assessment Data
    try:
        ass_data = run_comprehensive_assessment(AssessmentRequest(profile_id=profile_id))
    except Exception:
        ass_data = None

    if ass_data:
        h = ass_data.headline_metrics
        pz = ass_data.worst_case_patient_zero

        story.append(Paragraph("1. Executive Headline Readiness Metrics", h2_style))

        metrics_table_data = [
            ["Metric Name", "Value", "Baseline Target / Status", "Defensive Interpretation"],
            ["Composite Blast Radius", f"{h.blast_radius_composite_pct:.1f}%", "Max Exposure", f"{ass_data.simulation.blast_radius.compromised_hosts}/{ass_data.simulation.blast_radius.total_hosts} hosts compromised"],
            ["Modeled Time-to-Detect", f"{h.time_to_detect_hours:.1f} Hours", "SOC Telemetry Delay", f"Mechanism: {ass_data.simulation.detection.detection_mechanism}"],
            ["Estimated Recovery Time", f"{h.recovery_time_hours:.1f} Hours", f"RTO Target: {h.required_rto_hours}h", f"Status: {h.rto_status} (Gap: {h.rto_gap_hours:+.1f}h)"],
            ["NIST CSF Maturity Score", f"{h.overall_maturity_score:.1f} / 100", f"Tier: {h.maturity_tier}", f"Level {ass_data.scoring.maturity_level} of 5"],
        ]

        t_metrics = Table(metrics_table_data, colWidths=[130, 80, 130, 200])
        t_metrics.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t_metrics)
        story.append(Spacer(1, 10))

        story.append(Paragraph(f"<b>Worst-Case Patient Zero Breach Vector:</b> {pz.entity_name} ({pz.entity_id}, {pz.department}). Risk Score: {pz.risk_score:.1f}/100. Domain Admin Reached: {'Yes' if pz.domain_admin_reached else 'No'}.", body_style))
        story.append(Spacer(1, 10))

    # 2. ML Early-Warning Detector Evaluation
    story.append(Paragraph("2. ML Early-Warning Ransomware Detector Evaluation", h2_style))

    try:
        eval_res = run_safe_evaluation()
    except Exception:
        eval_res = None

    if eval_res and not eval_res.get("insufficient_data"):
        ml = eval_res["isolation_forest_ml"]
        th = eval_res["threshold_detector"]
        cm = ml["confusion_matrix"]

        story.append(Paragraph(f"<b>Evaluation Summary:</b> Evaluated on {eval_res['total_test_windows']} test windows ({eval_res['heldout_normal_count']} held-out normal baseline + {eval_res['emulator_window_count']} SAFE sandbox emulator attack stage windows).", body_style))

        eval_table_data = [
            ["Detector Engine", "Detection Rate", "False Positive Rate (FPR)", "Precision", "Recall", "F1 Score", "Modeled TTD"],
            ["Fixed Threshold Rule", f"{th['detection_rate']*100:.1f}%", f"{th['false_positive_rate']*100:.1f}%", f"{th['precision']:.2f}", f"{th['recall']:.2f}", f"{th['f1_score']:.2f}", f"{th['ttd_hours']:.2f}h"],
            ["IsolationForest ML", f"{ml['detection_rate']*100:.1f}%", f"{ml['false_positive_rate']*100:.1f}%", f"{ml['precision']:.2f}", f"{ml['recall']:.2f}", f"{ml['f1_score']:.2f}", f"{ml['ttd_hours']:.2f}h"],
        ]

        t_eval = Table(eval_table_data, colWidths=[120, 75, 110, 55, 55, 55, 70])
        t_eval.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#06b6d4")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t_eval)
        story.append(Spacer(1, 8))

        story.append(Paragraph(f"<b>Confusion Matrix (IsolationForest):</b> True Positives (TP): {cm['tp']} | False Positives (FP): {cm['fp']} | True Negatives (TN): {cm['tn']} | False Negatives (FN): {cm['fn']}", body_style))
    else:
        story.append(Paragraph("<i>ML Safe Evaluation results unavailable. Please record baseline telemetry and train a model first.</i>", body_style))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

    # 3. Provenance & Limitations Disclaimer
    story.append(Paragraph("3. Provenance & Prototype Limitations Disclaimer", h2_style))
    story.append(Paragraph(
        "<b>DATA PROVENANCE NOTICE:</b> Modeled TTD is derived from user-configured telemetry coverage; "
        "Emulator TTD is measured in a temporary isolated SAFE sandbox; Live Observed TTD is measured during "
        "active host monitoring. All calculations are non-destructive decision-support models designed "
        "strictly for cyber defense investment prioritization.",
        disclaimer_style,
    ))

    doc.build(story)
    return buffer.getvalue()
