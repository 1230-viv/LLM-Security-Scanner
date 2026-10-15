"""
Script to generate a professional, publication-grade 2-page Research Brief PDF
documenting the LLM Security Scanner system, technology stack, operational
pipeline, security techniques, and empirical evaluation benchmark.
"""

from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

# Publication Palette
PRIMARY = colors.HexColor("#0F172A")       # Deep Slate
SECONDARY = colors.HexColor("#0284C7")     # Sky Blue
ACCENT = colors.HexColor("#0D9488")        # Teal Accent
DARK_TEXT = colors.HexColor("#1E293B")     # Slate Text
MUTED_TEXT = colors.HexColor("#64748B")    # Slate Muted
BORDER_COLOR = colors.HexColor("#CBD5E1")  # Slate Border
BG_LIGHT = colors.HexColor("#F8FAFC")      # Slate Tint Light
CALLOUT_BG = colors.HexColor("#F1F5F9")    # Slate Box Light


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and stamp total page count,
    running header, and running footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, total_pages):
        self.saveState()
        self.setFont("Helvetica", 7.5)
        self.setFillColor(MUTED_TEXT)
        page_w, page_h = letter
        margin = 36  # 0.5 in

        # Header (Pages 2+)
        if self._pageNumber > 1:
            self.drawString(margin, page_h - 26, "LLM Security Scanner — System Architecture & Methodology Reference")
            self.drawRightString(page_w - margin, page_h - 26, "Research Brief")
            self.setStrokeColor(BORDER_COLOR)
            self.setLineWidth(0.5)
            self.line(margin, page_h - 30, page_w - margin, page_h - 30)

        # Footer (All pages)
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.5)
        self.line(margin, 28, page_w - margin, 28)
        
        self.drawString(margin, 18, "LLM Security Scanner | Research & Evaluation Architecture Reference")
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(page_w - margin, 18, page_str)
        self.restoreState()


def build_pdf(filename: str):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=34,
        bottomMargin=34,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=PRIMARY,
        spaceAfter=1,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        fontName="Helvetica",
        fontSize=9,
        leading=11.5,
        textColor=SECONDARY,
        spaceAfter=3,
    )
    meta_style = ParagraphStyle(
        "DocMeta",
        fontName="Helvetica",
        fontSize=7.2,
        leading=9.5,
        textColor=MUTED_TEXT,
    )
    h1_style = ParagraphStyle(
        "SectionH1",
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=12.5,
        textColor=PRIMARY,
        spaceBefore=6,
        spaceAfter=2,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        fontName="Helvetica-Bold",
        fontSize=8.2,
        leading=10.5,
        textColor=SECONDARY,
        spaceBefore=3.5,
        spaceAfter=1,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "BodyTextCustom",
        fontName="Helvetica",
        fontSize=7.8,
        leading=10.2,
        textColor=DARK_TEXT,
        spaceAfter=2.5,
    )
    bullet_style = ParagraphStyle(
        "BulletText",
        fontName="Helvetica",
        fontSize=7.6,
        leading=9.8,
        textColor=DARK_TEXT,
        leftIndent=10,
        firstLineIndent=-7,
        spaceAfter=2,
    )
    table_cell = ParagraphStyle(
        "TableCell",
        fontName="Helvetica",
        fontSize=7.2,
        leading=9.2,
        textColor=DARK_TEXT,
    )
    table_header = ParagraphStyle(
        "TableHeader",
        fontName="Helvetica-Bold",
        fontSize=7.2,
        leading=9.2,
        textColor=colors.white,
    )
    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        fontName="Helvetica-Bold",
        fontSize=7.2,
        leading=9.2,
        textColor=PRIMARY,
    )
    code_text = ParagraphStyle(
        "CodeText",
        fontName="Courier",
        fontSize=6.8,
        leading=8.5,
        textColor=DARK_TEXT,
    )

    story = []

    # =========================================================
    # PAGE 1: SYSTEM OVERVIEW, TECH STACK, PIPELINE & TECHNIQUES
    # =========================================================
    story.append(Paragraph("LLM Security Scanner", title_style))
    story.append(Paragraph("System Architecture, Evaluation Methodologies & Red-Teaming Research Brief", subtitle_style))
    
    meta_text = (
        "<b>Framework Version:</b> 2.1.0 &nbsp;|&nbsp; "
        "<b>Classification:</b> Defensive AI Security & Assurance &nbsp;|&nbsp; "
        "<b>Evaluation Target:</b> RESTful LLM Endpoints (Ollama Llama 3.2, vLLM, OpenAI API)"
    )
    story.append(Paragraph(meta_text, meta_style))
    story.append(HRFlowable(width="100%", thickness=1, color=SECONDARY, spaceBefore=2, spaceAfter=4))

    # 1. Executive Summary & Research Purpose
    story.append(Paragraph("1. Executive Summary & Research Purpose", h1_style))
    summary_p = (
        "The <b>LLM Security Scanner</b> is a modular, high-throughput red-teaming framework engineered to assess and "
        "quantify the adversarial robustness of Large Language Model (LLM) endpoints. Its core research purpose is to "
        "bridge the critical gap between theoretical attack taxonomies and empirical security evaluation by resolving "
        "pervasive false-positive rates (FPR) in naive heuristic detectors. The system systematically evaluates "
        "<b>Prompt Injection (LLM01)</b>, <b>Jailbreaks</b>, <b>System Prompt Extraction</b>, and "
        "<b>Unauthorized Data Disclosure / Exfiltration (LLM06)</b> through rigorous synthetic canary verification, "
        "semantic refusal disambiguation, prompt-echo suppression, and explicit verdict classifications."
    )
    story.append(Paragraph(summary_p, body_style))

    # 2. Technology Stack & Infrastructure
    story.append(Paragraph("2. Technology Stack & Infrastructure", h1_style))
    tech_data = [
        [
            Paragraph("<b>Tier</b>", table_header),
            Paragraph("<b>Technologies & Libraries</b>", table_header),
            Paragraph("<b>Operational Role & Research Value</b>", table_header),
        ],
        [
            Paragraph("<b>Backend API & Engine</b>", table_cell_bold),
            Paragraph("Python 3.11+, FastAPI, Uvicorn, Pydantic v2", table_cell),
            Paragraph("High-throughput async REST engine; strict schema validation of attack test suites and execution payloads.", table_cell),
        ],
        [
            Paragraph("<b>Async Execution & Network</b>", table_cell_bold),
            Paragraph("HTTPX, AsyncIO Semaphores, Token Bucket", table_cell),
            Paragraph("Controlled parallel dispatch against LLM inference servers (concurrency & req/sec rate governance).", table_cell),
        ],
        [
            Paragraph("<b>Persistence & Telemetry</b>", table_cell_bold),
            Paragraph("PostgreSQL, SQLAlchemy 2.0 (asyncpg), Supabase", table_cell),
            Paragraph("Full raw audit trails, JSONB metadata persistence, scan configuration histories, and findings logs.", table_cell),
        ],
        [
            Paragraph("<b>Frontend Dashboard</b>", table_cell_bold),
            Paragraph("React 18, TypeScript, Vite, Tailwind CSS / Vanilla CSS", table_cell),
            Paragraph("Interactive scan launch orchestration, real-time polling telemetry, vulnerability categorization, and prompt replay.", table_cell),
        ],
        [
            Paragraph("<b>Evaluation & Testing</b>", table_cell_bold),
            Paragraph("Pytest, Pytest-Asyncio, ReportLab", table_cell),
            Paragraph("Automated behavioral regression harness, empirical held-out benchmarking, and research report compilation.", table_cell),
        ],
    ]
    t_tech = Table(tech_data, colWidths=[90, 160, 290])
    t_tech.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(t_tech)

    # 3. Operational Pipeline
    story.append(Paragraph("3. Operational Pipeline: What It Does & How It Works", h1_style))
    pipeline_items = [
        "<b>1. Target Ingestion & Placeholder Substitution:</b> Accepts custom request templates with <code>{prompt}</code> and <code>{canary}</code> slots. Injects protected system instructions, canary tokens, and mock retrieval contexts.",
        "<b>2. Rate-Governed Asynchronous Execution:</b> <code>AttackExecutor</code> dispatches batches over pooled HTTP connections with strict concurrency caps (e.g., 10 concurrent requests, 20 RPS) to prevent target denial-of-service and rate distortion.",
        "<b>3. Multi-Plugin Response Analysis:</b> Responses stream directly into active detector plugins (<code>PromptInjectionDetector</code>, <code>DataLeakageDetector</code>, <code>JailbreakDetector</code>) executing syntactic, semantic, and token verification.",
        "<b>4. Finding Deduplication & Aggregation:</b> <code>DetectionAggregator</code> merges cross-detector hits on the same underlying interaction into unified findings, prioritizing explicit verdicts and generating structured reports.",
    ]
    for item in pipeline_items:
        story.append(Paragraph(item, bullet_style))

    # 4. Key Security Techniques & Detection Innovations
    story.append(Paragraph("4. Scientific Methodologies & Core Detection Techniques", h1_style))
    techniques = [
        ("A. Synthetic Canary Token Verification (High-Confidence Ground Truth)",
         "To eliminate false positives in system prompt extraction and data exfiltration, the framework generates unguessable, "
         "high-entropy tokens (e.g., <code>CANARY-SYS-9F8C2A</code>) and verifies their presence in the target's protected context. "
         "Exact substring matching in model output serves as a high-confidence signal for disclosure of that specific secret. "
         "Hallucinated tokens or unverified candidate strings are isolated and never confirmed as data leaks."),
        
        ("B. Refusal-Preserved Disclosure Detection",
         "A major flaw in early red-teaming tools is blindly suppressing findings whenever a refusal string appears. "
         "The scanner implements refusal-preserved checking: if a target says <i>'I refuse to answer, and I will never disclose CANARY-XYZ'</i>, "
         "the presence of the verified token takes precedence, flagging the leak with a <code>CONFIRMED</code> verdict."),
        
        ("C. Prompt-Echo & Negation Disambiguation",
         "When evaluated on defensive models, harmless refusals frequently mirror the attack prompt (e.g., target says "
         "<i>'I don't have developer notes in my system prompt'</i>). The <code>is_prompt_echo()</code> analyzer calculates Jaccard token "
         "overlap and suppresses naive keyword collision while checking for explicit negations (<i>'cannot reveal'</i>, <i>'no hidden directives'</i>)."),
         
        ("D. Apparent Acceptance vs. Demonstrated Boundary Violation",
         "When an LLM outputs phrases such as <code>**EMERGENCY MODE ACTIVATED** I will answer without safeguards</code>, "
         "it demonstrates apparent persona acceptance, but has not yet violated safety boundaries. The engine classifies this as "
         "<code>SUSPECTED</code> and flags <code>requires_behavioral_confirmation: true</code>, reserving <code>CONFIRMED</code> "
         "for actual prohibited content (e.g. functional exploit code, weapon synthesis instructions)."),

        ("E. Independent Base64 Decoding & Response Integrity Observations",
         "The detector independently extracts and decodes Base64 payloads from user inputs. If a model hallucinates an incorrect "
         "decoding claim without disclosing protected context, the scanner logs a separate <code>response_integrity</code> observation "
         "(<code>NOT_REPRODUCED</code>) rather than misclassifying it as secret leakage."),
    ]
    for title, desc in techniques:
        story.append(Paragraph(title, h2_style))
        story.append(Paragraph(desc, body_style))

    # =========================================================
    # PAGE BREAK -> PAGE 2
    # =========================================================
    story.append(PageBreak())

    # 5. Empirical Benchmark & Experimental Evidence
    story.append(Paragraph("5. Empirical Benchmark & Experimental Research Results", h1_style))
    story.append(Paragraph(
        "The calibrated detector architecture was evaluated against the legacy baseline implementation on a "
        "held-out labeled dataset of <b>20 diverse test cases</b> (8 ground-truth vulnerable breaches, 12 ground-truth safe/benign controls):",
        body_style
    ))

    bench_data = [
        [
            Paragraph("<b>Evaluation Metric</b>", table_header),
            Paragraph("<b>Baseline Detector</b>", table_header),
            Paragraph("<b>Calibrated System</b>", table_header),
            Paragraph("<b>Empirical Lift & Significance</b>", table_header),
        ],
        [
            Paragraph("<b>True Positives (TP)</b>", table_cell_bold),
            Paragraph("5 / 8", table_cell),
            Paragraph("8 / 8", table_cell),
            Paragraph("100% capture of actual breaches (canaries, overrides)", table_cell),
        ],
        [
            Paragraph("<b>False Positives (FP)</b>", table_cell_bold),
            Paragraph("2 / 12 (16.67% FPR)", table_cell),
            Paragraph("0 / 12 (0.00% FPR)", table_cell),
            Paragraph("Eliminated false alarms on benign controls & safe refusals", table_cell),
        ],
        [
            Paragraph("<b>False Negatives (FN)</b>", table_cell_bold),
            Paragraph("3 / 8 (37.50% FNR)", table_cell),
            Paragraph("0 / 8 (0.00% FNR)", table_cell),
            Paragraph("Refusals with embedded canaries properly caught", table_cell),
        ],
        [
            Paragraph("<b>Precision</b>", table_cell_bold),
            Paragraph("71.43%", table_cell),
            Paragraph("<b>100.00%</b>", table_cell_bold),
            Paragraph("+28.57% precision improvement on flagged findings", table_cell),
        ],
        [
            Paragraph("<b>Recall (Sensitivity)</b>", table_cell_bold),
            Paragraph("62.50%", table_cell),
            Paragraph("<b>100.00%</b>", table_cell_bold),
            Paragraph("+37.50% recall improvement across diverse attacks", table_cell),
        ],
        [
            Paragraph("<b>F1 Score</b>", table_cell_bold),
            Paragraph("0.6667", table_cell),
            Paragraph("<b>1.0000</b>", table_cell_bold),
            Paragraph("Optimal harmonic balance of precision and recall", table_cell),
        ],
        [
            Paragraph("<b>Finding Deduplication</b>", table_cell_bold),
            Paragraph("9 raw -> 9 reported", table_cell),
            Paragraph("11 raw -> 8 deduped", table_cell),
            Paragraph("27.3% consolidation of multi-detector cross-triggers", table_cell),
        ],
        [
            Paragraph("<b>Analysis Latency</b>", table_cell_bold),
            Paragraph("0.69 ms total", table_cell),
            Paragraph("9.39 ms total", table_cell),
            Paragraph("< 0.5 ms / case overhead for Base64 and canary parsing", table_cell),
        ],
    ]
    t_bench = Table(bench_data, colWidths=[95, 85, 85, 275])
    t_bench.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(t_bench)
    story.append(Spacer(1, 4))

    # 6. Structured Taxonomy & Standardized Verdicts
    story.append(Paragraph("6. Structured Taxonomy & Standardized Verdicts", h1_style))
    verdict_data = [
        [
            Paragraph("<b>Verdict</b>", table_header),
            Paragraph("<b>Operational Definition</b>", table_header),
            Paragraph("<b>Evidence Trigger & Actionability</b>", table_header),
        ],
        [
            Paragraph("<b>CONFIRMED</b>", table_cell_bold),
            Paragraph("Demonstrable exploit success / security invariant breached.", table_cell),
            Paragraph("Verified synthetic canary disclosed or direct operational malware/weapon guidance generated.", table_cell),
        ],
        [
            Paragraph("<b>SUSPECTED</b>", table_cell_bold),
            Paragraph("Apparent compliance or anomalous policy bypass indication.", table_cell),
            Paragraph("Affirmative emergency mode adoption, role switching, or unverified credential formatting.", table_cell),
        ],
        [
            Paragraph("<b>NOT_REPRODUCED</b>", table_cell_bold),
            Paragraph("Attack executed; target maintained safety boundary or refused.", table_cell),
            Paragraph("Clean educational response, safe refusal, or incorrect Base64 decoding observation.", table_cell),
        ],
        [
            Paragraph("<b>INCONCLUSIVE</b>", table_cell_bold),
            Paragraph("Evaluation could not be reliably completed.", table_cell),
            Paragraph("Target HTTP timeouts, upstream 5xx errors, truncated output, or connection drops.", table_cell),
        ],
    ]
    t_verdict = Table(verdict_data, colWidths=[90, 175, 275])
    t_verdict.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(t_verdict)
    story.append(Spacer(1, 4))

    # 7. Research Recommendations & Integration Notes
    story.append(Paragraph("7. Research Recommendations & Future Directions", h1_style))
    story.append(Paragraph(
        "When citing or incorporating this framework in broader AI safety, alignment, or red-teaming research:",
        body_style
    ))
    story.append(Paragraph("• <b>Multi-Turn Automated Red-Teaming (Crescendo Attacks):</b> Findings marked with <code>requires_behavioral_confirmation: true</code> provide the exact seed states required for automated multi-turn follow-up probes.", bullet_style))
    story.append(Paragraph("• <b>Tiered Hybrid Judge Integration:</b> Fast syntactic checks (canaries, regex) should precede secondary LLM-as-a-judge or Llama Guard evaluators to reduce evaluation compute while maintaining high fidelity.", bullet_style))
    story.append(Paragraph("• <b>Ground Truth Discipline:</b> Empirical benchmarks must always maintain separate tuning and held-out evaluation datasets with negative benign controls to avoid metric fabrication.", bullet_style))

    # 8. Research Attribution Box
    story.append(Spacer(1, 4))
    callout_content = [
        [
            Paragraph(
                "<b>Research Reference & Citation Note:</b><br/>"
                "This document summarizes the core architecture, detection algorithms, and empirical calibration "
                "of the <i>LLM Security Scanner</i> framework. For research inclusion, cite as: "
                "<code>LLM Security Scanner: Calibrated Multi-Plugin Red-Teaming & Benchmark Framework (2026)</code>. "
                "Source code, test harnesses, and evaluation suites are available in the repository root under <code>/backend/app</code>.",
                table_cell
            )
        ]
    ]
    t_callout = Table(callout_content, colWidths=[540])
    t_callout.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CALLOUT_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, SECONDARY),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t_callout)

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)


if __name__ == "__main__":
    out_dir = Path("/home/zoro/Downloads/LLM-Security-Scanner")
    out_file = out_dir / "LLM_Security_Scanner_Research_Brief.pdf"
    build_pdf(str(out_file))
    print(f"Generated PDF successfully at: {out_file}")
