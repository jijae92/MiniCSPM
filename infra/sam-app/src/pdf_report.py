"""PDF report generation for Mini-CSPM."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from typing import Optional

from models import ExecutionResult
from settings import Settings
import html_report
import s3io

try:  # pragma: no cover - optional dependency
    from weasyprint import HTML  # type: ignore
except ImportError:  # pragma: no cover - handled gracefully in _render_with_weasyprint
    HTML = None

LOGGER = logging.getLogger(__name__)


def write_pdf(result: ExecutionResult, settings: Settings) -> Optional[str]:
    """Render the PDF version of the HTML report and upload it to S3."""
    html_body = html_report.render_html(result=result, settings=settings)
    pdf_bytes = render_pdf_bytes(html_body, settings=settings)
    if pdf_bytes is None:
        LOGGER.info("PDF rendering skipped; no renderer available.")
        return None

    key = s3io.build_report_key(settings.pdf_prefix, result, "pdf")
    s3io.put_object(key=key, body=pdf_bytes, content_type="application/pdf")
    return key


def render_pdf_bytes(html_body: str, settings: Settings) -> Optional[bytes]:
    """Convert HTML content to PDF using WeasyPrint or wkhtmltopdf."""
    if HTML is not None:
        try:
            return HTML(string=html_body).write_pdf()
        except Exception as exc:  # pragma: no cover - defensive guard
            LOGGER.warning("WeasyPrint rendering failed: %s", exc)

    wkhtmltopdf_path = settings.wkhtmltopdf_path if hasattr(settings, "wkhtmltopdf_path") else None
    if not wkhtmltopdf_path:
        wkhtmltopdf_path = os.getenv("WKHTMLTOPDF_PATH") or "wkhtmltopdf"

    wkhtmltopdf_path = _resolve_binary(wkhtmltopdf_path)
    if not wkhtmltopdf_path:
        return None

    return _render_with_wkhtmltopdf(html_body, wkhtmltopdf_path)


def _resolve_binary(candidate: str) -> Optional[str]:
    if os.path.isabs(candidate) and os.path.exists(candidate):
        return candidate

    resolved = subprocess.run(
        ["which", candidate],
        check=False,
        capture_output=True,
        text=True,
    )
    if resolved.returncode == 0:
        path = resolved.stdout.strip()
        if path:
            return path
    return None


def _render_with_wkhtmltopdf(html_body: str, wkhtmltopdf_path: str) -> Optional[bytes]:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp_html:
        tmp_html.write(html_body.encode("utf-8"))
        tmp_html.flush()
        tmp_html_path = tmp_html.name

    try:
        process = subprocess.run(
            [wkhtmltopdf_path, "--quiet", tmp_html_path, "-"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.returncode != 0:
            LOGGER.warning("wkhtmltopdf failed: %s", process.stderr.decode("utf-8", errors="ignore"))
            return None
        return process.stdout
    finally:
        try:
            os.unlink(tmp_html_path)
        except FileNotFoundError:  # pragma: no cover
            pass
