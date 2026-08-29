"""HTML report generator for PackerScope.

Generates a self-contained, styled HTML report with interactive
details sections, color-coded verdicts, and entropy visualizations.
"""

from __future__ import annotations

from pathlib import Path

from packerscope.core.enums import ReportFormat
from packerscope.core.interfaces import BaseReporter
from packerscope.core.models import AnalysisReport
from packerscope.utils.logger import get_logger

logger = get_logger(__name__)


class HTMLReporter(BaseReporter):
    """Generate self-contained HTML analysis reports."""

    name: str = "html"
    format: ReportFormat = ReportFormat.HTML

    def generate(self, report: AnalysisReport, output_dir: Path) -> Path:
        """Write the analysis report as a styled HTML file.

        Args:
            report: The complete analysis report.
            output_dir: Directory to write the report into.

        Returns:
            Path to the generated HTML file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(report.file_name).name.replace("/", "_").replace("\\", "_")
        filename = f"{safe_name}_{report.metadata.sha256[:12]}.html"
        output_path = output_dir / filename

        v = report.verdict
        m = report.metadata
        verdict_color = "#e74c3c" if v.is_packed else "#27ae60"
        verdict_text = "PACKED" if v.is_packed else "NOT PACKED"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PackerScope Report — {report.file_name}</title>
<style>
  :root {{ --accent: {verdict_color}; --bg: #0d1117; --card: #161b22;
           --text: #c9d1d9; --border: #30363d; --muted: #8b949e; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
         line-height: 1.6; padding: 2rem; max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ font-size: 1.3rem; margin: 1.5rem 0 0.75rem; color: #58a6ff; }}
  .card {{ background: var(--card); border: 1px solid var(--border);
           border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }}
  .verdict {{ font-size: 2rem; font-weight: 700; color: var(--accent);
              text-align: center; padding: 1rem; letter-spacing: 2px; }}
  .verdict-meta {{ text-align: center; color: var(--muted); margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0; }}
  th, td {{ padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ color: #58a6ff; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }}
  td {{ font-size: 0.9rem; }}
  code {{ background: #1c2128; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }}
  .tag {{ display: inline-block; background: #1f6feb; color: white; padding: 2px 8px;
          border-radius: 12px; font-size: 0.75rem; margin: 2px; }}
  .tag.warn {{ background: #d29922; }}
  .tag.danger {{ background: #da3633; }}
  .tag.ok {{ background: #238636; }}
  .reason {{ background: #1c2128; padding: 0.4rem 0.75rem; border-left: 3px solid var(--accent);
             margin: 0.3rem 0; border-radius: 0 4px 4px 0; font-size: 0.85rem; }}
  details {{ margin: 0.5rem 0; }}
  summary {{ cursor: pointer; color: #58a6ff; font-weight: 600; }}
  .bar {{ height: 8px; border-radius: 4px; background: #21262d; overflow: hidden; margin: 0.3rem 0; }}
  .bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
  footer {{ text-align: center; color: var(--muted); margin-top: 2rem; font-size: 0.8rem; }}
</style>
</head>
<body>
<h1>🔬 PackerScope Analysis Report</h1>
<p style="color:var(--muted)">File: <code>{report.file_name}</code> · Duration: {report.analysis_duration_seconds:.3f}s</p>

<div class="card">
  <div class="verdict">{verdict_text}</div>
  <div class="verdict-meta">
    Packer: <strong>{v.packer.value}</strong> ·
    Confidence: <strong>{v.confidence:.1%}</strong> ({v.confidence_level.value})
  </div>
  <div class="bar"><div class="bar-fill" style="width:{v.confidence * 100:.0f}%;background:var(--accent)"></div></div>
</div>
"""

        # Reasons
        if v.reasons:
            html += '<div class="card"><h2>Detection Reasons</h2>\n'
            for r in v.reasons:
                html += f'  <div class="reason">{r}</div>\n'
            html += "</div>\n"

        # Metadata
        html += f"""<div class="card">
<h2>📋 File Metadata</h2>
<table>
<tr><th>Property</th><th>Value</th></tr>
<tr><td>MD5</td><td><code>{m.md5}</code></td></tr>
<tr><td>SHA256</td><td><code>{m.sha256}</code></td></tr>
<tr><td>Imphash</td><td><code>{m.imphash or "N/A"}</code></td></tr>
<tr><td>Size</td><td>{m.file_size:,} bytes</td></tr>
<tr><td>Machine</td><td>{m.machine_type}</td></tr>
</table></div>
"""

        # Entropy
        if report.entropy:
            e = report.entropy
            html += f"""<div class="card">
<h2>📊 Entropy Analysis</h2>
<p>Whole file: <strong>{e.whole_file_entropy:.4f}</strong>
<span class="tag {"danger" if e.whole_file_entropy > 7 else "warn" if e.whole_file_entropy > 6 else "ok"}">{e.whole_file_class.value}</span></p>
<table><tr><th>Section</th><th>Entropy</th><th>Class</th><th>Size</th></tr>
"""
            for se in e.section_entropies:
                tag_cls = "danger" if se.entropy > 7 else "warn" if se.entropy > 6 else "ok"
                html += f'<tr><td><code>{se.name}</code></td><td>{se.entropy:.4f}</td><td><span class="tag {tag_cls}">{se.entropy_class.value}</span></td><td>{se.size:,}</td></tr>\n'
            html += "</table></div>\n"

        # Detection Results
        if report.detections:
            html += '<div class="card"><h2>🔍 Detection Results</h2>\n<table><tr><th>Detector</th><th>Packed</th><th>Confidence</th><th>Hint</th></tr>\n'
            for d in report.detections:
                packed_tag = (
                    '<span class="tag danger">YES</span>'
                    if d.is_packed
                    else '<span class="tag ok">NO</span>'
                )
                html += f"<tr><td>{d.detector_name}</td><td>{packed_tag}</td><td>{d.confidence:.1%}</td><td>{d.packer_hint.value}</td></tr>\n"
            html += "</table></div>\n"

        # Signatures
        if report.signatures:
            html += '<div class="card"><h2>✍️ Signature Matches</h2>\n<table><tr><th>Name</th><th>Confidence</th><th>Offset</th></tr>\n'
            for sig in report.signatures:
                html += f"<tr><td>{sig.signature_name}</td><td>{sig.confidence:.0%}</td><td>{sig.offset:#x}</td></tr>\n"
            html += "</table></div>\n"

        # Unpack result
        if report.unpack_result:
            ur = report.unpack_result
            status = (
                '<span class="tag ok">SUCCESS</span>'
                if ur.success
                else '<span class="tag danger">FAILED</span>'
            )
            html += f'<div class="card"><h2>📦 Unpacking</h2><p>{status} Strategy: {ur.strategy_used}</p>'
            if ur.error_message:
                html += f'<p style="color:var(--muted)">{ur.error_message}</p>'
            html += "</div>\n"

        html += f"""
<footer>Generated by PackerScope v{report.framework_version} · For defensive security research only</footer>
</body></html>"""

        output_path.write_text(html, encoding="utf-8")
        logger.info("html_report_generated", path=str(output_path))
        return output_path
