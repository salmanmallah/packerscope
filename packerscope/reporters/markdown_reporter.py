"""Markdown report generator for PackerScope."""

from __future__ import annotations

from pathlib import Path

from packerscope.core.enums import ReportFormat
from packerscope.core.interfaces import BaseReporter
from packerscope.core.models import AnalysisReport
from packerscope.utils.logger import get_logger

logger = get_logger(__name__)


class MarkdownReporter(BaseReporter):
    """Generate analysis reports in Markdown format."""

    name: str = "markdown"
    format: ReportFormat = ReportFormat.MARKDOWN

    def generate(self, report: AnalysisReport, output_dir: Path) -> Path:
        """Write the analysis report as a Markdown file.

        Args:
            report: The complete analysis report.
            output_dir: Directory to write the report into.

        Returns:
            Path to the generated Markdown file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(report.file_name).name.replace("/", "_").replace("\\", "_")
        filename = f"{safe_name}_{report.metadata.sha256[:12]}.md"
        output_path = output_dir / filename

        lines: list[str] = []
        v = report.verdict

        lines.append("# PackerScope Analysis Report")
        lines.append("")
        lines.append(f"**File**: `{report.file_name}`  ")
        lines.append(f"**Path**: `{report.file_path}`  ")
        lines.append(f"**Duration**: {report.analysis_duration_seconds:.3f}s  ")
        lines.append(f"**Framework Version**: {report.framework_version}")
        lines.append("")

        # Verdict
        emoji = "🔴" if v.is_packed else "🟢"
        lines.append(f"## {emoji} Verdict")
        lines.append("")
        lines.append("| Property | Value |")
        lines.append("|---|---|")
        lines.append(f"| **Packed** | {v.is_packed} |")
        lines.append(f"| **Packer** | {v.packer.value} |")
        lines.append(f"| **Confidence** | {v.confidence:.2%} ({v.confidence_level.value}) |")
        lines.append("")

        if v.reasons:
            lines.append("### Reasons")
            for r in v.reasons:
                lines.append(f"- {r}")
            lines.append("")

        # File Metadata
        m = report.metadata
        lines.append("## 📋 File Metadata")
        lines.append("")
        lines.append("| Hash | Value |")
        lines.append("|---|---|")
        lines.append(f"| MD5 | `{m.md5}` |")
        lines.append(f"| SHA1 | `{m.sha1}` |")
        lines.append(f"| SHA256 | `{m.sha256}` |")
        lines.append(f"| Imphash | `{m.imphash or 'N/A'}` |")
        lines.append(f"| Size | {m.file_size:,} bytes |")
        lines.append("")

        # Entropy
        if report.entropy:
            e = report.entropy
            lines.append("## 📊 Entropy Analysis")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|---|---|")
            lines.append(
                f"| Whole file | {e.whole_file_entropy:.4f} ({e.whole_file_class.value}) |"
            )
            lines.append(f"| Max section | {e.max_section_entropy:.4f} |")
            lines.append(f"| Min section | {e.min_section_entropy:.4f} |")
            lines.append(f"| Mean section | {e.mean_section_entropy:.4f} |")
            lines.append("")

            if e.section_entropies:
                lines.append("### Section Entropies")
                lines.append("")
                lines.append("| Section | Entropy | Class | Size |")
                lines.append("|---|---|---|---|")
                for se in e.section_entropies:
                    lines.append(
                        f"| `{se.name}` | {se.entropy:.4f} | {se.entropy_class.value} | {se.size:,} |"
                    )
                lines.append("")

        # Sections
        if report.sections:
            lines.append("## 📦 Sections")
            lines.append("")
            lines.append("| Name | VSize | RSize | Entropy | Exec | Write | RWX |")
            lines.append("|---|---|---|---|---|---|---|")
            for s in report.sections:
                lines.append(
                    f"| `{s.name}` | {s.virtual_size:,} | {s.raw_size:,} | "
                    f"{s.entropy:.4f} | {'✅' if s.is_executable else '❌'} | "
                    f"{'✅' if s.is_writable else '❌'} | {'⚠️' if s.is_rwx else '—'} |"
                )
            lines.append("")

        # Imports
        if report.imports:
            imp = report.imports
            lines.append("## 📥 Import Analysis")
            lines.append("")
            lines.append(f"- **Total imports**: {imp.total_imports}")
            lines.append(f"- **DLL count**: {imp.dll_count}")
            lines.append(f"- **Dynamic loading**: {'Yes ⚠️' if imp.has_dynamic_loading else 'No'}")
            if imp.suspicious_apis:
                lines.append(f"- **Suspicious APIs**: {', '.join(imp.suspicious_apis[:10])}")
            lines.append("")

        # Detection Results
        if report.detections:
            lines.append("## 🔍 Detection Results")
            lines.append("")
            lines.append("| Detector | Method | Packed | Confidence | Packer Hint |")
            lines.append("|---|---|---|---|---|")
            for d in report.detections:
                lines.append(
                    f"| {d.detector_name} | {d.method.value} | "
                    f"{'✅' if d.is_packed else '❌'} | {d.confidence:.2%} | "
                    f"{d.packer_hint.value} |"
                )
            lines.append("")

        # Signature matches
        if report.signatures:
            lines.append("## ✍️ Signature Matches")
            lines.append("")
            for sig in report.signatures:
                lines.append(
                    f"- **{sig.signature_name}** (confidence: {sig.confidence:.0%}, offset: {sig.offset:#x})"
                )
            lines.append("")

        # YARA matches
        if report.yara_matches:
            lines.append("## 🎯 YARA Matches")
            lines.append("")
            for ym in report.yara_matches:
                lines.append(f"- **{ym.rule_name}**: {ym.description}")
            lines.append("")

        # Unpack result
        if report.unpack_result:
            ur = report.unpack_result
            emoji = "✅" if ur.success else "❌"
            lines.append(f"## {emoji} Unpacking Result")
            lines.append("")
            lines.append(f"- **Success**: {ur.success}")
            lines.append(f"- **Strategy**: {ur.strategy_used}")
            if ur.unpacked_path:
                lines.append(f"- **Output**: `{ur.unpacked_path}`")
            if ur.error_message:
                lines.append(f"- **Error**: {ur.error_message}")
            lines.append("")

        # Verification
        if report.verification:
            vr = report.verification
            lines.append("## ✔️ Verification")
            lines.append("")
            lines.append(f"- Checks passed: {vr.checks_passed}/{vr.total_checks}")
            lines.append(f"- Valid PE: {'✅' if vr.is_valid_pe else '❌'}")
            lines.append(f"- Entropy reduced: {'✅' if vr.entropy_reduced else '❌'}")
            lines.append(f"- IAT restored: {'✅' if vr.iat_restored else '❌'}")
            lines.append(f"- Sections normal: {'✅' if vr.sections_normal else '❌'}")
            lines.append("")

        # Errors / Warnings
        if report.errors:
            lines.append("## ⚠️ Errors")
            for err in report.errors:
                lines.append(f"- {err}")
            lines.append("")

        lines.append("---")
        lines.append(f"*Generated by PackerScope v{report.framework_version}*")

        output_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("markdown_report_generated", path=str(output_path))
        return output_path
