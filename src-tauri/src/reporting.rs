use serde::{Deserialize, Serialize};

/// WonderSuite Reporting Engine
/// Generates HTML and JSON vulnerability reports from scan findings.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    pub format: String,       // "html", "json", "xml"
    pub title: String,
    pub include_evidence: bool,
    pub include_remediation: bool,
    pub severity_filter: Option<Vec<String>>,
    pub confidence_filter: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFinding {
    pub name: String,
    pub severity: String,
    pub confidence: String,
    pub url: String,
    pub parameter: Option<String>,
    pub detail: String,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
}

/// Generate an HTML vulnerability report.
pub fn generate_html_report(title: &str, findings: &[ReportFinding], config: &ReportConfig) -> String {
    let severity_order = |s: &str| match s {
        "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4
    };

    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));

    // Filter
    let filtered: Vec<&ReportFinding> = sorted.iter().filter(|f| {
        if let Some(ref sevs) = config.severity_filter {
            if !sevs.contains(&f.severity) { return false; }
        }
        if let Some(ref confs) = config.confidence_filter {
            if !confs.contains(&f.confidence) { return false; }
        }
        true
    }).collect();

    let critical = filtered.iter().filter(|f| f.severity == "critical").count();
    let high = filtered.iter().filter(|f| f.severity == "high").count();
    let medium = filtered.iter().filter(|f| f.severity == "medium").count();
    let low = filtered.iter().filter(|f| f.severity == "low").count();
    let info = filtered.iter().filter(|f| f.severity == "info").count();

    let findings_html: String = filtered.iter().enumerate().map(|(i, f)| {
        let sev_color = match f.severity.as_str() {
            "critical" => "#dc2626", "high" => "#ef4444", "medium" => "#f59e0b", "low" => "#3b82f6", _ => "#6b7280"
        };
        let evidence_section = if config.include_evidence {
            f.evidence.as_ref().map(|e| format!(
                "<div class='evidence'><h4>Evidence</h4><pre>{}</pre></div>", html_escape(e)
            )).unwrap_or_default()
        } else { String::new() };
        let remediation_section = if config.include_remediation {
            f.remediation.as_ref().map(|r| format!(
                "<div class='remediation'><h4>Remediation</h4><p>{}</p></div>", html_escape(r)
            )).unwrap_or_default()
        } else { String::new() };
        let param_info = f.parameter.as_ref().map(|p| format!("<span class='param'>Parameter: {}</span>", html_escape(p))).unwrap_or_default();

        format!(r#"
        <div class="finding">
            <div class="finding-header">
                <span class="finding-num">#{}</span>
                <span class="sev-badge" style="background:{};">{}</span>
                <span class="finding-name">{}</span>
                <span class="conf-badge">{}</span>
            </div>
            <div class="finding-url">{}</div>
            {}
            <div class="finding-detail"><p>{}</p></div>
            {}
            {}
        </div>"#, i + 1, sev_color, f.severity.to_uppercase(), html_escape(&f.name),
            f.confidence, html_escape(&f.url), param_info, html_escape(&f.detail),
            evidence_section, remediation_section)
    }).collect();

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title} — WonderSuite Security Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; }}
.header {{ text-align: center; padding: 32px 0; border-bottom: 1px solid #1e293b; margin-bottom: 24px; }}
.header h1 {{ font-size: 28px; color: #f1f5f9; margin-bottom: 8px; }}
.header .subtitle {{ color: #94a3b8; font-size: 14px; }}
.summary {{ display: flex; gap: 16px; justify-content: center; margin: 24px 0; flex-wrap: wrap; }}
.summary-card {{ background: #1e293b; border-radius: 8px; padding: 16px 24px; text-align: center; min-width: 100px; }}
.summary-card .count {{ font-size: 28px; font-weight: 700; }}
.summary-card .label {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-top: 4px; }}
.finding {{ background: #1e293b; border-radius: 8px; margin-bottom: 16px; padding: 20px; border-left: 4px solid #334155; }}
.finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }}
.finding-num {{ color: #64748b; font-size: 12px; font-weight: 600; }}
.sev-badge {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; }}
.finding-name {{ font-size: 16px; font-weight: 600; color: #f1f5f9; }}
.conf-badge {{ font-size: 10px; color: #94a3b8; background: #334155; padding: 2px 6px; border-radius: 3px; }}
.finding-url {{ font-family: monospace; font-size: 12px; color: #60a5fa; margin-bottom: 8px; word-break: break-all; }}
.param {{ font-size: 11px; color: #f59e0b; display: inline-block; margin-bottom: 8px; }}
.finding-detail {{ font-size: 13px; color: #cbd5e1; line-height: 1.6; }}
.evidence {{ background: #0f172a; border-radius: 6px; padding: 12px; margin-top: 12px; }}
.evidence h4 {{ font-size: 11px; color: #64748b; text-transform: uppercase; margin-bottom: 6px; }}
.evidence pre {{ font-family: monospace; font-size: 12px; color: #e2e8f0; white-space: pre-wrap; word-break: break-all; }}
.remediation {{ margin-top: 12px; padding: 12px; background: #0c2d1c; border-radius: 6px; border-left: 3px solid #22c55e; }}
.remediation h4 {{ font-size: 11px; color: #22c55e; text-transform: uppercase; margin-bottom: 6px; }}
.remediation p {{ font-size: 13px; color: #86efac; }}
.footer {{ text-align: center; padding: 24px 0; color: #475569; font-size: 12px; border-top: 1px solid #1e293b; margin-top: 24px; }}
</style>
</head>
<body>
<div class="header">
    <h1>{title}</h1>
    <div class="subtitle">WonderSuite Security Report • {total} findings</div>
</div>
<div class="summary">
    <div class="summary-card"><div class="count" style="color:#dc2626">{critical}</div><div class="label">Critical</div></div>
    <div class="summary-card"><div class="count" style="color:#ef4444">{high}</div><div class="label">High</div></div>
    <div class="summary-card"><div class="count" style="color:#f59e0b">{medium}</div><div class="label">Medium</div></div>
    <div class="summary-card"><div class="count" style="color:#3b82f6">{low}</div><div class="label">Low</div></div>
    <div class="summary-card"><div class="count" style="color:#6b7280">{info}</div><div class="label">Info</div></div>
</div>
{findings_html}
<div class="footer">Generated by WonderSuite • {title}</div>
</body></html>"#, title=html_escape(title), total=filtered.len(), critical=critical, high=high,
    medium=medium, low=low, info=info, findings_html=findings_html)
}

/// Generate a JSON vulnerability report.
pub fn generate_json_report(title: &str, findings: &[ReportFinding]) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "report": {
            "title": title,
            "generator": "WonderSuite",
            "version": "1.0",
            "total_findings": findings.len(),
            "severity_summary": {
                "critical": findings.iter().filter(|f| f.severity == "critical").count(),
                "high": findings.iter().filter(|f| f.severity == "high").count(),
                "medium": findings.iter().filter(|f| f.severity == "medium").count(),
                "low": findings.iter().filter(|f| f.severity == "low").count(),
                "info": findings.iter().filter(|f| f.severity == "info").count(),
            },
            "findings": findings,
        }
    })).unwrap_or_default()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
