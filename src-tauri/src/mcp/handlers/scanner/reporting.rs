// ═══════════════════════════════════════════════════════════════════════
//  Reporting — Aggregate findings into structured reports
//  Generates JSON, Markdown, and summary reports
// ═══════════════════════════════════════════════════════════════════════

use crate::mcp::types::HandlerResult;
use std::collections::HashMap;

pub async fn handle_generate_report(params: &serde_json::Value) -> HandlerResult {
    let findings = params["findings"].as_array()
        .ok_or("findings array is required")?;

    let format = params["format"].as_str().unwrap_or("markdown");
    let title = params["title"].as_str().unwrap_or("WonderSuite Security Report");
    let target = params["target"].as_str().unwrap_or("Unknown Target");

    // Parse findings
    let mut severity_counts: HashMap<String, usize> = HashMap::new();
    let mut type_counts: HashMap<String, usize> = HashMap::new();

    for f in findings {
        if let Some(sev) = f["severity"].as_str() {
            *severity_counts.entry(sev.to_string()).or_insert(0) += 1;
        }
        if let Some(ft) = f["finding_type"].as_str() {
            *type_counts.entry(ft.to_string()).or_insert(0) += 1;
        }
    }

    let total = findings.len();
    let critical = severity_counts.get("critical").copied().unwrap_or(0);
    let high = severity_counts.get("high").copied().unwrap_or(0);
    let medium = severity_counts.get("medium").copied().unwrap_or(0);
    let low = severity_counts.get("low").copied().unwrap_or(0);
    let info = severity_counts.get("info").copied().unwrap_or(0);

    // Risk rating
    let risk_rating = if critical > 0 { "CRITICAL" }
        else if high > 0 { "HIGH" }
        else if medium > 0 { "MEDIUM" }
        else if low > 0 { "LOW" }
        else { "INFORMATIONAL" };

    match format {
        "markdown" => {
            let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
            let mut md = String::new();

            md.push_str(&format!("# {}\n\n", title));
            md.push_str(&format!("**Target:** {}\n", target));
            md.push_str(&format!("**Date:** {}\n", now));
            md.push_str(&format!("**Overall Risk:** {}\n\n", risk_rating));

            md.push_str("## Executive Summary\n\n");
            md.push_str(&format!("A total of **{}** findings were identified:\n\n", total));
            md.push_str(&format!("| Severity | Count |\n|----------|-------|\n"));
            md.push_str(&format!("| 🔴 Critical | {} |\n", critical));
            md.push_str(&format!("| 🟠 High | {} |\n", high));
            md.push_str(&format!("| 🟡 Medium | {} |\n", medium));
            md.push_str(&format!("| 🔵 Low | {} |\n", low));
            md.push_str(&format!("| ⚪ Info | {} |\n\n", info));

            md.push_str("## Finding Types\n\n");
            let mut types: Vec<_> = type_counts.iter().collect();
            types.sort_by(|a, b| b.1.cmp(a.1));
            for (t, c) in &types {
                md.push_str(&format!("- **{}**: {} occurrences\n", t, c));
            }
            md.push_str("\n");

            // Detail each finding
            md.push_str("## Detailed Findings\n\n");
            for (i, f) in findings.iter().enumerate() {
                let sev_icon = match f["severity"].as_str().unwrap_or("") {
                    "critical" => "🔴",
                    "high" => "🟠",
                    "medium" => "🟡",
                    "low" => "🔵",
                    _ => "⚪",
                };
                md.push_str(&format!("### {}. {} {}\n\n", i + 1, sev_icon,
                    f["name"].as_str().unwrap_or("Unknown")));
                md.push_str(&format!("- **Severity:** {}\n", f["severity"].as_str().unwrap_or("")));
                md.push_str(&format!("- **Confidence:** {}\n", f["confidence"].as_str().unwrap_or("")));
                md.push_str(&format!("- **URL:** `{}`\n", f["url"].as_str().unwrap_or("")));
                if let Some(param) = f["parameter"].as_str() {
                    md.push_str(&format!("- **Parameter:** `{}`\n", param));
                }
                if let Some(payload) = f["payload"].as_str() {
                    md.push_str(&format!("- **Payload:** `{}`\n", &payload[..payload.len().min(100)]));
                }
                md.push_str(&format!("\n**Evidence:**\n```\n{}\n```\n\n", f["evidence"].as_str().unwrap_or("")));
                md.push_str(&format!("**Detail:** {}\n\n", f["detail"].as_str().unwrap_or("")));
                md.push_str(&format!("**Remediation:** {}\n\n---\n\n", f["remediation"].as_str().unwrap_or("")));
            }

            Ok(serde_json::json!({
                "format": "markdown",
                "report": md,
                "summary": {
                    "total_findings": total,
                    "risk_rating": risk_rating,
                    "severity_counts": severity_counts,
                },
            }))
        }

        "json" => {
            Ok(serde_json::json!({
                "format": "json",
                "report": {
                    "title": title,
                    "target": target,
                    "date": chrono::Utc::now().to_rfc3339(),
                    "risk_rating": risk_rating,
                    "summary": {
                        "total": total,
                        "severity": severity_counts,
                        "types": type_counts,
                    },
                    "findings": findings,
                },
            }))
        }

        "summary" => {
            Ok(serde_json::json!({
                "format": "summary",
                "target": target,
                "risk_rating": risk_rating,
                "total_findings": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
                "top_types": type_counts,
            }))
        }

        _ => Err(format!("Unknown format: {}. Use: markdown, json, summary", format)),
    }
}
