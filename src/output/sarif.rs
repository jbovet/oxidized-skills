use crate::finding::{AuditReport, Finding, Severity};
use serde_sarif::sarif::{
    ArtifactLocation, Location, Message, MultiformatMessageString, PhysicalLocation, Region,
    ReportingDescriptor, Result as SarifResult, ResultLevel, Run, Sarif, Tool, ToolComponent,
};
use std::collections::HashMap;

pub fn format(report: &AuditReport) -> String {
    let all_findings: Vec<&Finding> = report
        .findings
        .iter()
        .chain(report.suppressed.iter())
        .collect();

    // Collect unique rules
    let mut rule_map: HashMap<&str, &Finding> = HashMap::new();
    for f in &all_findings {
        rule_map.entry(f.rule_id.as_str()).or_insert(f);
    }

    let mut rule_ids: Vec<&str> = rule_map.keys().copied().collect();
    rule_ids.sort();

    let rule_index: HashMap<&str, i64> = rule_ids
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, i as i64))
        .collect();

    let rules: Vec<ReportingDescriptor> = rule_ids
        .iter()
        .map(|id| {
            let f = rule_map[id];
            let mut rule = ReportingDescriptor::builder().id(id.to_string()).build();
            rule.short_description = Some(
                MultiformatMessageString::builder()
                    .text(f.message.clone())
                    .build(),
            );
            if let Some(ref rem) = f.remediation {
                rule.help = Some(
                    MultiformatMessageString::builder()
                        .text(rem.clone())
                        .build(),
                );
            }
            rule
        })
        .collect();

    let results: Vec<SarifResult> = all_findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Error => ResultLevel::Error,
                Severity::Warning => ResultLevel::Warning,
                Severity::Info => ResultLevel::Note,
            };

            let mut result = SarifResult::builder()
                .message(Message::builder().text(f.message.clone()).build())
                .build();

            result.rule_id = Some(f.rule_id.clone());
            result.level = Some(level);
            result.rule_index = rule_index.get(f.rule_id.as_str()).copied();

            if let Some(ref file) = f.file {
                let uri = file.to_string_lossy().replace('\\', "/");

                let mut location = Location::builder().build();
                let mut physical = PhysicalLocation::builder().build();

                physical.artifact_location = Some(ArtifactLocation::builder().uri(uri).build());

                if let Some(line) = f.line {
                    physical.region = Some(Region::builder().start_line(line as i64).build());
                }

                location.physical_location = Some(physical);
                result.locations = Some(vec![location]);
            }

            result
        })
        .collect();

    let driver = ToolComponent::builder()
        .name("oxidized-skills")
        .version(env!("CARGO_PKG_VERSION").to_string())
        .rules(rules)
        .build();

    let tool = Tool::builder().driver(driver).build();

    let run = Run::builder().tool(tool).results(results).build();

    let sarif = Sarif::builder().version("2.1.0").runs(vec![run]).build();

    serde_json::to_string_pretty(&sarif).expect("SARIF serialization failed")
}
