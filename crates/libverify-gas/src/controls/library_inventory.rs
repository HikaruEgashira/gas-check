use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

pub struct LibraryInventoryControl {
    gas: Arc<GasProjectEvidence>,
}

impl LibraryInventoryControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for LibraryInventoryControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-library-inventory")
    }

    fn description(&self) -> &'static str {
        "All external library dependencies must be inventoried"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Declare all library dependencies explicitly in appsscript.json")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        // This control always satisfies if libraries are declared in the manifest.
        // It's informational — providing visibility into the dependency surface.
        let libs: Vec<String> = self
            .gas
            .libraries
            .iter()
            .map(|l| format!("{}@{} ({})", l.user_symbol, l.version, l.library_id))
            .collect();

        vec![ControlFinding::satisfied(
            self.id(),
            format!("{} library(ies) inventoried from manifest", libs.len()),
            libs,
        )]
    }
}
