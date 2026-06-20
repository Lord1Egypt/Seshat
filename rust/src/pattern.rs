//! Pattern model + loader — mirrors `seshat.patterns`, reads the SAME YAML files.

use fancy_regex::Regex;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
struct RawTests {
    #[serde(default)]
    positive: Vec<String>,
    #[serde(default)]
    negative: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawDetector {
    #[serde(rename = "type", default)]
    _dtype: Option<String>,
    pattern: String,
    #[serde(default = "default_conf")]
    confidence: f64,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    multiline: bool,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    forbids: Vec<String>,
}

fn default_conf() -> f64 {
    0.5
}

#[derive(Debug, Deserialize)]
struct RawPattern {
    id: String,
    name: String,
    severity: String,
    category: String,
    detectors: Vec<RawDetector>,
    #[serde(default)]
    tests: RawTests,
}

/// A compiled detector ready to run.
pub struct Detector {
    pub scope: String, // "file" | "function"
    pub multiline: bool,
    pub confidence: f64,
    pub rx: Regex,
    pub req: Vec<Regex>,
    pub forb: Vec<Regex>,
}

/// A compiled pattern.
pub struct Pattern {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub category: String,
    pub detectors: Vec<Detector>,
    pub positive: Vec<String>,
    pub negative: Vec<String>,
}

fn compile_all(src: &[String]) -> Result<Vec<Regex>, String> {
    src.iter()
        .map(|p| Regex::new(p).map_err(|e| format!("bad regex {p:?}: {e}")))
        .collect()
}

impl Pattern {
    fn from_raw(raw: RawPattern) -> Result<Pattern, String> {
        let mut detectors = Vec::with_capacity(raw.detectors.len());
        for d in raw.detectors {
            detectors.push(Detector {
                scope: d.scope.unwrap_or_else(|| "file".to_string()),
                multiline: d.multiline,
                confidence: d.confidence,
                rx: Regex::new(&d.pattern).map_err(|e| format!("bad regex {:?}: {e}", d.pattern))?,
                req: compile_all(&d.requires)?,
                forb: compile_all(&d.forbids)?,
            });
        }
        Ok(Pattern {
            id: raw.id,
            name: raw.name,
            severity: raw.severity,
            category: raw.category,
            detectors,
            positive: raw.tests.positive,
            negative: raw.tests.negative,
        })
    }
}

/// Load + compile every `*.yaml` pattern under `dir`, sorted by id.
pub fn load_dir(dir: &Path) -> Result<Vec<Pattern>, String> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            matches!(p.extension().and_then(|s| s.to_str()), Some("yaml") | Some("yml"))
        })
        .collect();
    files.sort();

    let mut patterns = Vec::with_capacity(files.len());
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let raw: RawPattern =
            serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
        patterns.push(Pattern::from_raw(raw)?);
    }
    patterns.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(patterns)
}
