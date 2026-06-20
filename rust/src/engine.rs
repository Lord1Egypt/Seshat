//! The matcher — a faithful port of `seshat.engine`.
//!
//! Same mechanics, so findings are identical to the Python engine:
//! - `scope=file`  → per-line match over the whole source
//! - `scope=function` → match inside each brace-balanced function body
//!   (including `receive`/`fallback`); flag once, at the first matching line
//! - `multiline` → match over the whole source, line taken from match start
//! - `requires` (all present in scope) / `forbids` (none present)
//! - confidence threshold + per-(pattern, line) dedup, highest confidence wins

use std::collections::HashMap;

use fancy_regex::Regex;

use crate::pattern::{Detector, Pattern};

#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub pattern_id: String,
    pub severity: String,
    pub confidence: f64,
    pub line: usize,
}

fn rx_match(rx: &Regex, hay: &str) -> bool {
    rx.is_match(hay).unwrap_or(false)
}

fn all_present(rxs: &[Regex], text: &str) -> bool {
    rxs.iter().all(|r| rx_match(r, text))
}

fn any_present(rxs: &[Regex], text: &str) -> bool {
    rxs.iter().any(|r| rx_match(r, text))
}

/// `(function_text, base_line)` for each function body. Mirrors
/// `iter_function_regions` in Python (keyword incl. receive/fallback, brace
/// balanced, declarations skipped).
fn function_regions(text: &str) -> Vec<(&str, usize)> {
    let kw = Regex::new(r"\b(?:function|receive|fallback)\b").unwrap();
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut regions = Vec::new();

    let mut search_from = 0usize;
    while let Ok(Some(m)) = kw.find_from_pos(text, search_from) {
        let start = m.start();
        search_from = m.end();

        // find the body-opening brace, skipping the signature's parens
        let mut j = m.end();
        let mut depth_paren = 0i32;
        let mut brace: Option<usize> = None;
        while j < n {
            match bytes[j] {
                b'(' => depth_paren += 1,
                b')' => depth_paren -= 1,
                b';' if depth_paren <= 0 => break, // declaration, no body
                b'{' if depth_paren <= 0 => {
                    brace = Some(j);
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        let bstart = match brace {
            Some(b) => b,
            None => continue,
        };

        // balance braces
        let mut depth = 0i32;
        let mut k = bstart;
        let mut end = n;
        while k < n {
            match bytes[k] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = k + 1;
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
        let base_line = text[..start].matches('\n').count() + 1;
        regions.push((&text[start..end], base_line));
    }
    regions
}

fn detector_hits(det: &Detector, text: &str) -> Vec<usize> {
    if det.scope == "function" {
        let mut hits = Vec::new();
        for (region, base_line) in function_regions(text) {
            if !det.req.is_empty() && !all_present(&det.req, region) {
                continue;
            }
            if !det.forb.is_empty() && any_present(&det.forb, region) {
                continue;
            }
            for (idx, line) in region.split('\n').enumerate() {
                if rx_match(&det.rx, line) {
                    hits.push(base_line + idx);
                    break; // flag the function once
                }
            }
        }
        return hits;
    }

    // file scope: requires/forbids over the whole source
    if !det.req.is_empty() && !all_present(&det.req, text) {
        return Vec::new();
    }
    if !det.forb.is_empty() && any_present(&det.forb, text) {
        return Vec::new();
    }

    if det.multiline {
        let mut hits = Vec::new();
        let mut from = 0usize;
        while let Ok(Some(m)) = det.rx.find_from_pos(text, from) {
            hits.push(text[..m.start()].matches('\n').count() + 1);
            from = if m.end() > m.start() { m.end() } else { m.end() + 1 };
            if from > text.len() {
                break;
            }
        }
        return hits;
    }

    let mut hits = Vec::new();
    for (idx, line) in text.split('\n').enumerate() {
        if rx_match(&det.rx, line) {
            hits.push(idx + 1);
        }
    }
    hits
}

/// Scan normalized source, returning deduped findings sorted by (line, id).
pub fn scan_source(text: &str, patterns: &[Pattern], min_confidence: f64) -> Vec<Finding> {
    let mut best: HashMap<(String, usize), Finding> = HashMap::new();
    for pat in patterns {
        for det in &pat.detectors {
            if det.confidence < min_confidence {
                continue;
            }
            for line in detector_hits(det, text) {
                let key = (pat.id.clone(), line);
                let cand = Finding {
                    pattern_id: pat.id.clone(),
                    severity: pat.severity.clone(),
                    confidence: det.confidence,
                    line,
                };
                match best.get(&key) {
                    Some(prev) if prev.confidence >= cand.confidence => {}
                    _ => {
                        best.insert(key, cand);
                    }
                }
            }
        }
    }
    let mut out: Vec<Finding> = best.into_values().collect();
    out.sort_by(|a, b| a.line.cmp(&b.line).then(a.pattern_id.cmp(&b.pattern_id)));
    out
}
