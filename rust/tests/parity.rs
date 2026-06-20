//! Fixture parity: the Rust engine must flag every pattern's positive fixture
//! and stay quiet on its negative — exactly like the Python harness. This proves
//! the Rust core produces identical findings to Python on the baseline corpus
//! (the inline pattern fixtures).

use std::path::PathBuf;

use seshat_rs::{engine, normalize, pattern};

fn catalog_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("src")
        .join("seshat")
        .join("catalog")
}

fn fires(src: &str, pat: &pattern::Pattern) -> bool {
    let text = normalize::strip_comments_and_strings(src);
    // scan with ONLY this pattern (slice of one)
    let one = std::slice::from_ref(pat);
    engine::scan_source(&text, one, 0.0)
        .iter()
        .any(|f| f.pattern_id == pat.id)
}

#[test]
fn catalog_loads_and_has_100_plus() {
    let pats = pattern::load_dir(&catalog_dir()).expect("load catalog");
    assert!(pats.len() >= 100, "expected 100+ patterns, got {}", pats.len());
}

#[test]
fn every_pattern_fixture_passes() {
    let pats = pattern::load_dir(&catalog_dir()).expect("load catalog");
    let mut failures = Vec::new();
    for pat in &pats {
        for (i, src) in pat.positive.iter().enumerate() {
            if !fires(src, pat) {
                failures.push(format!("{}: positive #{} did not fire", pat.id, i + 1));
            }
        }
        for (i, src) in pat.negative.iter().enumerate() {
            if fires(src, pat) {
                failures.push(format!("{}: negative #{} false-positived", pat.id, i + 1));
            }
        }
    }
    assert!(failures.is_empty(), "parity failures:\n{}", failures.join("\n"));
}

#[test]
fn clean_erc20_zero_critical() {
    let clean = r#"
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract MyToken is ERC20, Ownable {
    constructor() ERC20("MyToken", "MTK") { _mint(msg.sender, 1000); }
    function mint(address to, uint256 amount) external onlyOwner { _mint(to, amount); }
}
"#;
    let pats = pattern::load_dir(&catalog_dir()).expect("load catalog");
    let text = normalize::strip_comments_and_strings(clean);
    let finds = engine::scan_source(&text, &pats, 0.0);
    let crit: Vec<_> = finds.iter().filter(|f| f.severity == "critical").collect();
    assert!(crit.is_empty(), "clean ERC-20 raised critical flags: {crit:?}");
}
