#!/usr/bin/env python3
"""Generator for the Seshat pattern catalog.

This emits the canonical YAML pattern files under ``patterns/catalog/``. The
YAML files are the source of truth the engine loads; this script is committed
for provenance and to regenerate the set consistently. Run from the repo root:

    python tools/gen_catalog.py

Every pattern ships inline TP/FP fixtures; ``python -m seshat patterns
--validate`` (and the test suite) prove each one fires on its positive and
stays quiet on its negative.
"""
from __future__ import annotations

from pathlib import Path

# Catalog lives INSIDE the package so it ships as package-data (offline install).
OUT = Path(__file__).resolve().parent.parent / "src" / "seshat" / "catalog"

# A vanilla, safe contract used as the negative for most token-smell patterns.
CLEAN = ("contract Safe { uint256 private value; "
         "function getValue() external view returns (uint256) { return value; } }")

GUARDS = ["only[A-Za-z]\\w*", "hasRole", "_checkRole", "_checkOwner",
          "require\\s*\\(\\s*msg\\.sender", "msg\\.sender\\s*==\\s*owner"]


def det(pattern, conf, *, type="regex", scope="file", requires=None, forbids=None,
        multiline=False, desc="", rec=""):
    return {
        "type": type, "pattern": pattern, "confidence": conf, "scope": scope,
        "requires": requires or [], "forbids": forbids or [],
        "multiline": multiline, "description": desc, "recommendation": rec,
    }


def P(id, name, sev, cat, swc, cwe, conf, detectors, pos, neg):
    return dict(id=id, name=name, severity=sev, category=cat, swc=swc, cwe=cwe,
                confidence=conf, detectors=detectors, pos=pos, neg=neg)


PATTERNS = []
add = PATTERNS.append

# ----------------------------------------------------------------- ACCESS_CONTROL
add(P("P001", "Unprotected Mint", "critical", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.8,
      [det(r"function\s+\w*[mM]int\w*\s*\(", 0.8, type="function_signature", scope="function",
           requires=[r"\b(public|external)\b"], forbids=GUARDS + ["MINTER_ROLE"],
           desc="Public/external mint without an owner/role guard")],
      ["contract C { mapping(address=>uint) b; function mint(address to, uint a) public { b[to]+=a; } }"],
      ["contract C { mapping(address=>uint) b; function mint(address to, uint a) public onlyOwner { b[to]+=a; } }",
       "contract C { mapping(address=>uint) b; function _mint(address to, uint a) internal { b[to]+=a; } }"]))

add(P("P002", "Selfdestruct Anyone", "critical", "ACCESS_CONTROL", "SWC-106", "CWE-284", 0.8,
      [det(r"selfdestruct\s*\(", 0.8, type="ast", scope="function", forbids=GUARDS,
           desc="selfdestruct reachable without an access guard")],
      ["contract C { function kill() public { selfdestruct(payable(msg.sender)); } }"],
      ["contract C { address owner; function kill() public onlyOwner { selfdestruct(payable(owner)); } }", CLEAN]))

add(P("P005", "tx.origin Authentication", "high", "ACCESS_CONTROL", "SWC-115", "CWE-477", 0.85,
      [det(r"(require\s*\(\s*tx\.origin|tx\.origin\s*==|==\s*tx\.origin)", 0.85,
           desc="Authorization compared against tx.origin")],
      ["contract C { address owner; function f() public view { require(tx.origin == owner); } }"],
      ["contract C { function f() public view { require(msg.sender != address(0)); } }", CLEAN]))

add(P("P014", "Unsafe Ownership Renounce", "medium", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.5,
      [det(r"function\s+renounceOwnership\s*\(", 0.5, desc="renounceOwnership left enabled")],
      ["contract C { function renounceOwnership() public { } }"],
      [CLEAN]))

add(P("P018", "Missing Access Control On Setter", "high", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.6,
      [det(r"function\s+set[A-Z]\w*\s*\(", 0.6, type="function_signature", scope="function",
           requires=[r"\b(public|external)\b"], forbids=GUARDS,
           desc="State-changing setter without an access guard")],
      ["contract C { uint fee; function setFee(uint f) public { fee=f; } }"],
      ["contract C { uint fee; function setFee(uint f) public onlyOwner { fee=f; } }", CLEAN]))

add(P("P021", "Unprotected Initializer", "critical", "ACCESS_CONTROL", "SWC-118", "CWE-665", 0.75,
      [det(r"function\s+initialize\w*\s*\(", 0.75, type="function_signature", scope="function",
           requires=[r"\b(public|external)\b"],
           forbids=["initializer", "onlyInitializing", "_disableInitializers"] + GUARDS,
           desc="initialize() callable by anyone")],
      ["contract C { address owner; function initialize(address o) public { owner=o; } }"],
      ["contract C { address owner; function initialize(address o) public initializer { owner=o; } }", CLEAN]))

add(P("P022", "Role Admin Hijack", "critical", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.6,
      [det(r"_setRoleAdmin\s*\(", 0.6, type="ast", scope="function", forbids=GUARDS,
           desc="_setRoleAdmin reachable without a guard")],
      ["contract C { function pwn(bytes32 a, bytes32 b) public { _setRoleAdmin(a, b); } }"],
      ["contract C { function pwn(bytes32 a, bytes32 b) public onlyOwner { _setRoleAdmin(a, b); } }", CLEAN]))

add(P("P023", "Ownership Transfer Without Two-Step", "high", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.5,
      [det(r"function\s+transferOwnership\b", 0.5, forbids=["pendingOwner", "acceptOwnership", "Ownable2Step"],
           desc="One-step ownership transfer (no pending/accept)")],
      ["contract C { address owner; function transferOwnership(address n) public onlyOwner { owner=n; } }"],
      ["contract C { address owner; address pendingOwner; function transferOwnership(address n) public onlyOwner { pendingOwner=n; } function acceptOwnership() public { } }", CLEAN]))

add(P("P024", "Pausable Without Unpause Guard", "high", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.55,
      [det(r"function\s+unpause\s*\(", 0.55, type="function_signature", scope="function",
           requires=[r"\b(public|external)\b"], forbids=GUARDS, desc="unpause() without a guard")],
      ["contract C { bool p; function unpause() public { p=false; } }"],
      ["contract C { bool p; function unpause() public onlyOwner { p=false; } }", CLEAN]))

add(P("P101", "Unprotected Fund Sweep", "high", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.7,
      [det(r"function\s+(withdraw|sweep|rescue|recover)\w*\s*\(", 0.7, type="function_signature",
           scope="function", requires=[r"\b(public|external)\b", r"\.(transfer|call|send)\b"],
           forbids=GUARDS, desc="Fund-moving sweep/withdraw without a guard")],
      ["contract C { function sweep(address payable t) public { t.transfer(address(this).balance); } }"],
      ["contract C { function sweep(address payable t) public onlyOwner { t.transfer(address(this).balance); } }", CLEAN]))

add(P("P102", "Unprotected Admin Setter", "critical", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.75,
      [det(r"function\s+set(Owner|Admin|Governance|Authority)\w*\s*\(", 0.75, type="function_signature",
           scope="function", requires=[r"\b(public|external)\b"], forbids=GUARDS,
           desc="Privileged role setter without a guard")],
      ["contract C { address admin; function setAdmin(address a) public { admin=a; } }"],
      ["contract C { address admin; function setAdmin(address a) public onlyOwner { admin=a; } }", CLEAN]))

add(P("P103", "Hardcoded Privileged Address", "medium", "ACCESS_CONTROL", "SWC-105", "CWE-798", 0.5,
      [det(r"address\s+(public\s+|private\s+|internal\s+|constant\s+)*\w*(owner|admin|treasury|deployer)\w*\s*=\s*0x[0-9a-fA-F]{40}",
           0.5, desc="Privileged role hardcoded to a literal address")],
      ["contract C { address owner = 0x1111111111111111111111111111111111111111; }"],
      [CLEAN]))

add(P("P104", "UUPS Authorize Upgrade Without Guard", "critical", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.7,
      [det(r"function\s+_authorizeUpgrade\s*\(", 0.7, type="ast", scope="function",
           forbids=GUARDS + ["onlyProxy"], desc="_authorizeUpgrade with no access guard")],
      ["contract C { function _authorizeUpgrade(address n) internal { } }"],
      ["contract C { function _authorizeUpgrade(address n) internal onlyOwner { } }", CLEAN]))

add(P("P105", "Unprotected Role Grant", "high", "ACCESS_CONTROL", "SWC-105", "CWE-284", 0.65,
      [det(r"grantRole\s*\(", 0.65, type="ast", scope="function",
           requires=[r"\b(public|external)\b"], forbids=GUARDS + ["onlyRole"],
           desc="grantRole wrapper callable without a guard")],
      ["contract C { function giveRole(bytes32 r, address a) public { grantRole(r, a); } }"],
      ["contract C { function giveRole(bytes32 r, address a) public onlyRole(bytes32(0)) { grantRole(r, a); } }", CLEAN]))

# --------------------------------------------------------------------- REENTRANCY
add(P("P003", "Reentrancy", "critical", "REENTRANCY", "SWC-107", "CWE-841", 0.6,
      [det(r"\.call\{[^}]*value", 0.6, type="ast", scope="function", forbids=["nonReentrant"],
           desc="Value-sending low-level call without a reentrancy guard")],
      ['contract C { mapping(address=>uint) bal; function withdraw() public { uint a=bal[msg.sender]; (bool ok,)=msg.sender.call{value:a}(""); bal[msg.sender]=0; } }'],
      ['contract C { mapping(address=>uint) bal; function withdraw() public nonReentrant { uint a=bal[msg.sender]; bal[msg.sender]=0; (bool ok,)=msg.sender.call{value:a}(""); } }', CLEAN]))

add(P("P025", "Cross-Function Reentrancy", "critical", "REENTRANCY", "SWC-107", "CWE-841", 0.55,
      [det(r"\.call\{[^}]*value", 0.55, type="ast", scope="function", forbids=["nonReentrant"],
           requires=[r"\w+\[[^\]]*\]\s*[-+]?="], desc="Value call alongside mapping state writes, no guard")],
      ['contract C { mapping(address=>uint) b; function withdraw() public { (bool ok,)=msg.sender.call{value:b[msg.sender]}(""); b[msg.sender]=0; } }'],
      ['contract C { mapping(address=>uint) b; function withdraw() public nonReentrant { b[msg.sender]=0; (bool ok,)=msg.sender.call{value:1}(""); } }', CLEAN]))

add(P("P026", "Read-Only Reentrancy", "high", "REENTRANCY", "SWC-107", "CWE-841", 0.45,
      [det(r"view[^{;]*\{[^}]*address\(this\)\.balance", 0.45, multiline=True,
           desc="View price/accounting derived from live balance (read-only reentrancy)")],
      ["contract C { function price() external view returns (uint) { return address(this).balance / 1; } }"],
      [CLEAN]))

add(P("P027", "Cross-Contract Reentrancy", "critical", "REENTRANCY", "SWC-107", "CWE-841", 0.5,
      [det(r"\.call\s*\(", 0.5, type="ast", scope="function", forbids=["nonReentrant"],
           requires=[r"\w+\s*=\s*[^=]"], desc="Low-level call with state write, no reentrancy guard")],
      ['contract C { uint s; function f(address t) public { t.call(""); s = 1; } }'],
      ['contract C { uint s; function f(address t) public nonReentrant { s = 1; t.call(""); } }', CLEAN]))

add(P("P028", "ERC721 Callback Reentrancy", "critical", "REENTRANCY", "SWC-107", "CWE-841", 0.45,
      [det(r"\bsafeTransferFrom\s*\(", 0.45, type="ast", scope="function", forbids=["nonReentrant"],
           desc="safeTransferFrom triggers onERC721Received callback without a guard")],
      ["contract C { function buy(address n, uint id) public { I(n).safeTransferFrom(address(this), msg.sender, id); } }"],
      ["contract C { function buy(address n, uint id) public nonReentrant { I(n).safeTransferFrom(address(this), msg.sender, id); } }", CLEAN]))

add(P("P029", "ERC1155 Batch Reentrancy", "critical", "REENTRANCY", "SWC-107", "CWE-841", 0.45,
      [det(r"\bsafeBatchTransferFrom\s*\(", 0.45, type="ast", scope="function", forbids=["nonReentrant"],
           desc="safeBatchTransferFrom callback without a guard")],
      ["contract C { function f(address n) public { I(n).safeBatchTransferFrom(address(this), msg.sender, ids, amts, bytes(0)); } }"],
      ["contract C { function f(address n) public nonReentrant { I(n).safeBatchTransferFrom(address(this), msg.sender, ids, amts, bytes(0)); } }", CLEAN]))

add(P("P030", "Reentrancy Via Fallback", "high", "REENTRANCY", "SWC-107", "CWE-841", 0.5,
      [det(r"\b(receive|fallback)\b", 0.5, type="ast", scope="function", requires=[r"\.call"],
           forbids=["nonReentrant"], desc="receive/fallback performs an external call without a guard")],
      ['contract C { receive() external payable { msg.sender.call{value:1}(""); } }'],
      ["contract C { receive() external payable { } }", CLEAN]))

add(P("P031", "Flash Loan Reentrancy Bridge", "critical", "REENTRANCY", "SWC-107", "CWE-841", 0.5,
      [det(r"(onFlashLoan|executeOperation|flashLoan)", 0.5, type="ast", scope="function",
           requires=[r"\.call"], forbids=["nonReentrant"],
           desc="Flash-loan callback performs external call without a guard")],
      ['contract C { function onFlashLoan(address i, uint a) external { i.call(""); } }'],
      ['contract C { function onFlashLoan(address i, uint a) external nonReentrant { i.call(""); } }', CLEAN]))

# ----------------------------------------------------------------- EXTERNAL_CALLS
add(P("P006", "Unchecked Low-Level Call", "high", "EXTERNAL_CALLS", "SWC-104", "CWE-252", 0.6,
      [det(r"^\s*[^=]*\.call\{", 0.6, desc="Return value of a low-level call is not checked")],
      ['contract C { function f(address t) public { t.call{value: 1}(""); } }'],
      ['contract C { function f(address t) public { (bool ok,)=t.call{value: 1}(""); require(ok); } }', CLEAN]))

add(P("P007", "Delegatecall Injection", "critical", "EXTERNAL_CALLS", "SWC-112", "CWE-829", 0.7,
      [det(r"\.delegatecall\s*\(", 0.7, desc="delegatecall to a runtime-supplied target")],
      ["contract C { function f(address t, bytes calldata d) public { t.delegatecall(d); } }"],
      [CLEAN]))

add(P("P017", "Arbitrary External Call", "critical", "EXTERNAL_CALLS", "SWC-112", "CWE-749", 0.6,
      [det(r"\.call\{[^}]*\}\s*\(", 0.6, desc="Low-level call with value/gas to a runtime destination")],
      ["contract C { function f(address t, bytes calldata d) public { t.call{value: 0}(d); } }"],
      ["contract C { function f() public { uint x = 1; } }"]))

add(P("P041", "Contract Existence Check Missing", "high", "EXTERNAL_CALLS", "SWC-104", "CWE-252", 0.4,
      [det(r"\.call\{", 0.4, forbids=["extcodesize", r"code\.length", "isContract"],
           desc="Low-level call without verifying the target is a contract")],
      ['contract C { function f(address t) public { t.call{value:1}(""); } }'],
      ['contract C { function f(address t) public { require(t.code.length > 0); t.call{value:1}(""); } }', CLEAN]))

add(P("P042", "Gas Stipend Dependency", "medium", "EXTERNAL_CALLS", "SWC-134", "CWE-691", 0.55,
      [det(r"\.(transfer|send)\s*\(\s*[^,)]*\)", 0.55,
           desc="ETH transfer/send relies on the fixed 2300-gas stipend")],
      ["contract C { function f(address payable t) public { t.transfer(1 ether); } }"],
      ["contract C { function f(address t, uint a) public { IERC20(t).transfer(t, a); } }", CLEAN]))

add(P("P043", "Deprecated callcode", "critical", "EXTERNAL_CALLS", "SWC-111", "CWE-477", 0.7,
      [det(r"\.callcode\s*\(", 0.7, desc="Deprecated callcode opcode")],
      ['contract C { function f(address t) public { t.callcode(""); } }'],
      [CLEAN]))

add(P("P044", "Staticcall With Assumed Side Effects", "medium", "EXTERNAL_CALLS", "SWC-104", "CWE-252", 0.4,
      [det(r"^\s*[^=]*\.staticcall\s*\(", 0.4, desc="staticcall result unchecked")],
      ['contract C { function f(address t) public view { t.staticcall(""); } }'],
      ['contract C { function f(address t) public view { (bool ok,)=t.staticcall(""); require(ok); } }', CLEAN]))

add(P("P045", "CREATE2 Address Collision", "high", "EXTERNAL_CALLS", "SWC-000", "CWE-330", 0.5,
      [det(r"(create2\s*\(|\{\s*salt\s*:)", 0.5, desc="CREATE2 deployment (address-reuse risk)")],
      ["contract C { function f(bytes32 s) public { new Foo{salt: s}(); } }"],
      [CLEAN]))

add(P("P107", "External Call In Loop", "high", "EXTERNAL_CALLS", "SWC-113", "CWE-400", 0.55,
      [det(r"for\s*\([^)]*\)[^{]*\{[^}]*\.call", 0.55, multiline=True,
           desc="External call inside a loop (griefing / gas DoS)")],
      ['contract C { function f(address[] calldata t) public { for (uint i; i<t.length; i++) { t[i].call(""); } } }'],
      [CLEAN]))

add(P("P108", "Unchecked send()", "high", "EXTERNAL_CALLS", "SWC-104", "CWE-252", 0.6,
      [det(r"^\s*[^=]*\.send\s*\(", 0.6, desc="Return value of send() not checked")],
      ["contract C { function f(address payable t) public { t.send(1); } }"],
      ["contract C { function f(address payable t) public { bool ok=t.send(1); require(ok); } }", CLEAN]))

add(P("P110", "Delegatecall In Assembly", "critical", "EXTERNAL_CALLS", "SWC-112", "CWE-829", 0.65,
      [det(r"assembly[^}]*delegatecall", 0.65, multiline=True, desc="delegatecall via inline assembly")],
      ["contract C { function f(address t) public { assembly { let r := delegatecall(gas(), t, 0, 0, 0, 0) } } }"],
      [CLEAN]))

add(P("P144", "Unchecked delegatecall Return", "high", "EXTERNAL_CALLS", "SWC-104", "CWE-252", 0.55,
      [det(r"^\s*[^=]*\.delegatecall\s*\(", 0.55, desc="delegatecall result not checked")],
      ["contract C { function f(address t, bytes calldata d) public { t.delegatecall(d); } }"],
      ["contract C { function f(address t, bytes calldata d) public { (bool ok,)=t.delegatecall(d); require(ok); } }", CLEAN]))

add(P("P133", "Hardcoded Gas In Call", "medium", "EXTERNAL_CALLS", "SWC-134", "CWE-691", 0.45,
      [det(r"\.call\{[^}]*gas\s*:", 0.45, desc="Hardcoded gas amount in a low-level call")],
      ['contract C { function f(address t) public { t.call{gas: 2300}(""); } }'],
      [CLEAN]))

# ----------------------------------------------------------------- PROXY_UPGRADEABLE
add(P("P008", "Storage Collision Risk", "high", "PROXY_UPGRADEABLE", "SWC-000", "CWE-665", 0.4,
      [det(r"\.delegatecall\s*\(", 0.4, forbids=["__gap", "StorageSlot", r"\.slot"],
           desc="Proxy delegatecall without explicit storage-slot management")],
      ["contract C { function f(address t, bytes calldata d) public { t.delegatecall(d); } }"],
      ["contract C { uint[50] private __gap; function f(address t, bytes calldata d) public { t.delegatecall(d); } }", CLEAN]))

add(P("P016", "Uninitialized Proxy", "critical", "PROXY_UPGRADEABLE", "SWC-118", "CWE-665", 0.55,
      [det(r"is\s+[^{]*(Initializable|UUPSUpgradeable)", 0.55, forbids=["_disableInitializers"],
           desc="Upgradeable contract without _disableInitializers()")],
      ["contract C is Initializable { constructor() { } }"],
      ["contract C is Initializable { constructor() { _disableInitializers(); } }", CLEAN]))

add(P("P036", "Metamorphic Contract", "critical", "PROXY_UPGRADEABLE", "SWC-000", "CWE-913", 0.6,
      [det(r"selfdestruct", 0.6, requires=[r"(create2|\{\s*salt)"],
           desc="selfdestruct combined with CREATE2 (metamorphic redeploy)")],
      ["contract C { function k() public { selfdestruct(payable(0)); } function d(bytes32 s) public { new X{salt: s}(); } }"],
      [CLEAN]))

add(P("P037", "Implementation Selfdestruct", "critical", "PROXY_UPGRADEABLE", "SWC-106", "CWE-665", 0.6,
      [det(r"selfdestruct", 0.6, requires=["Upgradeable"],
           desc="selfdestruct in an upgradeable implementation")],
      ["contract C is UUPSUpgradeable { function k() public { selfdestruct(payable(0)); } }"],
      [CLEAN]))

add(P("P038", "Constructor In Implementation", "high", "PROXY_UPGRADEABLE", "SWC-118", "CWE-665", 0.5,
      [det(r"constructor\s*\(", 0.5, requires=["Upgradeable", r"=\s*[^=]"], forbids=["_disableInitializers"],
           desc="Constructor with state init in an upgradeable implementation")],
      ["contract C is UUPSUpgradeable { uint x; constructor() { x = 1; } }"],
      ["contract C is UUPSUpgradeable { constructor() { _disableInitializers(); } }", CLEAN]))

add(P("P039", "Proxy Function Clashing", "high", "PROXY_UPGRADEABLE", "SWC-000", "CWE-710", 0.45,
      [det(r"fallback\s*\(\s*\)\s*external[^{]*\{[^}]*delegatecall", 0.45, multiline=True,
           desc="Proxy fallback delegatecall can clash with implementation selectors")],
      ["contract C { fallback() external payable { address t; assembly { let r := delegatecall(gas(), t, 0, 0, 0, 0) } } }"],
      [CLEAN]))

add(P("P040", "UUPS Upgrade Without Guard", "high", "PROXY_UPGRADEABLE", "SWC-105", "CWE-284", 0.6,
      [det(r"function\s+upgradeTo\w*\s*\(", 0.6, type="function_signature", scope="function",
           requires=[r"\b(public|external)\b"], forbids=GUARDS + ["_authorizeUpgrade"],
           desc="upgradeTo exposed without an upgrade guard")],
      ["contract C { address impl; function upgradeTo(address n) public { impl = n; } }"],
      ["contract C { address impl; function upgradeTo(address n) public onlyOwner { impl = n; } }", CLEAN]))

add(P("P046", "Unprotected diamondCut", "critical", "PROXY_UPGRADEABLE", "SWC-105", "CWE-284", 0.7,
      [det(r"function\s+\w*(diamondCut|facetCut|replaceFacet|addFacet|removeFacet|setFacet|registerFacet)\w*\s*\(",
           0.7, type="function_signature", scope="function", requires=[r"\b(public|external)\b"],
           forbids=GUARDS + ["enforceIsContractOwner", r"LibDiamond\.enforce"],
           desc="EIP-2535 facet management without an owner/role guard")],
      ["contract D { mapping(bytes4=>address) f; function diamondCut(bytes4[] calldata s, address a) external { f[s[0]] = a; } }"],
      ["contract D { mapping(bytes4=>address) f; function diamondCut(bytes4[] calldata s, address a) external onlyOwner { f[s[0]] = a; } }",
       "contract D { mapping(bytes4=>address) f; function diamondCut(bytes4[] calldata s, address a) external { LibDiamond.enforceIsContractOwner(); f[s[0]] = a; } }", CLEAN]))

add(P("P047", "Unprotected Implementation Setter", "critical", "PROXY_UPGRADEABLE", "SWC-105", "CWE-284", 0.7,
      [det(r"function\s+\w*set(Implementation|Impl|Beacon)\w*\s*\(", 0.7, type="function_signature",
           scope="function", requires=[r"\b(public|external)\b"], forbids=GUARDS,
           desc="Proxy/beacon implementation pointer setter without an access guard")],
      ["contract P { address impl; function setImplementation(address i) external { impl = i; } }"],
      ["contract P { address impl; function setImplementation(address i) external onlyOwner { impl = i; } }", CLEAN]))

add(P("P048", "Upgrade Without Implementation Code Check", "medium", "PROXY_UPGRADEABLE", "SWC-000", "CWE-20", 0.45,
      [det(r"function\s+\w*(upgradeTo|setImplementation|upgradeBeaconTo)\w*\s*\(", 0.45,
           type="function_signature", scope="function", requires=[r"\b(public|external)\b"],
           forbids=[r"code\.length", "isContract", "extcodesize", r"Address\."],
           desc="Implementation pointer updated without checking the target is a contract")],
      ["contract B { address impl; function upgradeTo(address n) external onlyOwner { impl = n; } }"],
      ["contract B { address impl; function upgradeTo(address n) external onlyOwner { require(n.code.length > 0); impl = n; } }", CLEAN]))

# --------------------------------------------------------------------- ARITHMETIC
add(P("P004", "Outdated Compiler (Overflow Risk)", "critical", "ARITHMETIC", "SWC-101", "CWE-190", 0.7,
      [det(r"pragma\s+solidity\s+[\^>=~ ]*0\.[0-7]\.", 0.7,
           desc="Pre-0.8 compiler without built-in overflow checks")],
      ["pragma solidity 0.7.6; contract C { }"],
      ["pragma solidity ^0.8.20; contract C { }", CLEAN]))

add(P("P064", "Unchecked Arithmetic Block", "high", "ARITHMETIC", "SWC-101", "CWE-190", 0.5,
      [det(r"unchecked\s*\{", 0.5, desc="Explicit unchecked arithmetic block")],
      ["contract C { function f(uint a) public pure returns (uint) { unchecked { return a + 1; } } }"],
      [CLEAN]))

add(P("P032", "Precision Loss (Div Before Mul)", "high", "ARITHMETIC", "SWC-101", "CWE-682", 0.5,
      [det(r"/\s*[\w().]+\s*\*", 0.5, desc="Division before multiplication loses precision")],
      ["contract C { function f(uint a, uint b) public pure returns (uint) { return a / b * 100; } }"],
      ["contract C { function f(uint a, uint b) public pure returns (uint) { return a * 100 / b; } }", CLEAN]))

add(P("P033", "Rounding Direction Risk", "medium", "ARITHMETIC", "SWC-101", "CWE-682", 0.35,
      [det(r"\*\s*[\w().]+\s*/", 0.35, desc="Multiply-then-divide may round against the protocol")],
      ["contract C { function f(uint a, uint b, uint c) public pure returns (uint) { return a * b / c; } }"],
      [CLEAN]))

add(P("P034", "Fee Calculation Risk", "medium", "ARITHMETIC", "SWC-101", "CWE-682", 0.4,
      [det(r"\bfee\w*\s*=\s*[^;]*[*/]", 0.4, desc="Fee computed with multiplication/division")],
      ["contract C { uint fee; function set(uint a) public { fee = a * 3 / 100; } }"],
      [CLEAN]))

add(P("P035", "Share Price Manipulation (EIP-4626)", "critical", "ARITHMETIC", "SWC-000", "CWE-682", 0.5,
      [det(r"(convertToShares|previewDeposit|convertToAssets)", 0.5,
           desc="Vault share math vulnerable to first-deposit/donation attacks")],
      ["contract C { uint totalSupply; uint totalAssets; function convertToShares(uint a) public view returns (uint) { return a * totalSupply / totalAssets; } }"],
      [CLEAN]))

add(P("P066", "Unsafe Downcast", "medium", "ARITHMETIC", "SWC-101", "CWE-197", 0.4,
      [det(r"\buint(8|16|32|64|128)\s*\(", 0.4, desc="Narrowing cast can silently truncate")],
      ["contract C { function f(uint x) public pure returns (uint8) { return uint8(x); } }"],
      [CLEAN]))

add(P("P067", "Hash Collision (encodePacked)", "high", "ARITHMETIC", "SWC-133", "CWE-328", 0.55,
      [det(r"abi\.encodePacked\([^)]*,[^)]*\)", 0.55,
           desc="encodePacked with multiple dynamic args can collide")],
      ["contract C { function f(string memory a, string memory b) public pure returns (bytes32) { return keccak256(abi.encodePacked(a, b)); } }"],
      ["contract C { function f(string memory a) public pure returns (bytes32) { return keccak256(abi.encode(a)); } }", CLEAN]))

# ----------------------------------------------------------------- TOKEN_ECONOMICS
add(P("P010", "Oracle Manipulation", "critical", "TOKEN_ECONOMICS", "SWC-000", "CWE-345", 0.55,
      [det(r"(getReserves|latestAnswer)\s*\(", 0.55, forbids=["getPastVotes", "TWAP", "consult"],
           desc="Spot price/reserves used without a TWAP")],
      ["contract C { function p(address pair) public view returns (uint) { (uint r0, uint r1,) = IPair(pair).getReserves(); return r0 / r1; } }"],
      [CLEAN]))

add(P("P011", "Flash Loan Attack Vector", "high", "TOKEN_ECONOMICS", "SWC-000", "CWE-841", 0.45,
      [det(r"\bflashLoan\s*\(", 0.45, desc="Flash-loan entrypoint present")],
      ["contract C { function flashLoan(uint a) public { } }"],
      [CLEAN]))

add(P("P050", "Honeypot Indicators", "high", "TOKEN_ECONOMICS", "SWC-000", "CWE-840", 0.45,
      [det(r"(blacklist|tradingEnabled|canTransfer\s*=\s*false|_isExcludedFromSell)", 0.45,
           desc="Transfer-restriction toggles typical of honeypots")],
      ["contract C { mapping(address=>bool) blacklist; }"],
      [CLEAN]))

add(P("P051", "Fee-On-Transfer Accounting Mismatch", "high", "TOKEN_ECONOMICS", "SWC-000", "CWE-682", 0.4,
      [det(r"function\s+_transfer[^}]*fee", 0.4, multiline=True,
           desc="Fee deducted inside _transfer can break balance accounting")],
      ["contract C { uint fee; function _transfer(address a, address b, uint v) internal { uint f = v * fee / 100; } }"],
      [CLEAN]))

add(P("P052", "Deflationary Burn In Transfer", "medium", "TOKEN_ECONOMICS", "SWC-000", "CWE-682", 0.4,
      [det(r"function\s+_transfer[^}]*_burn", 0.4, multiline=True,
           desc="_burn inside _transfer changes received amount")],
      ["contract C { function _transfer(address a, address b, uint v) internal { _burn(a, v / 100); } }"],
      [CLEAN]))

add(P("P070", "Mutable Fee Setter", "high", "TOKEN_ECONOMICS", "SWC-000", "CWE-284", 0.4,
      [det(r"function\s+set\w*[Ff]ee\w*\s*\(", 0.4, forbids=[r"require"],
           desc="Fee setter without an upper-bound check")],
      ["contract C { uint fee; function setFee(uint f) public { fee = f; } }"],
      ["contract C { uint fee; function setFee(uint f) public { require(f <= 100); fee = f; } }", CLEAN]))

add(P("P073", "Max Transaction/Wallet Limit", "medium", "TOKEN_ECONOMICS", "SWC-000", "CWE-840", 0.35,
      [det(r"\b(maxTx\w*|maxWallet\w*)\b", 0.35, desc="Max transaction/wallet caps (rug-pull lever)")],
      ["contract C { uint maxTxAmount; }"],
      [CLEAN]))

add(P("P074", "Mutable Tax Setter", "high", "TOKEN_ECONOMICS", "SWC-000", "CWE-284", 0.4,
      [det(r"function\s+set\w*[Tt]ax\w*\s*\(", 0.4, desc="Owner-mutable tax rate")],
      ["contract C { uint tax; function setTax(uint t) public { tax = t; } }"],
      [CLEAN]))

# ----------------------------------------------------------------------- GOVERNANCE
add(P("P013", "Governance Vote Entry", "high", "GOVERNANCE", "SWC-000", "CWE-284", 0.4,
      [det(r"function\s+castVote\w*\s*\(", 0.4, desc="On-chain voting entrypoint")],
      ["contract C { function castVote(uint id, uint8 s) public { } }"],
      [CLEAN]))

add(P("P060", "Flash Loan Governance Takeover", "critical", "GOVERNANCE", "SWC-000", "CWE-841", 0.5,
      [det(r"(castVote|propose)\s*\(", 0.5, forbids=["getPastVotes", "getPastTotalSupply", "snapshot"],
           desc="Voting power read live (no snapshot) — flash-loan takeover risk")],
      ["contract C { function propose() public { } function vote() public { uint w = token.getVotes(msg.sender); } function castVote() public { } }"],
      ["contract C { function castVote(uint id) public { uint w = token.getPastVotes(msg.sender, block.number - 1); } }", CLEAN]))

add(P("P061", "Low Quorum / Proposal Threshold", "high", "GOVERNANCE", "SWC-000", "CWE-840", 0.5,
      [det(r"(proposalThreshold\s*=\s*0\b|quorumNumerator\s*=\s*[0-4]\b)", 0.5,
           desc="Quorum/threshold set dangerously low")],
      ["contract C { uint proposalThreshold = 0; }"],
      [CLEAN]))

add(P("P062", "Zero Timelock Delay", "medium", "GOVERNANCE", "SWC-000", "CWE-840", 0.45,
      [det(r"\b(minDelay|delay)\s*=\s*0\b", 0.45, desc="Timelock delay of zero")],
      ["contract C { uint minDelay = 0; }"],
      [CLEAN]))

add(P("P063", "Vote Weight From balanceOf", "high", "GOVERNANCE", "SWC-000", "CWE-841", 0.45,
      [det(r"balanceOf\s*\(", 0.45, requires=[r"\b(vote|Vote)\b"],
           desc="Voting power derived from spot balanceOf (manipulable)")],
      ["contract C { function vote() public { uint w = token.balanceOf(msg.sender); } }"],
      [CLEAN]))

add(P("P077", "Unprotected Emergency Function", "high", "GOVERNANCE", "SWC-105", "CWE-284", 0.55,
      [det(r"function\s+emergency\w*\s*\(", 0.55, type="function_signature", scope="function",
           requires=[r"\b(public|external)\b"], forbids=GUARDS, desc="Emergency function without a guard")],
      ["contract C { function emergencyWithdraw() public { payable(msg.sender).transfer(address(this).balance); } }"],
      ["contract C { function emergencyWithdraw() public onlyOwner { payable(msg.sender).transfer(address(this).balance); } }", CLEAN]))

add(P("P178", "Unprotected Pause", "medium", "GOVERNANCE", "SWC-105", "CWE-284", 0.5,
      [det(r"function\s+pause\s*\(", 0.5, type="function_signature", scope="function",
           requires=[r"\b(public|external)\b"], forbids=GUARDS, desc="pause() without a guard")],
      ["contract C { bool p; function pause() public { p = true; } }"],
      ["contract C { bool p; function pause() public onlyOwner { p = true; } }", CLEAN]))

# ----------------------------------------------------------------- SIGNATURE_CRYPTO
add(P("P012", "Signature Replay (No Nonce)", "high", "SIGNATURE_CRYPTO", "SWC-121", "CWE-294", 0.5,
      [det(r"ecrecover\s*\(", 0.5, forbids=["nonce", "_nonces"],
           desc="ecrecover-based auth without a replay nonce")],
      ["contract C { function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(h, v, r, s); } }"],
      ["contract C { mapping(address=>uint) nonce; function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(h, v, r, s); nonce[a]++; } }", CLEAN]))

add(P("P078", "ecrecover Zero-Address Unchecked", "high", "SIGNATURE_CRYPTO", "SWC-122", "CWE-476", 0.55,
      [det(r"ecrecover\s*\(", 0.55, forbids=[r"address\(0\)", "ECDSA"],
           desc="ecrecover result not checked against address(0)")],
      ["contract C { function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(h, v, r, s); _use(a); } }"],
      ["contract C { function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(h, v, r, s); require(a != address(0)); } }", CLEAN]))

add(P("P079", "Missing chainId In Signature", "medium", "SIGNATURE_CRYPTO", "SWC-121", "CWE-294", 0.4,
      [det(r"ecrecover\s*\(", 0.4, forbids=["chainid", "DOMAIN_SEPARATOR", "block.chainid"],
           desc="Signed data without chainId binding (cross-chain replay)")],
      ["contract C { function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(h, v, r, s); } }"],
      ["contract C { function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { uint id = block.chainid; address a = ecrecover(h, v, r, s); } }", CLEAN]))

add(P("P080", "Signature Malleability", "medium", "SIGNATURE_CRYPTO", "SWC-117", "CWE-347", 0.45,
      [det(r"ecrecover\s*\(", 0.45, forbids=["ECDSA", r"s\s*>", "malleab", "0x7FFF"],
           desc="Raw ecrecover without low-s malleability guard")],
      ["contract C { function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(h, v, r, s); } }"],
      ["contract C { function f(bytes32 h, bytes memory sig) public { address a = ECDSA.recover(h, sig); } }", CLEAN]))

add(P("P083", "Signature Without Deadline", "medium", "SIGNATURE_CRYPTO", "SWC-121", "CWE-294", 0.4,
      [det(r"ecrecover\s*\(", 0.4, forbids=["deadline", "expir"],
           desc="Signed approval without an expiry/deadline")],
      ["contract C { function permit(uint8 v, bytes32 r, bytes32 s) public { address a = ecrecover(bytes32(0), v, r, s); } }"],
      ["contract C { uint deadline; function permit(uint dl, uint8 v, bytes32 r, bytes32 s) public { require(block.timestamp <= dl); deadline = dl; address a = ecrecover(bytes32(0), v, r, s); } }", CLEAN]))

# ----------------------------------------------------------------- TIME_RANDOMNESS
add(P("P020", "Timestamp Dependence", "medium", "TIME_RANDOMNESS", "SWC-116", "CWE-829", 0.45,
      [det(r"block\.timestamp\s*(<|>|<=|>=|==)|(<|>|<=|>=|==)\s*block\.timestamp", 0.45,
           desc="Control flow depends on block.timestamp")],
      ["contract C { function f() public view returns (bool) { return block.timestamp > 100; } }"],
      [CLEAN]))

add(P("P085", "Blockhash / prevrandao Randomness", "high", "TIME_RANDOMNESS", "SWC-120", "CWE-330", 0.6,
      [det(r"(blockhash\s*\(|block\.difficulty|block\.prevrandao)", 0.6,
           desc="Weak randomness from block attributes")],
      ["contract C { function r() public view returns (uint) { return uint(blockhash(block.number - 1)); } }"],
      [CLEAN]))

add(P("P086", "Block Number As Time", "medium", "TIME_RANDOMNESS", "SWC-116", "CWE-682", 0.4,
      [det(r"block\.number\s*[*+/-]|[*+/-]\s*block\.number", 0.4,
           desc="block.number used in time arithmetic")],
      ["contract C { function f() public view returns (uint) { return block.number * 13; } }"],
      [CLEAN]))

add(P("P087", "Weak PRNG From Block Data", "high", "TIME_RANDOMNESS", "SWC-120", "CWE-330", 0.6,
      [det(r"keccak256\([^)]*block\.(timestamp|number|difficulty|prevrandao)", 0.6, multiline=True,
           desc="PRNG seeded from predictable block data")],
      ["contract C { function r() public view returns (uint) { return uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty))); } }"],
      [CLEAN]))

add(P("P088", "Swap Without Deadline", "medium", "TIME_RANDOMNESS", "SWC-000", "CWE-841", 0.4,
      [det(r"swap\w*\s*\(", 0.4, forbids=["deadline"], desc="DEX swap without a deadline parameter")],
      ["contract C { function go() public { router.swapExactTokensForTokens(1, 0, path, msg.sender); } }"],
      ["contract C { function go(uint dl) public { router.swapExactTokensForTokens(1, 0, path, msg.sender, dl); uint deadline = dl; } }", CLEAN]))

add(P("P089", "block.coinbase Dependence", "medium", "TIME_RANDOMNESS", "SWC-120", "CWE-330", 0.4,
      [det(r"block\.coinbase", 0.4, desc="Logic depends on block.coinbase (miner-influenced)")],
      ["contract C { function f() public view returns (address) { return block.coinbase; } }"],
      [CLEAN]))

# ----------------------------------------------------------------- BUSINESS_LOGIC
add(P("P009", "No Input Validation (Address)", "medium", "BUSINESS_LOGIC", "SWC-000", "CWE-20", 0.4,
      [det(r"function\s+\w+\s*\([^)]*\baddress\b[^)]*\)", 0.4, type="function_signature", scope="function",
           requires=[r"\b(public|external)\b"], forbids=[r"address\(0\)", r"require\s*\("],
           desc="Address parameter used without a zero-address check")],
      ["contract C { address a; function setA(address x) public { a = x; } }"],
      ["contract C { address a; function setA(address x) public { require(x != address(0)); a = x; } }", CLEAN]))

add(P("P090", "assert Misuse", "medium", "BUSINESS_LOGIC", "SWC-110", "CWE-617", 0.4,
      [det(r"\bassert\s*\(", 0.4, desc="assert used for input validation (consumes all gas)")],
      ["contract C { function f(uint a) public pure { assert(a > 0); } }"],
      [CLEAN]))

add(P("P091", "Deprecated Keywords", "medium", "BUSINESS_LOGIC", "SWC-111", "CWE-477", 0.6,
      [det(r"\b(throw|suicide|sha3)\b", 0.6, desc="Deprecated throw/suicide/sha3")],
      ["contract C { function f() public { suicide(payable(msg.sender)); } }"],
      [CLEAN]))

add(P("P092", "Unbounded Loop Over Array", "high", "BUSINESS_LOGIC", "SWC-128", "CWE-400", 0.45,
      [det(r"for\s*\([^)]*<\s*\w+\.length", 0.45, desc="Loop bounded by a growable array length (gas DoS)")],
      ["contract C { uint[] a; function f() public { for (uint i; i < a.length; i++) { a[i] = 0; } } }"],
      [CLEAN]))

add(P("P093", "Strict Balance Equality", "medium", "BUSINESS_LOGIC", "SWC-132", "CWE-697", 0.45,
      [det(r"address\(this\)\.balance\s*==|==\s*address\(this\)\.balance", 0.45,
           desc="Strict equality on contract balance (forced-send breaks it)")],
      ["contract C { function f() public view returns (bool) { return address(this).balance == 0; } }"],
      [CLEAN]))

add(P("P095", "Setter Without Event", "low", "BUSINESS_LOGIC", "SWC-000", "CWE-778", 0.35,
      [det(r"function\s+set[A-Z]\w*\s*\(", 0.35, type="function_signature", scope="function",
           forbids=["emit"], desc="Critical setter emits no event")],
      ["contract C { uint x; function setX(uint v) public { x = v; } }"],
      ["contract C { event S(uint v); uint x; function setX(uint v) public { x = v; emit S(v); } }", CLEAN]))

add(P("P096", "Deprecated now Alias", "low", "BUSINESS_LOGIC", "SWC-116", "CWE-477", 0.5,
      [det(r"\bnow\b", 0.5, desc="Deprecated 'now' alias for block.timestamp")],
      ["contract C { function f() public view returns (uint) { return now; } }"],
      [CLEAN]))

add(P("P099", "tx.gasprice Dependence", "low", "BUSINESS_LOGIC", "SWC-000", "CWE-330", 0.35,
      [det(r"tx\.gasprice", 0.35, desc="Logic depends on tx.gasprice")],
      ["contract C { function f() public view returns (uint) { return tx.gasprice; } }"],
      [CLEAN]))

# ------------------------------------------------------------------- ERC_STANDARDS
add(P("P019", "No SafeERC20 (transfer)", "medium", "ERC_STANDARDS", "SWC-104", "CWE-252", 0.45,
      [det(r"^\s*(?!.*require)[^=]*\.transfer\s*\(\s*[^,)]+,[^)]*\)\s*;", 0.45,
           desc="ERC-20 transfer return value ignored (use SafeERC20)")],
      ["contract C { function f(address t) public { IERC20(t).transfer(msg.sender, 1); } }"],
      ["contract C { function f(address t) public { require(IERC20(t).transfer(msg.sender, 1)); } }", CLEAN]))

add(P("P100", "Approve Race Condition", "medium", "ERC_STANDARDS", "SWC-114", "CWE-362", 0.35,
      [det(r"\.approve\s*\(\s*[^,]+,\s*type\(uint\d*\)\.max", 0.35,
           desc="Unlimited approval (allowance race / over-approval)")],
      ["contract C { function f(address t) public { IERC20(t).approve(t, type(uint256).max); } }"],
      [CLEAN]))

add(P("P109", "Unchecked transferFrom", "high", "ERC_STANDARDS", "SWC-104", "CWE-252", 0.5,
      [det(r"^\s*(?!.*require)[^=]*\.transferFrom\s*\(", 0.5,
           desc="transferFrom return value ignored")],
      ["contract C { function f(address t) public { IERC20(t).transferFrom(msg.sender, address(this), 1); } }"],
      ["contract C { function f(address t) public { require(IERC20(t).transferFrom(msg.sender, address(this), 1)); } }", CLEAN]))

add(P("P112", "Floating Pragma", "medium", "ERC_STANDARDS", "SWC-103", "CWE-1104", 0.5,
      [det(r"pragma\s+solidity\s+\^", 0.5, desc="Floating pragma (^) — pin the compiler")],
      ["pragma solidity ^0.8.0; contract C { }"],
      ["pragma solidity 0.8.20; contract C { }", CLEAN]))

add(P("P116", "SafeMath On 0.8+", "low", "ERC_STANDARDS", "SWC-101", "CWE-1041", 0.4,
      [det(r"using\s+SafeMath", 0.4, desc="Redundant SafeMath on a checked compiler")],
      ["contract C { using SafeMath for uint256; }"],
      [CLEAN]))

# --------------------------------------------------------------- BYTECODE_LOWLEVEL
add(P("P120", "Selfdestruct Present", "high", "BYTECODE_LOWLEVEL", "SWC-106", "CWE-477", 0.5,
      [det(r"\bselfdestruct\s*\(", 0.5, desc="Contract can be destroyed via selfdestruct")],
      ["contract C { address owner; function k() public onlyOwner { selfdestruct(payable(owner)); } }"],
      [CLEAN]))

add(P("P121", "Inline Assembly Usage", "medium", "BYTECODE_LOWLEVEL", "SWC-127", "CWE-695", 0.4,
      [det(r"assembly\s*\{", 0.4, desc="Inline assembly bypasses Solidity safety checks")],
      ["contract C { function f() public pure returns (uint x) { assembly { x := 1 } } }"],
      [CLEAN]))

add(P("P122", "extcodesize Sender Check", "medium", "BYTECODE_LOWLEVEL", "SWC-000", "CWE-697", 0.35,
      [det(r"extcodesize\s*\(", 0.35, desc="extcodesize-based contract check (bypassable in constructor)")],
      ["contract C { function f(address a) public view returns (uint s) { assembly { s := extcodesize(a) } } }"],
      [CLEAN]))

add(P("P123", "Raw Storage Slot Access", "medium", "BYTECODE_LOWLEVEL", "SWC-000", "CWE-665", 0.4,
      [det(r"assembly[^}]*(sstore|sload)", 0.4, multiline=True, desc="Raw sstore/sload via assembly")],
      ["contract C { function f(uint v) public { assembly { sstore(0, v) } } }"],
      [CLEAN]))

add(P("P127", "gasleft For Control Flow", "medium", "BYTECODE_LOWLEVEL", "SWC-000", "CWE-691", 0.35,
      [det(r"gasleft\s*\(\s*\)", 0.35, desc="Logic depends on remaining gas")],
      ["contract C { function f() public view returns (uint) { return gasleft(); } }"],
      [CLEAN]))

add(P("P155", "block.gaslimit Dependence", "low", "BYTECODE_LOWLEVEL", "SWC-000", "CWE-691", 0.35,
      [det(r"block\.gaslimit", 0.35, desc="Logic depends on block.gaslimit")],
      ["contract C { function f() public view returns (uint) { return block.gaslimit; } }"],
      [CLEAN]))

add(P("P157", "Deprecated this.balance", "low", "BYTECODE_LOWLEVEL", "SWC-000", "CWE-477", 0.35,
      [det(r"\bthis\.balance\b", 0.35, desc="Deprecated this.balance (use address(this).balance)")],
      ["contract C { function f() public view returns (uint) { return this.balance; } }"],
      [CLEAN]))

# ----------------------------------------------------------------------- EXTRAS
add(P("P135", "tx.origin Usage", "low", "ACCESS_CONTROL", "SWC-115", "CWE-477", 0.4,
      [det(r"tx\.origin", 0.4, desc="tx.origin referenced (phishing-prone)")],
      ["contract C { function f() public view returns (address) { return tx.origin; } }"],
      [CLEAN]))

add(P("P140", "Mint To Zero Address", "medium", "TOKEN_ECONOMICS", "SWC-000", "CWE-20", 0.45,
      [det(r"_mint\s*\(\s*address\(0\)", 0.45, desc="Mint to the zero address")],
      ["contract C { function f() internal { _mint(address(0), 1); } }"],
      [CLEAN]))

add(P("P152", "require Without Message", "low", "BUSINESS_LOGIC", "SWC-000", "CWE-778", 0.3,
      [det(r"require\s*\([^,)]*\)\s*;", 0.3, desc="require without a revert message")],
      ["contract C { function f(uint a) public pure { require(a > 0); } }"],
      ["contract C { function f(uint a) public pure { require(a > 0, \"too small\"); } }", CLEAN]))

add(P("P163", "Contract Balance For Accounting", "low", "BUSINESS_LOGIC", "SWC-000", "CWE-682", 0.3,
      [det(r"address\(this\)\.balance", 0.3, desc="Using live contract balance for accounting")],
      ["contract C { function f() public view returns (uint) { return address(this).balance; } }"],
      [CLEAN]))

add(P("P172", "Withdraw Without Reentrancy Guard", "high", "REENTRANCY", "SWC-107", "CWE-841", 0.5,
      [det(r"function\s+withdraw\w*\s*\(", 0.5, type="function_signature", scope="function",
           requires=[r"\.(call|transfer|send)\b"], forbids=["nonReentrant"],
           desc="withdraw moves funds without a reentrancy guard")],
      ["contract C { function withdraw() public { payable(msg.sender).transfer(1); } }"],
      ["contract C { function withdraw() public nonReentrant { payable(msg.sender).transfer(1); } }", CLEAN]))

add(P("P173", "ERC777 Hook Reentrancy", "high", "REENTRANCY", "SWC-107", "CWE-841", 0.4,
      [det(r"(tokensReceived|tokensToSend)\s*\(", 0.4, desc="ERC-777 hooks can re-enter")],
      ["contract C { function tokensReceived(address a, uint v) public { } }"],
      [CLEAN]))

add(P("P174", "Unprotected burnFrom", "high", "TOKEN_ECONOMICS", "SWC-000", "CWE-284", 0.45,
      [det(r"function\s+burnFrom\s*\(", 0.45, type="function_signature", scope="function",
           requires=[r"\b(public|external)\b"], forbids=["allowance", "_spendAllowance", "_approve"] + GUARDS,
           desc="burnFrom without allowance/authorization")],
      ["contract C { function burnFrom(address a, uint v) public { _burn(a, v); } }"],
      ["contract C { function burnFrom(address a, uint v) public { _spendAllowance(a, msg.sender, v); _burn(a, v); } }", CLEAN]))


def q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def emit(p: dict) -> str:
    out = [f"id: {p['id']}", f"name: {q(p['name'])}", f"severity: {p['severity']}",
           f"category: {p['category']}", f"confidence: {p['confidence']}"]
    if p.get("swc"):
        out.append(f"swc: {p['swc']}")
    if p.get("cwe"):
        out.append(f"cwe: {p['cwe']}")
    out.append("detectors:")
    for d in p["detectors"]:
        out.append(f"  - type: {d['type']}")
        out.append(f"    pattern: {q(d['pattern'])}")
        if d["scope"] != "file":
            out.append(f"    scope: {d['scope']}")
        if d["multiline"]:
            out.append("    multiline: true")
        if d["requires"]:
            out.append("    requires:")
            out += [f"      - {q(r)}" for r in d["requires"]]
        if d["forbids"]:
            out.append("    forbids:")
            out += [f"      - {q(r)}" for r in d["forbids"]]
        out.append(f"    confidence: {d['confidence']}")
        if d["description"]:
            out.append(f"    description: {q(d['description'])}")
        if d["recommendation"]:
            out.append(f"    recommendation: {q(d['recommendation'])}")
    out.append("tests:")
    out.append("  positive:")
    out += [f"    - {q(s)}" for s in p["pos"]]
    out.append("  negative:")
    out += [f"    - {q(s)}" for s in p["neg"]]
    return "\n".join(out) + "\n"


def slug(name: str) -> str:
    keep = "".join(c.lower() if c.isalnum() else "_" for c in name)
    while "__" in keep:
        keep = keep.replace("__", "_")
    return keep.strip("_")[:50]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for f in OUT.glob("*.yaml"):
        f.unlink()
    ids = set()
    for p in PATTERNS:
        if p["id"] in ids:
            raise SystemExit(f"duplicate id {p['id']}")
        ids.add(p["id"])
        (OUT / f"{p['id']}_{slug(p['name'])}.yaml").write_text(emit(p), encoding="utf-8")
    print(f"wrote {len(PATTERNS)} patterns to {OUT}")


if __name__ == "__main__":
    main()
