#!/usr/bin/env bash
# =============================================================================
# generate-report.sh — Unified Security HTML Report
# Tools : Opengrep (SAST) + Gitleaks (Secrets)
# Output: report.html
# =============================================================================
set -e

# ── Metadata ──────────────────────────────────────────────────────────────────
REPO="${BUILD_REPOSITORY_NAME:-unknown-repo}"
BRANCH="${BUILD_SOURCEBRANCH:-unknown-branch}"
BUILD_NUM="${BUILD_BUILDNUMBER:-0}"
BUILD_ID="${BUILD_BUILDID:-0}"
PR_TITLE_JS=$(printf '%s' "${SYSTEM_PULLREQUEST_TITLE:-N/A}" | sed 's/\\/\\\\/g; s/"/\\"/g')
PR_ID="${SYSTEM_PULLREQUEST_ID:-}"
BASELINE="${BASELINE_COMMIT:-HEAD}"
SCAN_DATE=$(date -u "+%Y-%m-%d %H:%M UTC")
COLLECTION="${SYSTEM_TEAMFOUNDATIONCOLLECTIONURI:-}"
PROJECT="${SYSTEM_TEAMPROJECT:-}"
ENABLE_QUALITY_GATE="${ENABLE_QUALITY_GATE:-false}"
AZURE_REPO_BASE_URL="${AZURE_REPO_BASE_URL:-}"

if [ -n "$COLLECTION" ] && [ -n "$PROJECT" ] && [ -n "$PR_ID" ]; then
  PR_URL="${COLLECTION}${PROJECT}/_git/${REPO}/pullrequest/${PR_ID}"
else
  PR_URL=""
fi

OG_NEW_COUNT="${OG_NEW_COUNT:-0}"
OG_FULL_COUNT="${OG_FULL_COUNT:-0}"
GL_NEW_COUNT="${GL_NEW_COUNT:-0}"
GL_FULL_COUNT="${GL_FULL_COUNT:-0}"

# ── Files to exclude from Gitleaks (pipeline-generated scan artifacts) ─────────
EXCL='["opengrep-full.sarif","opengrep-new.json","gitleaks-full.sarif","gitleaks-new.json",
        "sarif-reports/opengrep.sarif","sarif-reports/gitleaks.sarif",
        "audit-trail/opengrep-delta.json","audit-trail/gitleaks-delta.json",
        "audit-trail/opengrep-full.sarif","new.json","report.html","changed_files.txt"]'

# ── Extract Opengrep new findings (JSON delta) ────────────────────────────────
OG_NEW_JS="[]"
if [ -f opengrep-new.json ]; then
  OG_NEW_JS=$(jq '[.results[] | {
    file:     (.path // "unknown"),
    line:     (.start.line // 0),
    rule:     (.check_id // "unknown"),
    message:  (.extra.message // "No message"),
    severity: (.extra.severity // "INFO"),
    code:     (.extra.lines // ""),
    fix:      (.extra.metadata.fix // ""),
    cwe:      ((.extra.metadata.cwe // []) | if type=="array" then join(", ") else . end),
    owasp:    ((.extra.metadata.owasp // []) | if type=="array" then join(", ") else . end),
    refs:     ((.extra.metadata.references // []) | if type=="array" then . else [.] end),
    isNew:    true,
    tool:     "Opengrep"
  }]' opengrep-new.json 2>/dev/null || echo "[]")
fi

# ── Extract Opengrep full findings (SARIF) ────────────────────────────────────
OG_FULL_JS="[]"
if [ -f opengrep-full.sarif ]; then
  OG_FULL_JS=$(jq '
    (.runs[0].tool.driver.rules // []) as $rules |
    ($rules | map({ (.id): (.helpUri // (.help.text // "")) }) | add // {}) as $ruleRefs |
    [.runs[0].results[] |
      . as $r |
      ($ruleRefs[$r.ruleId] // "") as $helpUri |
      {
        file:     ($r.locations[0].physicalLocation.artifactLocation.uri // "unknown"),
        line:     ($r.locations[0].physicalLocation.region.startLine // 0),
        rule:     ($r.ruleId // "unknown"),
        message:  ($r.message.text // "No message"),
        severity: ($r.level // "note"),
        code:     ($r.locations[0].physicalLocation.region.snippet.text // ""),
        fix:      ($r.fixes[0].description.text // ""),
        refs:     ([$helpUri | select(length>0 and startswith("http"))]),
        cwe:      "", owasp: "", isNew: false, tool: "Opengrep"
      }
    ]
  ' opengrep-full.sarif 2>/dev/null || echo "[]")
fi

# ── Extract Gitleaks new findings (JSON delta) — exclude pipeline files ────────
GL_NEW_JS="[]"
if [ -f gitleaks-new.json ] && [ -s gitleaks-new.json ]; then
  GL_NEW_JS=$(jq --argjson excl "$EXCL" '
    if . == null then [] else
    [.[] |
      select(.File as $f | ($excl | index($f)) == null) |
      {
        file:        (.File // "unknown"),
        line:        (.StartLine // 0),
        rule:        (.RuleID // "unknown"),
        message:     ("Secret detected: " + (.Description // "unknown")),
        severity:    "CRITICAL",
        code:        "*** redacted for security ***",
        fix:         "Rotate the exposed credential immediately. Remove from git history with git-filter-repo. Use environment variables or a secrets manager.",
        cwe:         "CWE-798",
        owasp:       "A07:2021",
        refs:        ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
        commit:      (.Commit // ""),
        author:      (.Author // ""),
        fingerprint: (.Fingerprint // ""),
        isNew:       true,
        tool:        "Gitleaks"
      }
    ] end
  ' gitleaks-new.json 2>/dev/null || echo "[]")
fi

# ── Extract Gitleaks full findings (SARIF) — exclude pipeline files ────────────
GL_FULL_JS="[]"
if [ -f gitleaks-full.sarif ]; then
  GL_FULL_JS=$(jq --argjson excl "$EXCL" '
    [.runs[0].results[] |
      .locations[0].physicalLocation.artifactLocation.uri as $f |
      select(($excl | index($f)) == null) |
      {
        file:        $f,
        line:        (.locations[0].physicalLocation.region.startLine // 0),
        rule:        (.ruleId // "unknown"),
        message:     (.message.text // "No message"),
        severity:    "CRITICAL",
        code:        "*** redacted for security ***",
        fix:         "Rotate the exposed credential immediately. Remove from git history with git-filter-repo. Use environment variables or a secrets manager.",
        cwe:         "CWE-798",
        owasp:       "A07:2021",
        refs:        ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
        commit:      "", author: "", fingerprint: "",
        isNew:       false,
        tool:        "Gitleaks"
      }
    ]
  ' gitleaks-full.sarif 2>/dev/null || echo "[]")
fi

# ── Write report (static HTML section then injected data) ─────────────────────
cat > report.html << 'HTML_END'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Security Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

/* ── OWASP ZAP-inspired severity palette on a clean light base ───────── */
:root{
  --bg:       #f8f9fc;
  --surface:  #ffffff;
  --surface2: #f1f3f8;
  --border:   #e2e6ef;
  --border2:  #ccd0de;
  --text:     #111827;
  --text2:    #4b5563;
  --text3:    #9ca3af;
  --accent:   #2563eb;
  --accent-l: #eff4ff;

  /* OWASP ZAP exact severity colors */
  --c-critical: #c0392b;  --c-critical-bg: #fdf2f1;  --c-critical-bd: #f5c6c2;
  --c-high:     #e67e22;  --c-high-bg:     #fef8f1;  --c-high-bd:    #fad9b8;
  --c-medium:   #d4ac0d;  --c-medium-bg:   #fefdf0;  --c-medium-bd:  #f7ecb0;
  --c-low:      #27ae60;  --c-low-bg:      #f0fdf4;  --c-low-bd:     #b7f0cb;
  --c-info:     #2980b9;  --c-info-bg:     #eff6fd;  --c-info-bd:    #bdddf5;

  --c-new:      #7c3aed;  --c-new-bg:      #f5f0ff;  --c-new-bd:     #c4b5fd;

  --shadow-sm:  0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
  --shadow:     0 4px 12px rgba(0,0,0,.07),0 1px 3px rgba(0,0,0,.04);
  --shadow-lg:  0 10px 30px rgba(0,0,0,.09);

  --font:  'DM Sans', sans-serif;
  --mono:  'DM Mono', monospace;
  --r:     8px;
  --r-lg:  12px;
}

body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;display:flex;min-height:100vh}

/* ── Sidebar ────────────────────────────────────────────────────────────── */
.sidebar{
  width:220px;min-width:220px;background:var(--surface);
  border-right:1px solid var(--border);display:flex;flex-direction:column;
  position:sticky;top:0;height:100vh;overflow-y:auto;
  box-shadow:var(--shadow-sm);
}
.sidebar-brand{
  padding:20px 18px 16px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px;
}
.brand-logo{height:32px;width:auto;object-fit:contain}
.brand-text{font-size:12px;font-weight:600;color:var(--text);line-height:1.3}
.brand-sub{font-size:10px;color:var(--text3);letter-spacing:.8px;text-transform:uppercase}

.sidebar-nav{padding:12px 10px;flex:1}
.nav-label{font-size:9px;letter-spacing:1.8px;text-transform:uppercase;color:var(--text3);padding:0 8px;margin:8px 0 4px}
.nav-item{
  display:flex;align-items:center;gap:9px;padding:8px 10px;
  border-radius:var(--r);cursor:pointer;color:var(--text2);
  font-size:13px;font-weight:500;transition:.15s;text-decoration:none;
  border:1px solid transparent;
}
.nav-item:hover{background:var(--surface2);color:var(--text)}
.nav-item.active{background:var(--accent-l);color:var(--accent);border-color:#bfdbfe}
.nav-icon{font-size:15px;flex-shrink:0;width:18px;text-align:center}
.nav-badge{
  margin-left:auto;padding:1px 7px;border-radius:99px;
  font-size:10px;font-weight:600;
  background:var(--surface2);border:1px solid var(--border2);color:var(--text3);
}
.nav-badge.red{background:var(--c-critical-bg);border-color:var(--c-critical-bd);color:var(--c-critical)}

.sidebar-footer{
  padding:14px 18px;border-top:1px solid var(--border);
  font-size:10px;color:var(--text3);line-height:1.9;
}

/* ── Main ────────────────────────────────────────────────────────────────── */
.main{flex:1;overflow-x:hidden;min-width:0}

/* ── Topbar ──────────────────────────────────────────────────────────────── */
.topbar{
  background:var(--surface);border-bottom:1px solid var(--border);
  padding:14px 28px;display:flex;align-items:center;
  justify-content:space-between;gap:16px;
  position:sticky;top:0;z-index:20;box-shadow:var(--shadow-sm);
}
.topbar-left{}
.topbar-title{font-size:17px;font-weight:700;color:var(--text);letter-spacing:-.3px}
.topbar-meta{
  display:flex;align-items:center;gap:6px;flex-wrap:wrap;
  font-size:11px;color:var(--text3);margin-top:3px;
}
.topbar-meta a{color:var(--accent);text-decoration:none}
.topbar-meta a:hover{text-decoration:underline}
.meta-sep{color:var(--border2)}
.topbar-right{display:flex;align-items:center;gap:8px;flex-shrink:0}
.chip{padding:4px 10px;border-radius:99px;font-size:11px;font-weight:500;background:var(--surface2);border:1px solid var(--border);color:var(--text3)}
.gate-badge{
  padding:6px 14px;border-radius:99px;font-size:11px;font-weight:700;
  letter-spacing:.3px;text-transform:uppercase;border:1.5px solid;
}
.gate-pass{background:var(--c-low-bg);border-color:var(--c-low-bd);color:var(--c-low)}
.gate-fail{background:var(--c-critical-bg);border-color:var(--c-critical-bd);color:var(--c-critical)}
.gate-off{background:var(--surface2);border-color:var(--border2);color:var(--text3)}

/* ── Scan info banner ────────────────────────────────────────────────────── */
.scan-banner{
  background:var(--surface);border-bottom:1px solid var(--border);
  padding:14px 28px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;
}
.scan-stat{display:flex;flex-direction:column;gap:2px}
.scan-stat-label{font-size:9px;letter-spacing:1.2px;text-transform:uppercase;color:var(--text3);font-weight:600}
.scan-stat-val{font-size:13px;font-weight:600;color:var(--text)}
.scan-divider{width:1px;height:32px;background:var(--border)}

/* ── Tabs ────────────────────────────────────────────────────────────────── */
.tabs{
  display:flex;align-items:center;gap:2px;padding:0 28px;
  background:var(--surface);border-bottom:2px solid var(--border);
}
.tab{
  padding:13px 16px;font-size:13px;font-weight:500;cursor:pointer;
  color:var(--text3);border-bottom:2px solid transparent;margin-bottom:-2px;
  transition:.15s;display:flex;align-items:center;gap:7px;
}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);font-weight:600}
.tab-count{
  padding:1px 7px;border-radius:99px;font-size:10px;font-weight:600;
  background:var(--surface2);border:1px solid var(--border);color:var(--text3);
}
.tab.active .tab-count{background:var(--accent-l);border-color:#bfdbfe;color:var(--accent)}
.tab-count.red{background:var(--c-critical-bg);border-color:var(--c-critical-bd);color:var(--c-critical)}

/* ── Page section ────────────────────────────────────────────────────────── */
.page{display:none;padding:24px 28px}
.page.active{display:block}

/* ── Summary cards ───────────────────────────────────────────────────────── */
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}
.scard{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-lg);padding:18px 16px;
  box-shadow:var(--shadow-sm);position:relative;overflow:hidden;transition:.2s;
}
.scard:hover{box-shadow:var(--shadow);transform:translateY(-2px)}
.scard::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px}
.scard.c-critical::after{background:var(--c-critical)}
.scard.c-high::after{background:var(--c-high)}
.scard.c-medium::after{background:var(--c-medium)}
.scard.c-low::after{background:var(--c-low)}
.scard.c-new::after{background:var(--c-new)}
.scard.c-total::after{background:var(--accent)}
.scard-label{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--text3);font-weight:600;margin-bottom:8px}
.scard-num{font-size:32px;font-weight:700;line-height:1;margin-bottom:3px;font-family:var(--mono)}
.scard.c-critical .scard-num{color:var(--c-critical)}
.scard.c-high     .scard-num{color:var(--c-high)}
.scard.c-medium   .scard-num{color:var(--c-medium)}
.scard.c-low      .scard-num{color:var(--c-low)}
.scard.c-new      .scard-num{color:var(--c-new)}
.scard.c-total    .scard-num{color:var(--accent)}
.scard-sub{font-size:10px;color:var(--text3)}

/* ── Delta panes ─────────────────────────────────────────────────────────── */
.panes{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:24px}
.pane{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:16px;box-shadow:var(--shadow-sm)}
.pane-head{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:var(--text3);font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.pane-head::after{content:'';flex:1;height:1px;background:var(--border)}
.pane-row{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px}
.pane-row:last-child{border:none}
.pane-key{color:var(--text2)}
.pane-val{font-weight:700;font-family:var(--mono);color:var(--text)}
.pane-val.red{color:var(--c-critical)}
.pane-val.ora{color:var(--c-high)}
.pane-val.grn{color:var(--c-low)}

/* ── Filter bar ──────────────────────────────────────────────────────────── */
.filterbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.fb{
  padding:6px 12px;border-radius:var(--r);border:1px solid var(--border2);
  background:var(--surface);color:var(--text2);cursor:pointer;
  font-family:var(--font);font-size:12px;font-weight:500;transition:.15s;box-shadow:var(--shadow-sm);
}
.fb:hover{border-color:var(--accent);color:var(--accent)}
.fb.active{background:var(--accent-l);border-color:#bfdbfe;color:var(--accent);font-weight:600}
.fb.fc.active{background:var(--c-critical-bg);border-color:var(--c-critical-bd);color:var(--c-critical)}
.fb.fh.active{background:var(--c-high-bg);    border-color:var(--c-high-bd);    color:var(--c-high)}
.fb.fm.active{background:var(--c-medium-bg);  border-color:var(--c-medium-bd);  color:var(--c-medium)}
.fb.fl.active{background:var(--c-low-bg);     border-color:var(--c-low-bd);     color:var(--c-low)}
.searchbox{
  flex:1;min-width:180px;padding:6px 12px;border-radius:var(--r);
  border:1px solid var(--border2);background:var(--surface);color:var(--text);
  font-family:var(--font);font-size:12px;outline:none;box-shadow:var(--shadow-sm);
  transition:.15s;
}
.searchbox:focus{border-color:var(--accent)}
.searchbox::placeholder{color:var(--text3)}

/* ── Findings table ──────────────────────────────────────────────────────── */
.ftable-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);overflow:hidden;box-shadow:var(--shadow-sm)}
.ftable{width:100%;border-collapse:collapse}
.ftable thead tr{background:var(--surface2)}
.ftable th{
  padding:10px 14px;text-align:left;border-bottom:1px solid var(--border);
  font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--text3);font-weight:600;
  white-space:nowrap;
}
.ftable tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:.1s}
.ftable tbody tr:last-child{border:none}
.ftable tbody tr:hover{background:var(--surface2)}
.ftable tbody tr.expanded{background:#fafbff}
.ftable td{padding:11px 14px;vertical-align:middle;font-size:12px}

.sev-badge{
  display:inline-flex;align-items:center;gap:5px;
  padding:3px 9px;border-radius:4px;font-size:10px;font-weight:700;
  letter-spacing:.5px;text-transform:uppercase;border:1px solid;white-space:nowrap;
}
.sev-CRITICAL{background:var(--c-critical-bg);border-color:var(--c-critical-bd);color:var(--c-critical)}
.sev-HIGH,.sev-ERROR{background:var(--c-high-bg);border-color:var(--c-high-bd);color:var(--c-high)}
.sev-MEDIUM,.sev-WARNING{background:var(--c-medium-bg);border-color:var(--c-medium-bd);color:var(--c-medium)}
.sev-LOW,.sev-INFO,.sev-note{background:var(--c-low-bg);border-color:var(--c-low-bd);color:var(--c-low)}

.new-badge{display:inline-block;padding:2px 7px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;background:var(--c-new-bg);border:1px solid var(--c-new-bd);color:var(--c-new);margin-left:5px}

.file-cell{font-family:var(--mono);font-size:11px;color:var(--accent)}
.file-cell a{color:inherit;text-decoration:none}
.file-cell a:hover{text-decoration:underline}
.rule-cell{font-family:var(--mono);font-size:11px;color:var(--text2)}
.msg-cell{font-size:12px;color:var(--text);max-width:280px}
.line-cell{font-family:var(--mono);font-size:11px;color:var(--text3)}
.tool-pill{font-size:10px;padding:2px 7px;border-radius:3px;background:var(--surface2);border:1px solid var(--border);color:var(--text3)}

.expand-icon{color:var(--text3);font-size:10px;transition:.2s;float:right}
.expanded .expand-icon{transform:rotate(180deg)}

/* ── Detail row ──────────────────────────────────────────────────────────── */
.detail-row{display:none;background:#f8f9fc}
.detail-row.open{display:table-row}
.detail-cell{padding:0 14px 16px;border-bottom:1px solid var(--border)}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding-top:12px}
.d-block{display:flex;flex-direction:column;gap:4px}
.d-block.full{grid-column:1/-1}
.d-label{font-size:9px;letter-spacing:1.2px;text-transform:uppercase;color:var(--text3);font-weight:600}
.d-val{font-size:12px;color:var(--text2);line-height:1.5}
.d-val a{color:var(--accent);text-decoration:none}
.d-val a:hover{text-decoration:underline}
.code-snippet{
  background:var(--text);color:#f1f5f9;font-family:var(--mono);
  font-size:11px;padding:10px 12px;border-radius:var(--r);
  overflow-x:auto;white-space:pre;line-height:1.6;margin-top:4px;
  border-left:3px solid var(--c-high);
}
.fix-block{background:var(--c-low-bg);border:1px solid var(--c-low-bd);border-radius:var(--r);padding:10px 12px;font-size:11px;color:var(--text2);line-height:1.6;margin-top:4px}
.ref-link{display:block;font-size:11px;color:var(--accent);text-decoration:none;padding:1px 0}
.ref-link:hover{text-decoration:underline}
.tag-row{display:flex;gap:5px;flex-wrap:wrap;margin-top:4px}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;background:var(--surface2);border:1px solid var(--border2);color:var(--text3)}

/* ── Empty / ISO table ───────────────────────────────────────────────────── */
.empty{text-align:center;padding:48px;color:var(--text3);font-size:13px}
.empty .big{font-size:36px;margin-bottom:8px}

.iso-table{width:100%;border-collapse:collapse;font-size:12px;background:var(--surface);border-radius:var(--r-lg);overflow:hidden;box-shadow:var(--shadow-sm)}
.iso-table th{padding:10px 14px;text-align:left;background:var(--surface2);border-bottom:1px solid var(--border);color:var(--text3);font-size:9px;letter-spacing:1px;text-transform:uppercase;font-weight:600}
.iso-table td{padding:10px 14px;border-bottom:1px solid var(--border);color:var(--text2);vertical-align:top}
.iso-table tr:last-child td{border:none}
.iso-table tr:hover td{background:var(--surface2)}
.iso-c{color:var(--c-low);font-weight:600}
.iso-nc{color:var(--c-critical);font-weight:600}
.iso-p{color:var(--c-high);font-weight:600}

/* ── Scrollbar ───────────────────────────────────────────────────────────── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}

@media(max-width:860px){
  .sidebar{display:none}
  .panes{grid-template-columns:1fr}
  .detail-grid{grid-template-columns:1fr}
}
</style>
</head>
<body>

<!-- ── Sidebar ───────────────────────────────────────────────────────────── -->
<nav class="sidebar">
  <div class="sidebar-brand">
    <img class="brand-logo" src="https://upload.wikimedia.org/wikipedia/commons/1/18/Logo-jacobs.png" alt="JESA"/>
    <div>
      <div class="brand-text">Security Report</div>
      <div class="brand-sub">DevSecOps</div>
    </div>
  </div>
  <div class="sidebar-nav">
    <div class="nav-label">Views</div>
    <a class="nav-item active" href="#" onclick="showPage('dashboard',this);return false">
      <span class="nav-icon">📊</span>Dashboard
    </a>
    <a class="nav-item" href="#" onclick="showPage('all',this);return false">
      <span class="nav-icon">🔍</span>All Issues
      <span class="nav-badge red" id="snb-all">0</span>
    </a>
    <a class="nav-item" href="#" onclick="showPage('new',this);return false">
      <span class="nav-icon">🆕</span>New in PR
      <span class="nav-badge red" id="snb-new">0</span>
    </a>
    <a class="nav-item" href="#" onclick="showPage('compliance',this);return false">
      <span class="nav-icon">📋</span>ISO 27001
    </a>
  </div>
  <div class="sidebar-footer">
    Build <strong id="sb-build">—</strong><br>
    <span id="sb-date">—</span><br>
    <span style="font-size:9px;letter-spacing:.8px;text-transform:uppercase">ISO 27001:2022 · A.12.6.1</span>
  </div>
</nav>

<!-- ── Main ──────────────────────────────────────────────────────────────── -->
<main class="main">

  <!-- Topbar -->
  <div class="topbar">
    <div class="topbar-left">
      <div class="topbar-title" id="tb-repo">Security Assessment Report</div>
      <div class="topbar-meta">
        <span id="tb-branch">—</span>
        <span class="meta-sep">·</span>
        <span id="tb-pr">—</span>
        <span class="meta-sep">·</span>
        <span>Baseline: <code style="font-size:10px;color:var(--accent)" id="tb-base">—</code></span>
      </div>
    </div>
    <div class="topbar-right">
      <span class="chip" id="tb-date">—</span>
      <span class="gate-badge" id="gate-badge">—</span>
    </div>
  </div>

  <!-- Scan info banner -->
  <div class="scan-banner">
    <div class="scan-stat"><div class="scan-stat-label">Repository</div><div class="scan-stat-val" id="bi-repo">—</div></div>
    <div class="scan-divider"></div>
    <div class="scan-stat"><div class="scan-stat-label">Tools</div><div class="scan-stat-val">Opengrep · Gitleaks</div></div>
    <div class="scan-divider"></div>
    <div class="scan-stat"><div class="scan-stat-label">New findings</div><div class="scan-stat-val" id="bi-new">—</div></div>
    <div class="scan-divider"></div>
    <div class="scan-stat"><div class="scan-stat-label">Total findings</div><div class="scan-stat-val" id="bi-total">—</div></div>
    <div class="scan-divider"></div>
    <div class="scan-stat"><div class="scan-stat-label">Quality gate</div><div class="scan-stat-val" id="bi-gate">—</div></div>
    <div class="scan-divider"></div>
    <div class="scan-stat"><div class="scan-stat-label">Scanned</div><div class="scan-stat-val" id="bi-date">—</div></div>
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <div class="tab active" onclick="showPage('dashboard',null,this)" id="tab-dashboard">📊 Dashboard</div>
    <div class="tab" onclick="showPage('all',null,this)" id="tab-all">🔍 All Issues <span class="tab-count red" id="tc-all">0</span></div>
    <div class="tab" onclick="showPage('new',null,this)" id="tab-new">🆕 New in PR <span class="tab-count red" id="tc-new">0</span></div>
    <div class="tab" onclick="showPage('compliance',null,this)" id="tab-compliance">📋 ISO 27001</div>
  </div>

  <!-- ── DASHBOARD PAGE ────────────────────────────────────────────────── -->
  <div class="page active" id="page-dashboard">
    <div class="cards-grid" id="cards-grid"></div>
    <div class="panes" id="panes-grid"></div>
  </div>

  <!-- ── ALL ISSUES PAGE ───────────────────────────────────────────────── -->
  <div class="page" id="page-all">
    <div class="filterbar">
      <button class="fb active" onclick="setF('all',this,'all')">All</button>
      <button class="fb fc" onclick="setF('CRITICAL',this,'all')">Critical</button>
      <button class="fb fh" onclick="setF('ERROR',this,'all')">High</button>
      <button class="fb fm" onclick="setF('WARNING',this,'all')">Medium</button>
      <button class="fb fl" onclick="setF('INFO',this,'all')">Low</button>
      <input class="searchbox" type="text" placeholder="Search rule, file, message…" oninput="doSearch(this.value,'all')"/>
    </div>
    <div class="ftable-wrap" id="tbl-all"></div>
  </div>

  <!-- ── NEW IN PR PAGE ────────────────────────────────────────────────── -->
  <div class="page" id="page-new">
    <div class="filterbar">
      <button class="fb active" onclick="setF('all',this,'new')">All</button>
      <button class="fb fc" onclick="setF('CRITICAL',this,'new')">Critical</button>
      <button class="fb fh" onclick="setF('ERROR',this,'new')">High</button>
      <button class="fb fm" onclick="setF('WARNING',this,'new')">Medium</button>
      <button class="fb fl" onclick="setF('INFO',this,'new')">Low</button>
      <input class="searchbox" type="text" placeholder="Search rule, file, message…" oninput="doSearch(this.value,'new')"/>
    </div>
    <div class="ftable-wrap" id="tbl-new"></div>
  </div>

  <!-- ── ISO 27001 PAGE ────────────────────────────────────────────────── -->
  <div class="page" id="page-compliance">
    <table class="iso-table">
      <thead><tr><th>Control</th><th>Title</th><th>Tool</th><th>Status</th><th>Evidence</th></tr></thead>
      <tbody id="iso-body"></tbody>
    </table>
  </div>

</main>

<script>
HTML_END

# Inject shell variables as JS
printf '// ── Injected data ────────────────────────────────────────────────────────────\n' >> report.html
printf 'const META={\n' >> report.html
printf '  repo:        "%s",\n' "${REPO}"             >> report.html
printf '  branch:      "%s",\n' "${BRANCH}"           >> report.html
printf '  buildNum:    "%s",\n' "${BUILD_NUM}"         >> report.html
printf '  prTitle:     "%s",\n' "${PR_TITLE_JS}"       >> report.html
printf '  prUrl:       "%s",\n' "${PR_URL}"            >> report.html
printf '  prId:        "%s",\n' "${PR_ID}"             >> report.html
printf '  baseline:    "%s",\n' "${BASELINE}"          >> report.html
printf '  scanDate:    "%s",\n' "${SCAN_DATE}"         >> report.html
printf '  repoUrl:     "%s",\n' "${AZURE_REPO_BASE_URL}" >> report.html
printf '  gateEnabled: %s,\n'  "${ENABLE_QUALITY_GATE}" >> report.html
printf '  ogNewCount:  %s,\n'  "${OG_NEW_COUNT}"      >> report.html
printf '  ogFullCount: %s,\n'  "${OG_FULL_COUNT}"     >> report.html
printf '  glNewCount:  %s,\n'  "${GL_NEW_COUNT}"      >> report.html
printf '  glFullCount: %s,\n'  "${GL_FULL_COUNT}"     >> report.html
printf '};\n\n'                                        >> report.html
printf 'const OG_NEW  = %s;\n' "${OG_NEW_JS}"         >> report.html
printf 'const OG_FULL = %s;\n' "${OG_FULL_JS}"        >> report.html
printf 'const GL_NEW  = %s;\n' "${GL_NEW_JS}"         >> report.html
printf 'const GL_FULL = %s;\n\n' "${GL_FULL_JS}"      >> report.html

cat >> report.html << 'JS_END'
// ── Normalise ─────────────────────────────────────────────────────────────────
const GL_FIX='Rotate the exposed credential immediately. Remove it from git history using git-filter-repo. Use environment variables or a dedicated secrets manager (Azure Key Vault / HashiCorp Vault).';
const GL_REFS=['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html','https://cwe.mitre.org/data/definitions/798.html'];
function sarifSev(l){return l==='error'?'ERROR':l==='warning'?'WARNING':l==='note'?'INFO':'INFO';}
function nOgN(f){return{...f,severity:f.severity||'INFO',isNew:true,tool:'Opengrep',commit:'',author:''};}
function nOgF(f){return{...f,severity:sarifSev(f.severity),isNew:false,tool:'Opengrep',commit:'',author:''};}
function nGlN(f){return{...f,severity:'CRITICAL',code:'*** redacted ***',fix:GL_FIX,cwe:'CWE-798',owasp:'A07:2021',refs:GL_REFS,isNew:true,tool:'Gitleaks'};}
function nGlF(f){return{...f,severity:'CRITICAL',code:'*** redacted ***',fix:GL_FIX,cwe:'CWE-798',owasp:'A07:2021',refs:GL_REFS,isNew:false,tool:'Gitleaks',commit:'',author:''};}

const allF=[...OG_FULL.map(nOgF),...GL_FULL.map(nGlF)];
const newF=[...OG_NEW.map(nOgN),...GL_NEW.map(nGlN)];
const nKeys=new Set(newF.map(f=>f.file+':'+f.line+':'+f.rule));
allF.forEach(f=>{if(nKeys.has(f.file+':'+f.line+':'+f.rule))f.isNew=true;});

// ── Severity helpers ──────────────────────────────────────────────────────────
const SORD={CRITICAL:0,ERROR:1,WARNING:2,INFO:3,note:3,error:1,warning:2};
const SLBL={CRITICAL:'Critical',ERROR:'High',WARNING:'Medium',INFO:'Low',note:'Low',error:'High',warning:'Medium'};
const SCLS={CRITICAL:'CRITICAL',ERROR:'ERROR',WARNING:'WARNING',INFO:'INFO',note:'INFO',error:'ERROR',warning:'WARNING'};
function so(s){return SORD[s]??99;}

// ── Azure Repos link ──────────────────────────────────────────────────────────
function azdoLink(file,line){
  if(!META.repoUrl) return null;
  const branch=META.branch.replace(/^refs\/heads\//,'');
  return META.repoUrl+'?path='+encodeURIComponent('/'+file.replace(/^\.\//,''))+'&version=GB'+encodeURIComponent(branch)+'&line='+line;
}

// ── Escape ────────────────────────────────────────────────────────────────────
function e(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ── Filter/search state ───────────────────────────────────────────────────────
const FS={all:'all',new:'all'}, SS={all:'',new:''};
function setF(sev,btn,ctx){
  FS[ctx]=sev;
  btn.closest('.filterbar').querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderTable(ctx);
}
function doSearch(v,ctx){SS[ctx]=v.toLowerCase();renderTable(ctx);}
function applyFilters(arr,ctx){
  const sev=FS[ctx]||'all',q=SS[ctx]||'';
  return arr.filter(f=>{
    const sm=sev==='all'||(SCLS[f.severity]||f.severity)===sev;
    const qm=!q||f.file.toLowerCase().includes(q)||f.rule.toLowerCase().includes(q)||f.message.toLowerCase().includes(q);
    return sm&&qm;
  });
}

// ── Render findings table ─────────────────────────────────────────────────────
let openRow=null;

function renderTable(ctx){
  const src=ctx==='new'?newF:allF;
  const rows=applyFilters(src,ctx);
  const wrap=document.getElementById('tbl-'+ctx);
  if(!rows.length){wrap.innerHTML='<div class="empty"><div class="big">✅</div>No findings match the filter.</div>';return;}

  const sorted=[...rows].sort((a,b)=>so(a.severity)-so(b.severity));

  let html='<table class="ftable"><thead><tr>'
    +'<th></th><th>Severity</th><th>Rule</th><th>Description</th><th>File</th><th>Line</th><th>Tool</th>'
    +'</tr></thead><tbody>';

  sorted.forEach((f,i)=>{
    const sevCls=SCLS[f.severity]||f.severity;
    const lnk=azdoLink(f.file,f.line);
    const fileTd=lnk?'<a href="'+e(lnk)+'" target="_blank" onclick="event.stopPropagation()">'+e(f.file)+'</a>':e(f.file);
    const newBadge=f.isNew?'<span class="new-badge">NEW</span>':'';

    // References HTML for detail
    let refsHtml='';
    if(f.refs&&f.refs.length){
      const vr=f.refs.filter(r=>r&&String(r).startsWith('http'));
      if(vr.length) refsHtml=vr.map(r=>'<a class="ref-link" href="'+e(r)+'" target="_blank">→ '+e(r)+'</a>').join('');
    }
    let commitHtml=f.commit?'<div class="d-block"><div class="d-label">Commit</div><div class="d-val"><code>'+e(f.commit.slice(0,12))+'</code>'+(f.author?' · '+e(f.author):'')+'</div></div>':'';
    let tagsHtml=(f.cwe?'<span class="tag">'+e(f.cwe)+'</span>':'')+(f.owasp?'<span class="tag">'+e(f.owasp)+'</span>':'');

    html+=`
      <tr class="issue-row" data-idx="${i}" onclick="toggleRow(this,${i})">
        <td style="width:20px"><span class="expand-icon">▼</span></td>
        <td><span class="sev-badge sev-${sevCls}">${e(SLBL[f.severity]||f.severity)}</span>${newBadge}</td>
        <td class="rule-cell">${e(f.rule)}</td>
        <td class="msg-cell">${e(f.message)}</td>
        <td class="file-cell">${fileTd}</td>
        <td class="line-cell">${f.line}</td>
        <td><span class="tool-pill">${e(f.tool)}</span></td>
      </tr>
      <tr class="detail-row" id="dr-${ctx}-${i}">
        <td class="detail-cell" colspan="7">
          <div class="detail-grid">
            <div class="d-block full"><div class="d-label">Rule ID</div><div class="d-val"><code>${e(f.rule)}</code></div></div>
            <div class="d-block full"><div class="d-label">Explanation</div><div class="d-val">${e(f.message)}</div></div>
            ${f.fix?`<div class="d-block full"><div class="d-label">Remediation</div><div class="fix-block">${e(f.fix)}</div></div>`:''}
            <div class="d-block full"><div class="d-label">Vulnerable Code / Match</div><div class="code-snippet">${e(f.code||'(no snippet available)')}</div></div>
            ${tagsHtml?`<div class="d-block full"><div class="d-label">Tags</div><div class="tag-row">${tagsHtml}</div></div>`:''}
            ${commitHtml}
            ${refsHtml?`<div class="d-block full"><div class="d-label">Remediation References</div>${refsHtml}</div>`:''}
          </div>
        </td>
      </tr>`;
  });

  html+='</tbody></table>';
  wrap.innerHTML=html;
}

function toggleRow(tr,idx){
  const ctx=tr.closest('[id^="tbl-"]').id.replace('tbl-','');
  const drId='dr-'+ctx+'-'+idx;
  const dr=document.getElementById(drId);
  if(!dr) return;
  const isOpen=dr.classList.contains('open');
  // close previous
  document.querySelectorAll('.detail-row.open').forEach(r=>r.classList.remove('open'));
  document.querySelectorAll('.issue-row.expanded').forEach(r=>r.classList.remove('expanded'));
  if(!isOpen){dr.classList.add('open');tr.classList.add('expanded');}
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
function renderDashboard(){
  const totalNew=META.ogNewCount+META.glNewCount;
  const totalFull=META.ogFullCount+META.glFullCount;
  const bySev={CRITICAL:0,ERROR:0,WARNING:0,INFO:0};
  allF.forEach(f=>{const s=SCLS[f.severity]||f.severity; bySev[s]!==undefined?bySev[s]++:bySev.INFO++;});

  document.getElementById('cards-grid').innerHTML=[
    {lbl:'New in PR',   num:totalNew,       sub:'introduced by this PR',    cls:'c-new',    zero:'c-total'},
    {lbl:'Critical',    num:bySev.CRITICAL, sub:'secrets & critical SAST',  cls:'c-critical',zero:'c-total'},
    {lbl:'High',        num:bySev.ERROR,    sub:'high severity',             cls:'c-high',   zero:'c-total'},
    {lbl:'Medium',      num:bySev.WARNING,  sub:'medium severity',           cls:'c-medium', zero:'c-total'},
    {lbl:'Low',         num:bySev.INFO,     sub:'low severity',              cls:'c-low',    zero:'c-total'},
    {lbl:'Total',       num:totalFull,      sub:'full codebase',             cls:'c-total',  zero:'c-total'},
  ].map(c=>`<div class="scard ${c.num>0?c.cls:c.zero}">
    <div class="scard-label">${c.lbl}</div>
    <div class="scard-num">${c.num}</div>
    <div class="scard-sub">${c.sub}</div>
  </div>`).join('');

  function pv(n,thresh){return`<span class="pane-val ${n>thresh?n>0?'red':'grn':'grn'}">${n}</span>`;}

  document.getElementById('panes-grid').innerHTML=`
    <div class="pane">
      <div class="pane-head">New code (PR delta)</div>
      <div class="pane-row"><span class="pane-key">Opengrep — SAST</span>${pv(META.ogNewCount,0)}</div>
      <div class="pane-row"><span class="pane-key">Gitleaks — Secrets</span>${pv(META.glNewCount,0)}</div>
      <div class="pane-row" style="border-top:2px solid var(--border);padding-top:8px">
        <span class="pane-key" style="font-weight:700;color:var(--text)">Total new</span>
        ${pv(totalNew,0)}
      </div>
    </div>
    <div class="pane">
      <div class="pane-head">Full codebase</div>
      <div class="pane-row"><span class="pane-key">Opengrep — SAST</span>${pv(META.ogFullCount,0)}</div>
      <div class="pane-row"><span class="pane-key">Gitleaks — Secrets</span>${pv(META.glFullCount,0)}</div>
      <div class="pane-row" style="border-top:2px solid var(--border);padding-top:8px">
        <span class="pane-key" style="font-weight:700;color:var(--text)">Total</span>
        ${pv(totalFull,0)}
      </div>
    </div>`;
}

// ── ISO 27001 ─────────────────────────────────────────────────────────────────
function renderISO(){
  const totalNew=META.ogNewCount+META.glNewCount;
  const controls=[
    {id:'A.12.6.1',title:'Management of technical vulnerabilities',tool:'Opengrep',evidence:'SAST delta scan on every PR; new findings block merge when gate is enabled.',status:META.ogFullCount>0?'partial':'compliant'},
    {id:'A.14.2.3',title:'Technical review after platform changes',tool:'Opengrep+Gitleaks',evidence:'Full codebase scan on every PR targeting develop.',status:totalNew===0?'compliant':'noncompliant'},
    {id:'A.8.8',title:'Vulnerability management (2022)',tool:'Opengrep',evidence:'Automated SAST with SARIF artifacts published per build.',status:'compliant'},
    {id:'A.9.4.3',title:'Password management system',tool:'Gitleaks',evidence:'Secret scanning on full commit history; credentials flagged as Critical.',status:META.glFullCount>0?'noncompliant':'compliant'},
    {id:'A.12.4.1',title:'Event logging',tool:'Pipeline Artifacts',evidence:'Delta JSON + full SARIF retained as signed build artifacts per scan.',status:'compliant'},
  ];
  document.getElementById('iso-body').innerHTML=controls.map(c=>{
    const cls=c.status==='compliant'?'iso-c':c.status==='noncompliant'?'iso-nc':'iso-p';
    const lbl=c.status==='compliant'?'✓ Compliant':c.status==='noncompliant'?'✗ Non-Compliant':'~ Partial';
    return`<tr><td><strong>${e(c.id)}</strong></td><td>${e(c.title)}</td><td><span class="tag">${e(c.tool)}</span></td><td class="${cls}">${lbl}</td><td>${e(c.evidence)}</td></tr>`;
  }).join('');
}

// ── Meta fields ───────────────────────────────────────────────────────────────
function renderMeta(){
  const totalNew=META.ogNewCount+META.glNewCount;
  const totalFull=META.ogFullCount+META.glFullCount;
  const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
  const setH=(id,h)=>{const el=document.getElementById(id);if(el)el.innerHTML=h;};

  set('tb-repo', META.repo);
  set('tb-branch', META.branch.replace(/^refs\/heads\//,''));
  set('tb-base', META.baseline.slice(0,8));
  set('tb-date', META.scanDate);
  set('bi-repo', META.repo);
  set('bi-new',  totalNew+' finding'+(totalNew!==1?'s':''));
  set('bi-total',totalFull+' finding'+(totalFull!==1?'s':''));
  set('bi-date', META.scanDate);
  set('bi-gate', META.gateEnabled?(totalNew===0?'Passed':'Failed'):'Disabled');
  set('sb-build','#'+META.buildNum);
  set('sb-date', META.scanDate);

  // tab/nav counts
  ['all','new'].forEach(ctx=>{
    const n=ctx==='new'?totalNew:totalFull;
    set('tc-'+ctx,n); set('snb-'+ctx,n);
  });

  // PR link
  const prEl=document.getElementById('tb-pr');
  if(prEl){
    if(META.prUrl&&META.prId){
      const t=META.prTitle&&META.prTitle!=='N/A'?' — '+META.prTitle:'';
      prEl.innerHTML='<a href="'+e(META.prUrl)+'" target="_blank">PR #'+e(META.prId)+e(t)+'</a>';
    }else if(META.prTitle&&META.prTitle!=='N/A'){
      prEl.textContent=META.prTitle;
    }else{prEl.textContent='';}
  }

  // Gate badge
  const gb=document.getElementById('gate-badge');
  if(!META.gateEnabled){gb.className='gate-badge gate-off';gb.textContent='Gate Disabled';}
  else if(totalNew===0){gb.className='gate-badge gate-pass';gb.textContent='✓ Gate Passed';}
  else{gb.className='gate-badge gate-fail';gb.textContent='✗ Gate Failed';}

  document.title='Security Report — '+META.repo+' — Build #'+META.buildNum;
}

// ── Navigation ────────────────────────────────────────────────────────────────
const PAGES=['dashboard','all','new','compliance'];

function showPage(id, navEl, tabEl){
  PAGES.forEach(p=>{
    document.getElementById('page-'+p)?.classList.remove('active');
    document.getElementById('tab-'+p)?.classList.remove('active');
  });
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+id)?.classList.add('active');
  document.getElementById('tab-'+id)?.classList.add('active');
  if(navEl) navEl.classList.add('active');
  if(tabEl) tabEl.classList.add('active');
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded',()=>{
  renderMeta();
  renderDashboard();
  renderTable('all');
  renderTable('new');
  renderISO();
});
</script>
</body>
</html>
JS_END

echo "✅ report.html generated — $(wc -c < report.html | tr -d ' ') bytes"