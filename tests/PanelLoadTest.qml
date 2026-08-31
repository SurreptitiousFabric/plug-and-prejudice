import QtQuick
import Quickshell

ShellRoot {
  id: testRoot
  property var panel: null

  Component { id: panelComponent; Panel {} }

  Component.onCompleted: {
    panel = panelComponent.createObject(testRoot, {"manifest": fakeManifest})
    if (!panel) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL component creation")
      Qt.exit(1)
      return
    }
    var normalized = panel.plain("before\u001b[31m\u061c\u200e\u200f\u202e\u2066after", 200)
    if (normalized.indexOf("\u001b") !== -1 || normalized.indexOf("\u061c") !== -1
        || normalized.indexOf("\u200e") !== -1 || normalized.indexOf("\u200f") !== -1
        || normalized.indexOf("\u202e") !== -1 || normalized.indexOf("\u2066") !== -1) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL control normalization")
      Qt.exit(1)
      return
    }
    if (panel.plain("123456", 4) !== "1234…") {
      console.error("PLUG_PREJUDICE_PANEL_FAIL length bound")
      Qt.exit(1)
      return
    }
    if (panel.plainInline("before\tFAKE TAB\nFAKE ROW\rAFTER", 200) !== "before FAKE TAB FAKE ROW AFTER") {
      console.error("PLUG_PREJUDICE_PANEL_FAIL inline layout normalization")
      Qt.exit(1)
      return
    }
    if (panel.brokerPath !== "/usr/bin/plug-prejudice-broker" || panel.protocolVersion !== "1.0.0") {
      console.error("PLUG_PREJUDICE_PANEL_FAIL fixed broker protocol boundary")
      Qt.exit(1)
      return
    }
    var point = {"path": "install.sh", "lineStart": 42, "lineEnd": 44}
    if (panel.evidenceLabel({"evidence": [point]}) !== "install.sh:42–44"
        || panel.evidenceLabel({"evidence": {"0": point, "length": 1}}) !== "install.sh:42–44"
        || panel.firstValue("hostile") !== null) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL evidence location")
      Qt.exit(1)
      return
    }
    Qt.callLater(finish)
  }

  function finish() {
    panel.pluginIds = ["one", "two"]
    panel.selectedPlugin = 0
    panel.moveCursor(0, -1)
    if (panel.selectedPlugin !== 0) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL plugin cursor lower bound")
      Qt.exit(1)
      return
    }
    panel.moveCursor(0, 3)
    if (panel.selectedPlugin !== 1) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL plugin cursor upper bound")
      Qt.exit(1)
      return
    }
    var findingReference = "PP-1234567890ABCDEF1234567890ABCDEF"
    var unknownReference = "PP-FEDCBA0987654321FEDCBA0987654321"
    panel.acceptReport(JSON.stringify({
      "schemaVersion": "2.0.0",
      "status": "incomplete",
      "scan": {"sandboxed": true},
      "target": {"displayName": "hostile fixture", "manifest": {
        "description": "Useful helper\nFAKE CRITICAL ROW <img src='https://example.invalid/a'>\u202e",
        "kinds": ["panel\rFAKE TAB", "service\tFAKE"]
      }},
      "review": {
      "securityImpact": {"level": "high", "reasons": [{"reference": findingReference, "title": "impact\nFAKE\u202e", "scope": "runtime"}]},
      "evidenceConfidence": {"level": "medium", "high": 1, "medium": 1, "low": 0, "reasons": [{"reference": findingReference, "title": "impact", "scope": "runtime"}]},
      "analysisCoverage": {"level": "partial", "denominator": "retained supported executable, configuration, archive, and binary artifact files", "analyzedUnits": 1, "partialUnits": 1, "unanalyzedUnits": 1, "totalUnits": 3, "percentage": 33},
      "unknownBehavior": {"level": "moderate", "unknowns": 1, "limitations": 0, "errors": 0, "reasons": [{"reference": unknownReference, "title": "snapshot binding unknown", "scope": "unknown"}]},
      "counts": {"facts": 1, "inferences": 0, "unknownBehaviors": 1},
      "mainReasons": [{"reference": findingReference, "title": "impact\nFAKE\u202e", "scope": "runtime"}, {"reference": unknownReference, "title": "snapshot binding unknown", "scope": "unknown"}]
      },
      "operations": [],
      "findings": [{"reference": findingReference, "severity": "high", "claim": "fact", "title": "impact", "explanation": "retained finding", "scope": "runtime", "confidence": "high", "evidence": []}],
      "resources": [],
      "unknowns": [{"reference": unknownReference, "category": "external-evidence-binding", "reason": "unresolved-data-flow", "description": "snapshot binding unknown", "scope": "unknown", "confidence": "medium", "evidence": [], "origins": [], "affectedOperationIds": [], "suppressedRules": []}],
      "relationships": [],
      "limitations": [],
      "errors": []
    }))
    if (panel.view !== "report" || !panel.currentReport || panel.currentReport.findings.length !== 1
        || panel.currentReport.unknowns.length !== 1 || panel.errorText !== "") {
      console.error("PLUG_PREJUDICE_PANEL_FAIL current 128-bit report acceptance")
      Qt.exit(1)
      return
    }
    var authorClaim = panel.authorClaimLabel() + panel.authorClaimDescription()
    if (authorClaim.indexOf("AUTHOR CLAIM · KINDS · ") !== 0 || authorClaim.indexOf("<img") === -1
        || authorClaim.indexOf("\n") !== -1 || authorClaim.indexOf("\r") !== -1
        || authorClaim.indexOf("\t") !== -1 || authorClaim.indexOf("\u202e") !== -1) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL hostile author claim rendering")
      Qt.exit(1)
      return
    }
    var reviewText = panel.reviewSummaryText() + panel.reviewCountsText() + panel.mainReasonsText()
    if (!panel.validReviewSummary(panel.currentReport.review) || reviewText.indexOf("Security impact HIGH") === -1
        || reviewText.indexOf("33%") === -1 || reviewText.indexOf(findingReference) === -1
        || reviewText.indexOf("[runtime]") === -1
        || reviewText.indexOf("\n") !== -1 || reviewText.indexOf("\u202e") !== -1) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL review summary rendering")
      Qt.exit(1)
      return
    }
    var invalidReview = JSON.parse(JSON.stringify(panel.currentReport.review))
    invalidReview.analysisCoverage.percentage = 99
    if (panel.validReviewSummary(invalidReview)) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL forged coverage accepted")
      Qt.exit(1)
      return
    }
    var staleReferenceReview = JSON.parse(JSON.stringify(panel.currentReport.review))
    staleReferenceReview.securityImpact.reasons[0].reference = "PP-1234567890ABCDEF"
    if (panel.validReviewSummary(staleReferenceReview)) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL obsolete 64-bit reference accepted")
      Qt.exit(1)
      return
    }
    panel.reportSection = 0
    panel.visibleFindings = [{"title": "one"}, {"title": "two"}]
    panel.visibleOperations = [{"command": "curl", "arguments": ["https://example.invalid"]}]
    panel.visibleResources = [{"value": "resource"}]
    panel.moveCursor(1, 0)
    if (panel.reportSection !== 1 || panel.selectedReportRow !== 0) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL report section navigation")
      Qt.exit(1)
      return
    }
    var hostileOperation = {
      "reference": "PP-1234567890ABCDEF1234567890ABCDEF",
      "category": "process-execution",
      "command": "<img src='https://example.invalid/a'>\nFAKE FINDING\u202e",
      "arguments": ["\u061c", "before\u001bafter\tFAKE META"],
      "dynamic": true,
      "scope": "runtime",
      "confidence": "medium",
      "evidence": {"inputId": "input-target\nFAKE", "path": "run.sh", "lineStart": 4, "operation": "curl <hostile>"},
      "provenance": {"ruleId": "rule\nFAKE", "analyzer": "analyzer\u202e", "analyzerVersion": "1\t2", "evidenceSource": "target-source"}
    }
    var renderedOperation = panel.rowTitle(hostileOperation) + panel.rowBody(hostileOperation)
      + panel.rowMeta(hostileOperation) + panel.rowEvidence(hostileOperation)
    if (renderedOperation.indexOf("\u202e") !== -1 || renderedOperation.indexOf("\u061c") !== -1
        || renderedOperation.indexOf("\u001b") !== -1 || renderedOperation.indexOf("\n") !== -1
        || renderedOperation.indexOf("\t") !== -1 || renderedOperation.indexOf("<img") === -1
        || renderedOperation.indexOf("analyzer analyzer�") === -1 || renderedOperation.indexOf("evidence source target-source") === -1
        || renderedOperation.indexOf("evidence input input-target FAKE") === -1) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL hostile operation rendering")
      Qt.exit(1)
      return
    }
    panel.currentReport = {"evidenceInputs": [{"id": "input-omarchy\nFAKE", "type": "omarchy-audit", "documentSha256": "abc\u202e", "format": "pr8439-732b104", "version": "pr8439-732b104"}]}
    var inputSummary = panel.evidenceInputSummary()
    if (inputSummary.indexOf("document SHA-256 abc�") === -1 || inputSummary.indexOf("target snapshot binding unavailable") === -1
        || inputSummary.indexOf("subject snapshot") !== -1 || inputSummary.indexOf("\n") !== -1 || inputSummary.indexOf("\u202e") !== -1) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL external evidence identity rendering")
      Qt.exit(1)
      return
    }
    panel.reportSection = 0
    panel.currentReport = {"relationships": [
      {"type": "inferred-from\nFAKE ROW", "from": "PP-FINDING00000001", "to": "PP-FACT0000000001\u202e"},
      {"type": "disagrees-with", "from": "PP-EXTERNAL0000001", "to": "PP-FINDING00000001"},
      {"type": "ignored", "from": "PP-OTHER000000001", "to": "PP-FACT0000000002"}
    ]}
    var hostileFinding = {"reference": "PP-FINDING00000001"}
    panel.visibleFindings = [hostileFinding]
    panel.setVisibleRelationships(panel.currentReport.relationships)
    var chain = panel.evidenceChain(hostileFinding)
    if (chain.indexOf("Evidence chain: PP-FINDING00000001") !== 0 || chain.indexOf("inferred-from FAKE ROW") === -1
        || chain.indexOf("PP-FACT0000000001") === -1 || chain.indexOf("disagrees-with PP-EXTERNAL0000001") === -1 || chain.indexOf("ignored") !== -1
        || chain.indexOf("\n") !== -1 || chain.indexOf("\u202e") !== -1) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL hostile evidence-chain rendering")
      Qt.exit(1)
      return
    }
    var limitations = []
    var errors = []
    for (var i = 0; i < 400; i++) {
      limitations.push({"code": "limit-" + i, "description": "unknown"})
      errors.push({"code": "error-" + i, "message": "failed"})
    }
    panel.setVisibleUnknowns([], limitations, errors)
    panel.reportSection = 3
    if (panel.visibleLimitations.length !== 250 || panel.visibleErrors.length !== 250
        || panel.reportRows().length !== 500) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL limits fair bound")
      Qt.exit(1)
      return
    }
    var behaviorUnknowns = []
    for (var unknownIndex = 0; unknownIndex < 400; unknownIndex++)
      behaviorUnknowns.push({"reference": "PP-UNKNOWN" + unknownIndex, "reason": "dynamic-value", "description": "unresolved", "origins": []})
    panel.setVisibleUnknowns(behaviorUnknowns, limitations, errors)
    if (panel.visibleBehaviorUnknowns.length !== 166 || panel.visibleLimitations.length !== 166
        || panel.visibleErrors.length !== 168 || panel.reportRows().length !== 500) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL three-way unknown bound")
      Qt.exit(1)
      return
    }
    var unknownRow = {
      "reference": "PP-UNKNOWN00000001", "reason": "dynamic-value", "description": "Executable unresolved\nFAKE ROW\u202e",
      "scope": "runtime", "confidence": "high",
      "evidence": [{"path": "run.sh", "lineStart": 4}],
      "origins": [{"kind": "assignment\nFAKE", "name": "helper\u202e", "evidence": {"path": "run.sh", "lineStart": 1}}],
      "provenance": {"ruleId": "unknown/v1", "analyzer": "scanner", "analyzerVersion": "1", "evidenceSource": "target-source"}
    }
    var renderedUnknown = panel.rowTitle(unknownRow) + panel.rowBody(unknownRow) + panel.rowMeta(unknownRow) + panel.rowEvidence(unknownRow)
    if (renderedUnknown.indexOf("UNKNOWN · PP-UNKNOWN00000001") === -1 || renderedUnknown.indexOf("assignment FAKE helper� at run.sh:1") === -1
        || renderedUnknown.indexOf("\u202e") !== -1) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL explicit unknown rendering")
      Qt.exit(1)
      return
    }
    var findings = []
    var resources = []
    for (var priorityIndex = 0; priorityIndex < 600; priorityIndex++) {
      findings.push({"severity": "low", "title": "low-" + priorityIndex})
      resources.push({"sensitive": false, "value": "ordinary-" + priorityIndex})
    }
    findings.push({"severity": "HIGH", "title": "late-high"})
    resources.push({"sensitive": true, "value": "late-sensitive"})
    panel.setVisibleFindings(findings)
    panel.setVisibleResources(resources)
    if (panel.visibleFindings.length !== 500 || panel.visibleFindings[0].title !== "late-high"
        || panel.visibleFindings[1].title !== "low-0" || panel.visibleFindings[499].title !== "low-498"
        || panel.visibleResources.length !== 500 || panel.visibleResources[0].value !== "late-sensitive"
        || panel.visibleResources[1].value !== "ordinary-0"
        || panel.visibleResources[499].value !== "ordinary-498") {
      console.error("PLUG_PREJUDICE_PANEL_FAIL stable priority bounds")
      Qt.exit(1)
      return
    }
    var hostileError = {
      "code": "read-failed\u202e",
      "message": "<img src='https://example.invalid/a'>\u061c before\u001bafter",
      "path": "run.sh"
    }
    var renderedError = panel.rowTitle(hostileError) + panel.rowBody(hostileError) + panel.rowMeta(hostileError)
    if (renderedError.indexOf("ERROR · read-failed") !== 0 || renderedError.indexOf("<img") === -1
        || renderedError.indexOf("\u202e") !== -1 || renderedError.indexOf("\u061c") !== -1
        || renderedError.indexOf("\u001b") !== -1
        || panel.rowTitle({"code": "dynamic", "description": "unknown"}).indexOf("UNKNOWN · ") !== 0) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL hostile limits rendering")
      Qt.exit(1)
      return
    }
    panel.busy = false
    panel.reportSection = 3
    panel.selectedReportRow = 0
    panel.setVisibleUnknowns([], [], [hostileError])
    panel.moveCursor(0, 2)
    if (panel.selectedReportRow !== 0) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL report cursor upper bound")
      Qt.exit(1)
      return
    }
    console.log("PLUG_PREJUDICE_PANEL_PASS")
    panel.destroy()
    panel = null
    Qt.callLater(Qt.quit)
  }

  QtObject { id: fakeManifest; property string sourceDir: "" }
}
