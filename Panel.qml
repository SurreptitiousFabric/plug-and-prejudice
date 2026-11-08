pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Item {
  id: root

  property var shell: null
  property var manifest: null
  property bool closingFromHost: false
  property string view: "plugins" // plugins | report | error
  property bool busy: false
  property var pluginIds: []
  property int selectedPlugin: 0
  property var currentReport: null
  property var visibleFindings: []
  property var visibleOperations: []
  property var visibleResources: []
  property var visibleLimitations: []
  property var visibleErrors: []
  property var visibleBehaviorUnknowns: []
  property var visibleRelationshipChains: ({})
  property var visibleRelationshipTotals: ({})
  property int reportSection: 0
  property int selectedReportRow: 0
  property string errorText: ""
  property string diagnosticText: ""

  readonly property string pluginId: "io.github.surreptitiousfabric.plug-and-prejudice"
  readonly property string brokerPath: "/usr/bin/plug-prejudice-broker"
  readonly property string protocolVersion: "1.0.0"
  readonly property color foreground: Color.foreground
  readonly property color background: Color.background
  readonly property color accent: Color.accent
  readonly property color urgent: Color.urgent
  readonly property string fontFamily: Style.font.family

  function open(payloadJson) {
    closingFromHost = false
    window.visible = true
    refreshPlugins()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function close() {
    closingFromHost = true
    window.visible = false
    listProcess.running = false
    scanProcess.running = false
    busy = false
    closingFromHost = false
  }

  function requestClose() {
    if (shell && typeof shell.hide === "function") shell.hide(pluginId)
    else window.visible = false
  }

  function plain(value, limit) {
    var text = value === undefined || value === null ? "" : String(value)
    text = text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, "�")
    text = text.replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "�")
    var maximum = limit || 4096
    return text.length > maximum ? text.slice(0, maximum) + "…" : text
  }

  function plainInline(value, limit) {
    return plain(value, limit).replace(/[\t\n\r]+/g, " ").replace(/ {2,}/g, " ")
  }

  function values(value) {
    return Array.isArray(value) ? value : []
  }

  function firstValue(value) {
    if (!value || typeof value === "string" || typeof value.length !== "number" || value.length < 1) return null
    return value[0]
  }

  function validReviewCount(value, maximum) {
    return typeof value === "number" && isFinite(value) && Math.floor(value) === value && value >= 0 && value <= maximum
  }

  function validReviewReasons(reasons) {
    if (!Array.isArray(reasons) || reasons.length > 8) return false
    for (var i = 0; i < reasons.length; i++) {
      var reason = reasons[i]
      if (!reason || typeof reason.title !== "string" || reason.title.length > 4096) return false
      if (reason.reference !== undefined && !/^PP-[0-9A-F]{16}$/.test(String(reason.reference))) return false
      if (reason.scope !== undefined && ["runtime", "repository-tooling", "unknown"].indexOf(String(reason.scope)) === -1) return false
    }
    return true
  }

  function validReviewSummary(review) {
    if (!review || !review.securityImpact || !review.evidenceConfidence || !review.analysisCoverage
        || !review.unknownBehavior || !review.counts || !Array.isArray(review.mainReasons)) return false
    var impact = review.securityImpact
    var confidence = review.evidenceConfidence
    var coverage = review.analysisCoverage
    var unknown = review.unknownBehavior
    var counts = review.counts
    if (["critical", "high", "medium", "low", "informational"].indexOf(String(impact.level)) === -1
        || ["high", "medium", "low", "not-applicable"].indexOf(String(confidence.level)) === -1
        || ["complete", "substantial", "partial", "limited", "not-applicable"].indexOf(String(coverage.level)) === -1
        || ["none", "low", "moderate", "high"].indexOf(String(unknown.level)) === -1) return false
    if (!validReviewReasons(impact.reasons) || !validReviewReasons(confidence.reasons)
        || !validReviewReasons(unknown.reasons) || !validReviewReasons(review.mainReasons)) return false
    if (!validReviewCount(confidence.high, 60000) || !validReviewCount(confidence.medium, 60000) || !validReviewCount(confidence.low, 60000)
        || !validReviewCount(unknown.unknowns, 20000) || !validReviewCount(unknown.limitations, 20000) || !validReviewCount(unknown.errors, 10000)
        || !validReviewCount(counts.facts, 60000) || !validReviewCount(counts.inferences, 20000) || !validReviewCount(counts.unknownBehaviors, 40000)
        || !validReviewCount(coverage.analyzedUnits, 10000) || !validReviewCount(coverage.partialUnits, 10000)
        || !validReviewCount(coverage.unanalyzedUnits, 10000) || !validReviewCount(coverage.totalUnits, 10000)) return false
    if (String(coverage.denominator) !== "retained supported executable, configuration, archive, and binary artifact files"
        || coverage.analyzedUnits + coverage.partialUnits + coverage.unanalyzedUnits !== coverage.totalUnits) return false
    if (coverage.totalUnits === 0) return coverage.percentage === null && coverage.level === "not-applicable"
    return validReviewCount(coverage.percentage, 100)
      && coverage.percentage === Math.floor(coverage.analyzedUnits * 100 / coverage.totalUnits)
  }

  function refreshPlugins() {
    if (!brokerPath) {
      showError("Reviewer installation is incomplete", "The trusted broker path is unavailable.")
      return
    }
    listProcess.running = false
    scanProcess.running = false
    pluginIds = []
    selectedPlugin = 0
    currentReport = null
    visibleFindings = []
    visibleOperations = []
    visibleResources = []
    visibleLimitations = []
    visibleErrors = []
    visibleBehaviorUnknowns = []
    visibleRelationshipChains = ({})
    visibleRelationshipTotals = ({})
    diagnosticText = ""
    errorText = ""
    view = "plugins"
    busy = true
    listProcess.command = [brokerPath, "--list"]
    listProcess.running = true
  }

  function acceptPluginList(text) {
    try {
      var parsed = JSON.parse(String(text || ""))
      if (!parsed || parsed.schemaVersion !== "1.0.0" || parsed.protocolVersion !== protocolVersion
          || typeof parsed.reviewerVersion !== "string" || !parsed.reviewerVersion || !Array.isArray(parsed.plugins))
        throw new Error("unsupported plugin-list response")
      var accepted = []
      for (var i = 0; i < parsed.plugins.length && i < 1024; i++) {
        var id = String(parsed.plugins[i])
        if (/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id) && id.indexOf("..") === -1 && id !== pluginId)
          accepted.push(id)
      }
      pluginIds = accepted
      selectedPlugin = Math.min(selectedPlugin, Math.max(0, accepted.length - 1))
      busy = false
    } catch (error) {
      showError("Could not read installed plugins", plain(error, 240))
    }
  }

  function reviewSelected() {
    if (busy || selectedPlugin < 0 || selectedPlugin >= pluginIds.length) return
    var id = String(pluginIds[selectedPlugin])
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id) || id.indexOf("..") !== -1) return
    currentReport = null
    visibleFindings = []
    visibleOperations = []
    visibleResources = []
    visibleLimitations = []
    visibleErrors = []
    reportSection = 0
    selectedReportRow = 0
    diagnosticText = ""
    errorText = ""
    busy = true
    scanProcess.command = [brokerPath, "--plugin", id]
    scanProcess.running = true
  }

  function acceptReport(text) {
    try {
      var parsed = JSON.parse(String(text || ""))
      if (!parsed || parsed.schemaVersion !== "2.0.0" || !validReviewSummary(parsed.review)) throw new Error("unsupported report schema")
      if (["complete", "incomplete", "error"].indexOf(String(parsed.status)) === -1)
        throw new Error("invalid report status")
      if (!parsed.scan || !parsed.target || !Array.isArray(parsed.operations)
          || !Array.isArray(parsed.findings) || !Array.isArray(parsed.resources)
          || !Array.isArray(parsed.unknowns)
          || !Array.isArray(parsed.relationships)
          || !Array.isArray(parsed.limitations) || !Array.isArray(parsed.errors))
        throw new Error("report sections are missing")
      if (parsed.operations.length > 20000 || parsed.findings.length > 20000
          || parsed.resources.length > 20000 || parsed.unknowns.length > 20000 || parsed.limitations.length > 20000
          || parsed.relationships.length > 660000
          || parsed.errors.length > 10000)
        throw new Error("report sections exceed supported limits")
      currentReport = parsed
      setVisibleFindings(parsed.findings)
      setVisibleRelationships(parsed.relationships)
      visibleOperations = parsed.operations.slice(0, 500)
      setVisibleResources(parsed.resources)
      setVisibleUnknowns(parsed.unknowns, parsed.limitations, parsed.errors)
      reportSection = 0
      selectedReportRow = 0
      view = "report"
      busy = false
      Qt.callLater(function() { keyCatcher.forceActiveFocus() })
    } catch (error) {
      showError("Could not display the report", plain(error, 240))
    }
  }

  function setVisibleFindings(findings) {
    var severities = ["critical", "high", "medium", "low", "informational"]
    var buckets = [[], [], [], [], []]
    for (var i = 0; i < findings.length; i++) {
      var severity = String(findings[i].severity || "").toLowerCase()
      var bucket = severities.indexOf(severity)
      buckets[bucket < 0 ? 4 : bucket].push(findings[i])
    }
    var selected = []
    for (var bucketIndex = 0; bucketIndex < buckets.length && selected.length < 500; bucketIndex++) {
      for (var rowIndex = 0; rowIndex < buckets[bucketIndex].length && selected.length < 500; rowIndex++)
        selected.push(buckets[bucketIndex][rowIndex])
    }
    visibleFindings = selected
  }

  function setVisibleResources(resources) {
    var sensitive = []
    var ordinary = []
    for (var i = 0; i < resources.length; i++) {
      if (resources[i].sensitive === true) sensitive.push(resources[i])
      else ordinary.push(resources[i])
    }
    visibleResources = sensitive.concat(ordinary).slice(0, 500)
  }

  function setVisibleRelationships(relationships) {
    var wanted = ({})
    var indexed = ({})
    var totals = ({})
    for (var findingIndex = 0; findingIndex < visibleFindings.length; findingIndex++) {
      var reference = String(visibleFindings[findingIndex].reference || "")
      if (reference) wanted[reference] = true
    }
    for (var i = 0; i < relationships.length; i++) {
      var relationship = relationships[i]
      if (!relationship) continue
      var from = String(relationship.from || "")
      var to = String(relationship.to || "")
      var selected = wanted[from] ? from : (wanted[to] ? to : "")
      if (!selected) continue
      var visible = relationship
      if (selected === to) visible = ({type: relationship.type, from: to, to: from})
      totals[selected] = Number(totals[selected] || 0) + 1
      if (!indexed[selected]) indexed[selected] = []
      if (indexed[selected].length < 16) indexed[selected].push(visible)
    }
    visibleRelationshipChains = indexed
    visibleRelationshipTotals = totals
  }

  function setVisibleUnknowns(unknowns, limitations, errors) {
    var maximum = 500
    var active = (unknowns.length ? 1 : 0) + (limitations.length ? 1 : 0) + (errors.length ? 1 : 0)
    var share = active ? Math.floor(maximum / active) : maximum
    var unknownCount = Math.min(unknowns.length, share)
    var limitationCount = Math.min(limitations.length, share)
    var errorCount = Math.min(errors.length, share)
    var remaining = maximum - unknownCount - limitationCount - errorCount
    var addErrors = Math.min(remaining, errors.length - errorCount)
    errorCount += addErrors
    remaining -= addErrors
    var addUnknowns = Math.min(remaining, unknowns.length - unknownCount)
    unknownCount += addUnknowns
    remaining -= addUnknowns
    limitationCount += Math.min(remaining, limitations.length - limitationCount)
    visibleBehaviorUnknowns = unknowns.slice(0, unknownCount)
    visibleLimitations = limitations.slice(0, limitationCount)
    visibleErrors = errors.slice(0, errorCount)
  }

  function showError(title, detail) {
    errorText = plainInline(title, 160)
    diagnosticText = plain(detail, 1024)
    view = "error"
    busy = false
  }

  function processFailure(title, exitCode) {
    Qt.callLater(function() {
      if (exitCode !== 0 && busy) showError(title,
        diagnosticText || "Install or update the matching Plug & Prejudice Arch package. The fixed trusted broker did not provide a compatible response.")
    })
  }

  function moveCursor(dx, dy) {
    if (busy) return
    if (view === "plugins") {
      if (dy !== 0) selectedPlugin = Math.max(0, Math.min(pluginIds.length - 1, selectedPlugin + dy))
      return
    }
    if (view === "report") {
      if (dx !== 0) {
        reportSection = Math.max(0, Math.min(3, reportSection + dx))
        selectedReportRow = 0
      } else if (dy !== 0) {
        selectedReportRow = Math.max(0, Math.min(reportRows().length - 1, selectedReportRow + dy))
      }
    }
  }

  function activateCursor() {
    if (view === "plugins") reviewSelected()
    else if (view === "error") refreshPlugins()
  }

  function back() {
    if (busy) return
    if (view === "plugins") requestClose()
    else refreshPlugins()
  }

  function reportRows() {
    if (reportSection === 0) return visibleFindings
    if (reportSection === 1) return visibleOperations
    if (reportSection === 2) return visibleResources
    return visibleErrors.concat(visibleBehaviorUnknowns).concat(visibleLimitations)
  }

  function sectionName(index) {
    return ["Findings", "Commands", "Resources", "Limits"][index] || "Report"
  }

  function rowTitle(row) {
    if (!row) return ""
    if (reportSection === 0) {
      return referenceLabel(row) + " · " + plainInline(String(row.severity || "informational").toUpperCase(), 32)
        + " · " + plainInline(String(row.claim || "unknown").toUpperCase(), 32)
        + " · " + plainInline(row.title, 240)
    }
    if (reportSection === 1) {
      return referenceLabel(row) + " · " + plainInline(String(row.category || "operation").toUpperCase(), 80)
        + " · " + plainInline(row.command || "<unknown>", 240)
    }
    if (reportSection === 2) {
      return referenceLabel(row) + " · " + plainInline(String(row.kind || "resource").toUpperCase(), 40)
        + " · " + plainInline(String(row.access || "access").toUpperCase(), 40)
        + (row.sensitive ? " · SENSITIVE" : "")
    }
    if (row.message !== undefined) return "ERROR · " + plainInline(row.code || "scan-error", 160)
    if (row.reason !== undefined) return "UNKNOWN · " + referenceLabel(row) + " · " + plainInline(row.reason || "unresolved", 80)
    return "UNKNOWN · " + plainInline(row.code || "analysis-limitation", 160)
  }

  function rowBody(row) {
    if (!row) return ""
    if (reportSection === 0) return plain(row.explanation, 1200)
    if (reportSection === 1) {
      var argumentsList = values(row.arguments)
      var rendered = []
      for (var i = 0; i < argumentsList.length && i < 64; i++) rendered.push(plainInline(argumentsList[i], 160))
      var detail = rendered.length ? "Arguments: " + rendered.join(" · ") : "No literal arguments recorded."
      if (argumentsList.length > rendered.length) detail += " · Additional arguments omitted."
      if (row.dynamic) detail += " Dynamic values are present."
      return plain(detail, 1200)
    }
    if (reportSection === 2) return plainInline(row.value, 1200)
    return plain(row.message !== undefined ? row.message : row.description, 1200)
  }

  function rowMeta(row) {
    if (!row) return ""
    if (reportSection === 0)
      return evidenceLabel(row) + " · " + plainInline(row.scope, 40) + " · confidence " + plainInline(row.confidence, 40) + provenanceLabel(row)
    if (reportSection === 1) {
      return evidencePoint(row.evidence || {}) + " · " + plainInline(row.scope, 40) + " · confidence " + plainInline(row.confidence, 40) + provenanceLabel(row)
    }
    if (reportSection === 2) {
      var evidence = row.evidence || {}
      return evidencePoint(evidence) + " · " + plainInline(row.scope, 40) + " · confidence " + plainInline(row.confidence, 40) + provenanceLabel(row)
    }
    if (row.reason !== undefined)
      return evidenceLabel(row) + " · " + plainInline(row.scope, 40) + " · confidence " + plainInline(row.confidence, 40) + provenanceLabel(row)
    return plainInline(row.path || "Whole scan", 240) + (row.scope ? " · " + plainInline(row.scope, 40) : "")
  }

  function rowEvidence(row) {
    if (!row) return ""
    if (reportSection === 3) {
      if (row.reason === undefined) return ""
      var origins = values(row.origins)
      var renderedOrigins = []
      for (var originIndex = 0; originIndex < origins.length && originIndex < 8; originIndex++) {
        var origin = origins[originIndex] || {}
        renderedOrigins.push(plainInline(origin.kind || "origin", 40) + " " + plainInline(origin.name || "", 80) + " at " + evidencePoint(origin.evidence || {}))
      }
      return renderedOrigins.length ? plainInline("Value origins: " + renderedOrigins.join(" · "), 1200) : "No earlier value origin was resolved statically."
    }
    var evidence = reportSection === 0
      ? firstValue(row.evidence)
      : row.evidence
    if (!evidence) return ""
    var source = plain(evidence.operation || evidence.excerpt || "", 800)
    if (reportSection !== 0) return source
    var chain = evidenceChain(row)
    return source + (source && chain ? " · " : "") + chain
  }

  function referenceLabel(row) {
    return plainInline(row && row.reference ? row.reference : "PP-UNAVAILABLE", 40)
  }

  function provenanceLabel(row) {
    var provenance = row && row.provenance ? row.provenance : {}
    var rule = plainInline(provenance.ruleId || "rule unavailable", 120)
    var analyzer = plainInline(provenance.analyzer || "analyzer unavailable", 120)
    var version = plainInline(provenance.analyzerVersion || "version unavailable", 80)
    var source = plainInline(provenance.evidenceSource || "source unavailable", 80)
    return " · rule " + rule + " · " + analyzer + " " + version + " · source " + source
  }

  function evidenceChain(row) {
    if (!row || !currentReport) return ""
    var relationships = values(visibleRelationshipChains[String(row.reference || "")])
    var rendered = []
    for (var i = 0; i < relationships.length && rendered.length < 16; i++) {
      var relationship = relationships[i]
      if (!relationship || relationship.from !== row.reference) continue
      rendered.push(plainInline(relationship.type, 40) + " " + plainInline(relationship.to, 40))
    }
    if (!rendered.length) return ""
    var total = Number(visibleRelationshipTotals[String(row.reference || "")] || rendered.length)
    var suffix = total > rendered.length ? " · " + String(total - rendered.length) + " additional edges omitted" : ""
    return plainInline("Evidence chain: " + referenceLabel(row) + " " + rendered.join(" · ") + suffix, 1200)
  }

  function ensureVisible(item, scroll) {
    if (!item || !scroll || !scroll.contentItem) return
    var flick = scroll.contentItem
    if (flick.contentY === undefined) return
    var point = item.mapToItem(flick.contentItem || flick, 0, 0)
    var top = point.y
    var bottom = top + (item.height || 0)
    var margin = Style.space(10)
    if (top < flick.contentY + margin) flick.contentY = Math.max(0, top - margin)
    else if (bottom > flick.contentY + flick.height - margin)
      flick.contentY = bottom + margin - flick.height
  }

  function evidencePoint(evidence) {
    if (!evidence) return "No source location"
    var label = plainInline(evidence.path, 240)
    if (!label) return "No source location"
    if (Number(evidence.lineStart) > 0) {
      label += ":" + Number(evidence.lineStart)
      if (Number(evidence.lineEnd) > Number(evidence.lineStart)) label += "–" + Number(evidence.lineEnd)
    }
    return label
  }

  function evidenceLabel(finding) {
    var evidence = finding ? firstValue(finding.evidence) : null
    return evidencePoint(evidence)
  }

  function statusText() {
    if (!currentReport) return ""
    if (currentReport.status === "complete") return "Completed within current analysis coverage"
    if (currentReport.status === "incomplete") return "Incomplete — inspect limits and errors before deciding"
    return "The scan reported an error"
  }

  function reviewSummaryText() {
    var review = currentReport && currentReport.review ? currentReport.review : null
    if (!review) return "Review dimensions unavailable"
    var coverage = review.analysisCoverage || {}
    var coverageValue = coverage.percentage === null || coverage.percentage === undefined ? "NOT APPLICABLE" : String(coverage.percentage) + "%"
    return plainInline("Security impact " + String(review.securityImpact.level || "informational").toUpperCase()
      + " · Evidence confidence " + String(review.evidenceConfidence.level || "not-applicable").toUpperCase()
      + " · Analysis coverage " + coverageValue
      + " · Unknown behavior " + String(review.unknownBehavior.level || "none").toUpperCase(), 800)
  }

  function reviewCountsText() {
    var review = currentReport && currentReport.review ? currentReport.review : null
    if (!review) return ""
    var counts = review.counts || {}
    var coverage = review.analysisCoverage || {}
    return plainInline(String(counts.facts || 0) + " facts · " + String(counts.inferences || 0) + " inferences · "
      + String(counts.unknownBehaviors || 0) + " unresolved behaviors · coverage denominator "
      + String(coverage.analyzedUnits || 0) + "/" + String(coverage.totalUnits || 0) + " fully analyzed artifact units", 800)
  }

  function mainReasonsText() {
    var reasons = values(currentReport && currentReport.review ? currentReport.review.mainReasons : null)
    if (!reasons.length) return "Main reasons · No impact or unresolved-behavior reason was retained. This is not a safety claim."
    var rendered = []
    for (var i = 0; i < reasons.length && i < 8; i++) rendered.push(plainInline(String(reasons[i].reference || "NO STABLE REFERENCE")
      + (reasons[i].scope ? " [" + String(reasons[i].scope) + "]" : "") + " " + String(reasons[i].title || "Reason unavailable"), 240))
    return plainInline("Main reasons · " + rendered.join(" · "), 1600)
  }

  function authorClaimLabel() {
    var target = currentReport && currentReport.target ? currentReport.target : null
    var declared = target && target.manifest ? target.manifest : null
    if (!declared) return "AUTHOR CLAIM · MANIFEST METADATA UNAVAILABLE"
    var kinds = values(declared.kinds)
    var rendered = []
    for (var i = 0; i < kinds.length && i < 8; i++) rendered.push(plainInline(kinds[i], 40))
    var suffix = rendered.length ? rendered.join(", ") : "no kinds declared"
    if (kinds.length > rendered.length) suffix += ", …"
    return plainInline("AUTHOR CLAIM · KINDS · " + suffix, 400)
  }

  function authorClaimDescription() {
    var target = currentReport && currentReport.target ? currentReport.target : null
    var declared = target && target.manifest ? target.manifest : null
    if (!declared) return "No parseable plugin description is available."
    var description = plainInline(declared.description, 500)
    return description || "No description was provided by the plugin author."
  }

  Process {
    id: listProcess
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (listProcess.running || root.busy) root.acceptPluginList(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.diagnosticText = root.plain(text, 1024)
    }
    onExited: function(exitCode) { root.processFailure("Could not list installed plugins", exitCode) }
  }

  Process {
    id: scanProcess
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (scanProcess.running || root.busy) root.acceptReport(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.diagnosticText = root.plain(text, 1024)
    }
    onExited: function(exitCode) { root.processFailure("The review did not complete", exitCode) }
  }

  FloatingWindow {
    id: window
    title: "Plug & Prejudice"
    visible: false
    color: root.background
    implicitWidth: 760
    implicitHeight: 720
    minimumSize: Qt.size(560, 480)

    onVisibleChanged: {
      if (!visible && !root.closingFromHost && root.shell && typeof root.shell.hide === "function")
        root.shell.hide(root.pluginId)
    }

    FocusScope {
      anchors.fill: parent
      focus: true
      Accessible.role: Accessible.Dialog
      Accessible.name: "Plug & Prejudice security review"
      Accessible.description: root.view === "report" ? root.statusText() : "Review an installed plugin without executing it"

      PanelKeyCatcher {
        id: keyCatcher
        anchors.fill: parent
        onMoveRequested: function(dx, dy) { root.moveCursor(dx, dy) }
        onActivateRequested: root.activateCursor()
        onCloseRequested: root.back()

        Column {
          anchors.fill: parent
          anchors.margins: Style.space(18)
          spacing: Style.space(12)

          Row {
            width: parent.width
            spacing: Style.space(10)

            Column {
              width: parent.width - closeButton.width - parent.spacing
              spacing: Style.space(2)

              Text {
                textFormat: Text.PlainText
                text: "PLUG & PREJUDICE"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.heading
                font.bold: true
              }
              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.busy ? "Static review in progress…" : (root.view === "report" ? root.statusText() : "Review an installed plugin without executing it")
                color: root.view === "report" && root.currentReport && root.currentReport.status !== "complete" ? root.urgent : Qt.darker(root.foreground, 1.5)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }
            }

            PanelActionButton {
              id: closeButton
              iconText: "󰅖"
              tooltipText: "Close"
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.requestClose()
              Accessible.role: Accessible.Button
              Accessible.name: "Close"
              Accessible.description: "Close this review window. Escape also returns or closes."
              Accessible.onPressAction: root.requestClose()
            }
          }

          Rectangle { width: parent.width; height: 1; color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.14) }

          Item {
            width: parent.width
            height: parent.height - y

            Text {
              textFormat: Text.PlainText
              visible: root.busy
              anchors.centerIn: parent
              text: "Inspecting source as hostile data…"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            ScrollView {
              id: pluginScroll
              visible: !root.busy && root.view === "plugins"
              anchors.fill: parent
              clip: true
              ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

              Column {
                width: pluginScroll.availableWidth
                spacing: Style.space(4)

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: root.pluginIds.length ? "Select a plugin · j/k move · Enter reviews · Esc closes" : "No installed third-party plugins were found."
                  color: Qt.darker(root.foreground, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                  bottomPadding: Style.space(8)
                }

                Repeater {
                  model: root.pluginIds

                  CursorSurface {
                    id: pluginRow
                    required property int index
                    required property string modelData
                    width: pluginScroll.availableWidth
                    height: Style.space(46)
                    hasCursor: pluginRow.index === root.selectedPlugin
                    onHasCursorChanged: if (hasCursor) root.ensureVisible(pluginRow, pluginScroll)
                    Accessible.role: Accessible.ListItem
                      Accessible.name: root.plainInline(pluginRow.modelData, 240)
                    Accessible.description: "Installed plugin. Review without executing it."
                    Accessible.focusable: true
                    Accessible.focused: hasCursor
                    Accessible.selectable: true
                    Accessible.selected: hasCursor
                    Accessible.onPressAction: {
                      root.selectedPlugin = pluginRow.index
                      root.reviewSelected()
                    }

                    Text {
                      textFormat: Text.PlainText
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      anchors.margins: Style.space(10)
                      text: root.plainInline(pluginRow.modelData, 240)
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      elide: Text.ElideMiddle
                    }

                    MouseArea {
                      anchors.fill: parent
                      hoverEnabled: true
                      onEntered: root.selectedPlugin = pluginRow.index
                      onClicked: { root.selectedPlugin = pluginRow.index; root.reviewSelected() }
                    }
                  }
                }
              }
            }

            Column {
              visible: !root.busy && root.view === "error"
              anchors.centerIn: parent
              width: Math.min(parent.width, Style.space(520))
              spacing: Style.space(10)

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.errorText
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.subtitle
                font.bold: true
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
              }
              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.diagnosticText
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WrapAnywhere
              }
              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "Press Enter to retry · Esc returns"
                color: Qt.darker(root.foreground, 1.5)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                horizontalAlignment: Text.AlignHCenter
              }
            }

            Column {
              visible: !root.busy && root.view === "report" && root.currentReport
              anchors.fill: parent
              spacing: Style.space(10)

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.plainInline(root.currentReport && root.currentReport.target ? root.currentReport.target.displayName : "Plugin", 240)
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.subtitle
                font.bold: true
                elide: Text.ElideMiddle
              }

              Column {
                width: parent.width
                spacing: Style.space(2)

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: root.authorClaimLabel()
                  color: Qt.darker(root.foreground, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  elide: Text.ElideRight
                }

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: root.authorClaimDescription()
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.WordWrap
                  maximumLineCount: 2
                  elide: Text.ElideRight
                }
              }

              Column {
                width: parent.width
                spacing: Style.space(2)
                Accessible.role: Accessible.StaticText
                Accessible.name: root.reviewSummaryText() + ". " + root.reviewCountsText() + ". " + root.mainReasonsText()

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: root.reviewSummaryText()
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  font.bold: true
                  wrapMode: Text.WordWrap
                }

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: root.reviewCountsText()
                  color: Qt.darker(root.foreground, 1.3)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                }

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: root.mainReasonsText()
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                  maximumLineCount: 2
                  elide: Text.ElideRight
                }
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.values(root.currentReport ? root.currentReport.findings : null).length + " findings · "
                  + root.values(root.currentReport ? root.currentReport.operations : null).length + " commands · "
                  + root.values(root.currentReport ? root.currentReport.resources : null).length + " resources · "
                  + root.values(root.currentReport ? root.currentReport.limitations : null).length + " limitations · "
                  + root.values(root.currentReport ? root.currentReport.errors : null).length + " errors · Esc returns"
                color: Qt.darker(root.foreground, 1.4)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Repeater {
                  model: 4

                  CursorSurface {
                    id: sectionTab
                    required property int index
                    width: (parent.width - Style.space(18)) / 4
                    height: Style.space(34)
                    current: root.reportSection === sectionTab.index
                    Accessible.role: Accessible.PageTab
                    Accessible.name: root.sectionName(sectionTab.index) + ", "
                      + [root.visibleFindings.length, root.visibleOperations.length, root.visibleResources.length, root.visibleErrors.length + root.visibleBehaviorUnknowns.length + root.visibleLimitations.length][sectionTab.index]
                    Accessible.focusable: true
                    Accessible.selectable: true
                    Accessible.selected: current
                    Accessible.onPressAction: {
                      root.reportSection = sectionTab.index
                      root.selectedReportRow = 0
                    }

                    Text {
                      textFormat: Text.PlainText
                      anchors.centerIn: parent
                      text: root.sectionName(sectionTab.index) + " " + [root.visibleFindings.length, root.visibleOperations.length, root.visibleResources.length, root.visibleErrors.length + root.visibleBehaviorUnknowns.length + root.visibleLimitations.length][sectionTab.index]
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: root.reportSection === sectionTab.index
                    }

                    MouseArea {
                      anchors.fill: parent
                      onClicked: { root.reportSection = sectionTab.index; root.selectedReportRow = 0 }
                    }
                  }
                }
              }

              ScrollView {
                id: reportScroll
                width: parent.width
                height: parent.height - y
                clip: true
                ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

                Column {
                  width: reportScroll.availableWidth
                  spacing: Style.space(6)

                  Text {
                    textFormat: Text.PlainText
                    visible: root.reportRows().length === 0
                    width: parent.width
                    text: root.reportSection === 0
                      ? (root.values(root.currentReport ? root.currentReport.limitations : null).length
                        ? "No findings were produced, but analysis limitations remain. This is not a safety claim."
                        : "No findings were produced within current analysis coverage. This is not a safety claim.")
                      : (root.reportSection === 1 ? "No command or filesystem-redirection operations were established."
                        : (root.reportSection === 2 ? "No resource access was established." : "No analysis limitations or scan errors were recorded."))
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    wrapMode: Text.WordWrap
                  }

                  Repeater {
                    model: root.reportRows()

                    CursorSurface {
                      id: findingRow
                      required property int index
                      required property var modelData
                      width: reportScroll.availableWidth
                      implicitHeight: findingColumn.implicitHeight + Style.space(18)
                      hasCursor: findingRow.index === root.selectedReportRow
                      bordered: true
                      onHasCursorChanged: if (hasCursor) root.ensureVisible(findingRow, reportScroll)
                      Accessible.role: Accessible.ListItem
                      Accessible.name: root.rowTitle(findingRow.modelData)
                      Accessible.description: root.rowBody(findingRow.modelData) + ". "
                        + root.rowEvidence(findingRow.modelData) + ". " + root.rowMeta(findingRow.modelData)
                      Accessible.focusable: true
                      Accessible.focused: hasCursor
                      Accessible.selectable: true
                      Accessible.selected: hasCursor

                      Column {
                        id: findingColumn
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.margins: Style.space(9)
                        spacing: Style.space(3)

                        Text {
                          textFormat: Text.PlainText
                          width: parent.width
                          text: root.rowTitle(findingRow.modelData)
                          color: (root.reportSection === 0 && (String(findingRow.modelData.severity) === "critical" || String(findingRow.modelData.severity) === "high")) || (root.reportSection === 2 && findingRow.modelData.sensitive) ? root.urgent : root.foreground
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.body
                          font.bold: true
                          wrapMode: Text.WordWrap
                        }
                        Text {
                          textFormat: Text.PlainText
                          width: parent.width
                          text: root.rowBody(findingRow.modelData)
                          color: root.foreground
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.bodySmall
                          wrapMode: Text.WordWrap
                        }
                        Text {
                          textFormat: Text.PlainText
                          visible: text !== ""
                          width: parent.width
                          text: root.rowEvidence(findingRow.modelData)
                          color: Qt.darker(root.foreground, 1.25)
                          font.family: "monospace"
                          font.pixelSize: Style.font.caption
                          wrapMode: Text.WrapAnywhere
                        }
                        Text {
                          textFormat: Text.PlainText
                          width: parent.width
                          text: root.rowMeta(findingRow.modelData)
                          color: Qt.darker(root.foreground, 1.5)
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                          elide: Text.ElideMiddle
                        }
                      }

                      MouseArea {
                        anchors.fill: parent
                        hoverEnabled: true
                        acceptedButtons: Qt.NoButton
                        onEntered: root.selectedReportRow = findingRow.index
                      }
                    }
                  }

                  Text {
                    textFormat: Text.PlainText
                    visible: root.currentReport && ((root.reportSection === 0 && root.values(root.currentReport.findings).length > root.visibleFindings.length)
                      || (root.reportSection === 1 && root.values(root.currentReport.operations).length > root.visibleOperations.length)
                      || (root.reportSection === 2 && root.values(root.currentReport.resources).length > root.visibleResources.length)
                      || (root.reportSection === 3 && (root.values(root.currentReport.limitations).length > root.visibleLimitations.length
                        || root.values(root.currentReport.errors).length > root.visibleErrors.length)))
                    width: parent.width
                    text: "Additional entries are omitted from this view; inspect the JSON report with the standalone CLI."
                    color: root.urgent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
