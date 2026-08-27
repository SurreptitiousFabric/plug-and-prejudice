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
  property var visibleResources: []
  property var visibleLimitations: []
  property int reportSection: 0
  property int selectedReportRow: 0
  property string errorText: ""
  property string diagnosticText: ""

  readonly property string pluginId: "io.github.surreptitiousfabric.plug-and-prejudice"
  readonly property string sourceDir: manifest && manifest.sourceDir ? String(manifest.sourceDir) : ""
  readonly property string brokerPath: sourceDir ? sourceDir + "/bin/plug-prejudice-broker" : ""
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
    text = text.replace(/[\u202a-\u202e\u2066-\u2069]/g, "�")
    var maximum = limit || 4096
    return text.length > maximum ? text.slice(0, maximum) + "…" : text
  }

  function values(value) {
    return Array.isArray(value) ? value : []
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
    visibleResources = []
    visibleLimitations = []
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
      if (!parsed || parsed.schemaVersion !== "1.0.0" || !Array.isArray(parsed.plugins))
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
    visibleResources = []
    visibleLimitations = []
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
      if (!parsed || parsed.schemaVersion !== "1.0.0") throw new Error("unsupported report schema")
      if (["complete", "incomplete", "error"].indexOf(String(parsed.status)) === -1)
        throw new Error("invalid report status")
      if (!parsed.scan || !parsed.target || !Array.isArray(parsed.findings)
          || !Array.isArray(parsed.limitations) || !Array.isArray(parsed.errors))
        throw new Error("report sections are missing")
      currentReport = parsed
      visibleFindings = parsed.findings.slice(0, 500)
      visibleResources = values(parsed.resources).slice(0, 500)
      visibleLimitations = parsed.limitations.slice(0, 500)
      reportSection = 0
      selectedReportRow = 0
      view = "report"
      busy = false
      Qt.callLater(function() { keyCatcher.forceActiveFocus() })
    } catch (error) {
      showError("Could not display the report", plain(error, 240))
    }
  }

  function showError(title, detail) {
    errorText = plain(title, 160)
    diagnosticText = plain(detail, 1024)
    view = "error"
    busy = false
  }

  function processFailure(title, exitCode) {
    Qt.callLater(function() {
      if (exitCode !== 0 && busy) showError(title, diagnosticText || "The trusted broker stopped without a report.")
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
        reportSection = Math.max(0, Math.min(2, reportSection + dx))
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
    if (reportSection === 1) return visibleResources
    return visibleLimitations
  }

  function sectionName(index) {
    return ["Findings", "Resources", "Limitations"][index] || "Report"
  }

  function rowTitle(row) {
    if (!row) return ""
    if (reportSection === 0) {
      return plain(String(row.severity || "informational").toUpperCase(), 32)
        + " · " + plain(String(row.claim || "unknown").toUpperCase(), 32)
        + " · " + plain(row.title, 240)
    }
    if (reportSection === 1) {
      return plain(String(row.kind || "resource").toUpperCase(), 40)
        + " · " + plain(String(row.access || "access").toUpperCase(), 40)
        + (row.sensitive ? " · SENSITIVE" : "")
    }
    return "UNKNOWN · " + plain(row.code || "analysis-limitation", 160)
  }

  function rowBody(row) {
    if (!row) return ""
    if (reportSection === 0) return plain(row.explanation, 1200)
    if (reportSection === 1) return plain(row.value, 1200)
    return plain(row.description, 1200)
  }

  function rowMeta(row) {
    if (!row) return ""
    if (reportSection === 0)
      return evidenceLabel(row) + " · " + plain(row.scope, 40) + " · confidence " + plain(row.confidence, 40)
    if (reportSection === 1) {
      var evidence = row.evidence || {}
      return evidencePoint(evidence) + " · " + plain(row.scope, 40) + " · confidence " + plain(row.confidence, 40)
    }
    return plain(row.path || "Whole scan", 240) + (row.scope ? " · " + plain(row.scope, 40) : "")
  }

  function rowEvidence(row) {
    if (!row || reportSection === 2) return ""
    var evidence = reportSection === 0
      ? (Array.isArray(row.evidence) && row.evidence.length ? row.evidence[0] : null)
      : row.evidence
    if (!evidence) return ""
    return plain(evidence.operation || evidence.excerpt || "", 800)
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
    var label = plain(evidence.path, 240)
    if (!label) return "No source location"
    if (Number(evidence.lineStart) > 0) {
      label += ":" + Number(evidence.lineStart)
      if (Number(evidence.lineEnd) > Number(evidence.lineStart)) label += "–" + Number(evidence.lineEnd)
    }
    return label
  }

  function evidenceLabel(finding) {
    var evidence = finding && Array.isArray(finding.evidence) && finding.evidence.length ? finding.evidence[0] : null
    return evidencePoint(evidence)
  }

  function statusText() {
    if (!currentReport) return ""
    if (currentReport.status === "complete") return "Completed within current analysis coverage"
    if (currentReport.status === "incomplete") return "Incomplete — inspect limitations before deciding"
    return "The scan reported an error"
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
                text: "PLUG & PREJUDICE"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.heading
                font.bold: true
              }
              Text {
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
            }
          }

          Rectangle { width: parent.width; height: 1; color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.14) }

          Item {
            width: parent.width
            height: parent.height - y

            Text {
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

                    Text {
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      anchors.margins: Style.space(10)
                      text: root.plain(pluginRow.modelData, 240)
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
                width: parent.width
                text: root.diagnosticText
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WrapAnywhere
              }
              Text {
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
                width: parent.width
                text: root.plain(root.currentReport && root.currentReport.target ? root.currentReport.target.displayName : "Plugin", 240)
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.subtitle
                font.bold: true
                elide: Text.ElideMiddle
              }

              Text {
                width: parent.width
                text: root.values(root.currentReport ? root.currentReport.findings : null).length + " findings · "
                  + root.values(root.currentReport ? root.currentReport.resources : null).length + " resources · "
                  + root.values(root.currentReport ? root.currentReport.limitations : null).length + " limitations · Esc returns"
                color: Qt.darker(root.foreground, 1.4)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Repeater {
                  model: 3

                  CursorSurface {
                    id: sectionTab
                    required property int index
                    width: (parent.width - Style.space(12)) / 3
                    height: Style.space(34)
                    current: root.reportSection === sectionTab.index

                    Text {
                      anchors.centerIn: parent
                      text: root.sectionName(sectionTab.index) + " " + [root.visibleFindings.length, root.visibleResources.length, root.visibleLimitations.length][sectionTab.index]
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
                    visible: root.reportRows().length === 0
                    width: parent.width
                    text: root.reportSection === 0
                      ? (root.values(root.currentReport ? root.currentReport.limitations : null).length
                        ? "No findings were produced, but analysis limitations remain. This is not a safety claim."
                        : "No findings were produced within current analysis coverage. This is not a safety claim.")
                      : (root.reportSection === 1 ? "No resource access was established." : "No analysis limitations were recorded.")
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

                      Column {
                        id: findingColumn
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.margins: Style.space(9)
                        spacing: Style.space(3)

                        Text {
                          width: parent.width
                          text: root.rowTitle(findingRow.modelData)
                          color: (root.reportSection === 0 && (String(findingRow.modelData.severity) === "critical" || String(findingRow.modelData.severity) === "high")) || (root.reportSection === 1 && findingRow.modelData.sensitive) ? root.urgent : root.foreground
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.body
                          font.bold: true
                          wrapMode: Text.WordWrap
                        }
                        Text {
                          width: parent.width
                          text: root.rowBody(findingRow.modelData)
                          color: root.foreground
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.bodySmall
                          wrapMode: Text.WordWrap
                        }
                        Text {
                          visible: text !== ""
                          width: parent.width
                          text: root.rowEvidence(findingRow.modelData)
                          color: Qt.darker(root.foreground, 1.25)
                          font.family: "monospace"
                          font.pixelSize: Style.font.caption
                          wrapMode: Text.WrapAnywhere
                        }
                        Text {
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
                    visible: root.currentReport && ((root.reportSection === 0 && root.values(root.currentReport.findings).length > root.visibleFindings.length)
                      || (root.reportSection === 1 && root.values(root.currentReport.resources).length > root.visibleResources.length)
                      || (root.reportSection === 2 && root.values(root.currentReport.limitations).length > root.visibleLimitations.length))
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
