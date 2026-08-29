import QtQuick
import Quickshell

ShellRoot {
  id: testRoot
  property var panel: null
  property int phase: 0
  property int ticks: 0
  readonly property string requestedPlugin: Quickshell.env("PLUG_PREJUDICE_TEST_PLUGIN")

  function fail(message) {
    console.error("PLUG_PREJUDICE_INTEGRATION_FAIL " + message)
    if (panel) panel.destroy()
    panel = null
    Qt.exit(1)
  }

  Component { id: panelComponent; Panel {} }
  QtObject {
    id: fakeManifest
    property string sourceDir: Quickshell.env("PLUG_PREJUDICE_TEST_SOURCE")
  }

  Component.onCompleted: {
    if (!fakeManifest.sourceDir) {
      fail("test source is missing")
      return
    }
    panel = panelComponent.createObject(testRoot, {"manifest": fakeManifest})
    if (!panel) {
      fail("component creation")
      return
    }
    panel.refreshPlugins()
    poll.start()
  }

  Timer {
    id: poll
    interval: 50
    repeat: true
    onTriggered: {
      testRoot.ticks++
      if (testRoot.ticks > 400) {
        testRoot.fail("timeout")
        return
      }
      if (!testRoot.panel) return
      if (testRoot.panel.view === "error") {
        testRoot.fail(testRoot.panel.errorText + ": " + testRoot.panel.diagnosticText)
        return
      }
      if (testRoot.phase === 0 && !testRoot.panel.busy) {
        var target = testRoot.requestedPlugin
          ? testRoot.panel.pluginIds.indexOf(testRoot.requestedPlugin)
          : (testRoot.panel.pluginIds.length ? 0 : -1)
        if (target < 0) {
          testRoot.fail("installed target was not listed")
          return
        }
        testRoot.panel.selectedPlugin = target
        testRoot.phase = 1
        testRoot.panel.reviewSelected()
        return
      }
      if (testRoot.phase === 1 && !testRoot.panel.busy && testRoot.panel.view === "report") {
        var report = testRoot.panel.currentReport
        if (!report || report.schemaVersion !== "2.0.0" || !report.scan.sandboxed
            || !Array.isArray(report.findings) || !Array.isArray(report.operations) || !Array.isArray(report.resources)
            || !Array.isArray(report.relationships)
            || !Array.isArray(report.unknowns)
            || !Array.isArray(report.limitations) || !Array.isArray(report.errors)) {
          testRoot.fail("report model is incomplete")
          return
        }
        console.log("PLUG_PREJUDICE_INTEGRATION_PASS " + report.status + " " + report.target.displayName)
        poll.stop()
        testRoot.panel.destroy()
        testRoot.panel = null
        Qt.callLater(Qt.quit)
      }
    }
  }
}
