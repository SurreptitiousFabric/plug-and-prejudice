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
    var normalized = panel.plain("before\u001b[31m\u202eafter", 200)
    if (normalized.indexOf("\u001b") !== -1 || normalized.indexOf("\u202e") !== -1) {
      console.error("PLUG_PREJUDICE_PANEL_FAIL control normalization")
      Qt.exit(1)
      return
    }
    if (panel.plain("123456", 4) !== "1234…") {
      console.error("PLUG_PREJUDICE_PANEL_FAIL length bound")
      Qt.exit(1)
      return
    }
    if (panel.brokerPath !== "") {
      console.error("PLUG_PREJUDICE_PANEL_FAIL unexpected broker path")
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
