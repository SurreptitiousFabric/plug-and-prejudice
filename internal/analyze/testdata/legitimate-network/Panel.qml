import QtQuick
import Quickshell.Io

Item {
  Process {
    command: ["curl", "-fsS", "https://status.example.test/v1/summary"]
  }
}
