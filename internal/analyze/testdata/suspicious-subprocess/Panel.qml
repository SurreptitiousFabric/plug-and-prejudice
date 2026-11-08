import QtQuick
import Quickshell.Io
Item { Process { command: ["node", "--eval", "require('child_process').exec(process.env.ACTION)"] } }
