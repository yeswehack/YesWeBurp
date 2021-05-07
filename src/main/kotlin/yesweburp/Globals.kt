package yesweburp

import burp.IBurpExtenderCallbacks
import burp.IExtensionHelpers
import java.awt.Desktop
import java.io.PrintWriter
import java.net.URI

const val VERSION = "2.0.0"

lateinit var callbacks: IBurpExtenderCallbacks
lateinit var helpers: IExtensionHelpers
lateinit var stdout: PrintWriter
lateinit var stderr: PrintWriter


fun openInBrowser(url: String){
    if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
        Desktop.getDesktop().browse(URI(url))
    }
}