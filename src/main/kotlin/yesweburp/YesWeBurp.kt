package yesweburp

import burp.IBurpExtender
import burp.IBurpExtenderCallbacks
import yesweburp.ui.YesWeBurpTab
import java.io.PrintWriter


open class YesWeBurp : IBurpExtender {
    override fun registerExtenderCallbacks(cb: IBurpExtenderCallbacks) {
        callbacks = cb
        helpers = cb.helpers
        stdout = PrintWriter(callbacks.stdout, true)
        stderr = PrintWriter(callbacks.stderr, true)

        callbacks.setExtensionName("YesWeBurp")
        callbacks.addSuiteTab(YesWeBurpTab())

    }

}

/*

* */