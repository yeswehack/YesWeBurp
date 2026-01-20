@file:Suppress("unused")

package burp

import burp.IBurpExtender
import burp.IBurpExtenderCallbacks
import yesweburp.YesWeBurp

public class BurpExtender : YesWeBurp(), IBurpExtender {
    // Explicitly implements IBurpExtender for Burp's class loader
}

