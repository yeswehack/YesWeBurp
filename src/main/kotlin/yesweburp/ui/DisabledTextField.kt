package yesweburp.ui

import javax.swing.JTextField

open class DisabledTextField(text: String? = null) : JTextField(text) {
    init {
        isEditable = false
        isOpaque = true
        isRequestFocusEnabled = false
        horizontalAlignment = CENTER
    }
}