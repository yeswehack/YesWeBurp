package yesweburp.ui.options

import swinger.ColumnPanel
import javax.swing.JScrollPane


class OptionsTab : JScrollPane() {

    init {
        setViewportView(ColumnPanel {
            add(APIPanel())
        })
    }
}