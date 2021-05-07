package yesweburp.ui

import burp.ITab
import yesweburp.Events.programsLoaded
import yesweburp.callbacks
import yesweburp.ui.options.OptionsTab
import yesweburp.ui.programs.ProgramTab
import java.awt.Component
import javax.swing.JTabbedPane


class YesWeBurpTab : ITab {

    override fun getTabCaption(): String {
        return "YesWeBurp"
    }

    override fun getUiComponent(): Component {
        val tab = JTabbedPane(JTabbedPane.TOP)
        tab.add("Options", OptionsTab())

        var programTab: ProgramTab? = null
        programsLoaded.listen { programs ->
            if (programTab != null) {
                tab.remove(programTab)
            }
            programTab = ProgramTab(programs)
            tab.add("Programs", programTab)
        }
        callbacks.customizeUiComponent(tab)
        return tab

    }

}