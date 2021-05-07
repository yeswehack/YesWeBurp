package yesweburp.ui.programs

import swinger.ColumnPanel
import swinger.SplitPanel
import yesweburp.api.Program
import javax.swing.JSplitPane


class ProgramTab(programs: List<Program>) : ColumnPanel() {
    private val splitPanel: SplitPanel = SplitPanel(JSplitPane.HORIZONTAL_SPLIT) {
        isOneTouchExpandable = true
        leftComponent = ProgramsListPanel(programs)
        if (programs.isNotEmpty()){
            rightComponent = ProgramInfoPanel(programs.first())
        }
    }

    init {
        add(splitPanel)
        Events.programSelected.listen {
            showProgramInfo(it)
        }
    }


    private fun showProgramInfo(program: Program) {
        splitPanel.withFixedDivider {
            rightComponent = ProgramInfoPanel(program)
        }
    }
}