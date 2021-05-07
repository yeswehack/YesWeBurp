package yesweburp.ui.programs

import swinger.*
import yesweburp.api.Program
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import javax.swing.DefaultListCellRenderer
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.ListSelectionModel
import javax.swing.border.EmptyBorder

class ProgramsListPanel(programs: List<Program>) : BorderPanel() {

    class ProgramListCellRender : DefaultListCellRenderer() {
        override fun getListCellRendererComponent(
            list: JList<*>?,
            value: Any,
            index: Int,
            isSelected: Boolean,
            cellHasFocus: Boolean
        ): Component {
            val program = value as Program
            val el = super.getListCellRendererComponent(list, program.title, index, isSelected, cellHasFocus) as JLabel
            el.border = EmptyBorder(3, 0, 3, 0)
            if (!program.public) {
                el.foreground = Color(0xff6633)
                el.font = el.font.deriveFont(el.font.style or Font.BOLD)
            }
            return el
        }
    }


    class ProgramList(programs: List<Program>) : SList<Program>(programs) {
        init {
            selectionMode = ListSelectionModel.SINGLE_SELECTION
            alignmentX = LEFT_ALIGNMENT
            onSelect(Events.programSelected::fire)
            cellRenderer = ProgramListCellRender()
        }
    }

    init {
        val programList = ProgramList(programs)
        vgap = 10
        addPaddingBorder(5)

        top = Label("Programs") {
            horizontalAlignment = JLabel.CENTER
        }

        bottom = BorderPanel {
            hgap = 5
            center = TextField {
                alignmentX = LEFT_ALIGNMENT
                onChange { programList.applyFilter { (title) -> title.contains(it, ignoreCase = true) } }
            }
            left = Label("Search :")
        }
        center = ScrollPane(programList)
        minimumSize = Dimension(300, preferredSize.height)
    }
}
