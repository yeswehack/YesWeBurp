package yesweburp.ui.programs

import swinger.*
import swinger.Button
import swinger.Label
import swinger.ScrollPane
import yesweburp.Settings
import yesweburp.api.Program
import yesweburp.openInBrowser
import yesweburp.ui.BurpConfig.createConfigFrame
import yesweburp.ui.matchSizes
import java.awt.*
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.font.TextAttribute
import java.lang.StrictMath.min
import java.util.*
import javax.swing.Box
import javax.swing.JEditorPane
import javax.swing.JLabel
import javax.swing.JTable
import javax.swing.border.EmptyBorder
import kotlin.reflect.jvm.internal.impl.resolve.calls.inference.CapturedType


class ProgramInfoPanel(program: Program) : BorderPanel() {


    private class TitleBar(program: Program) : GridBagPanel() {
        init {
            border = EmptyBorder(10, 10, 10, 10)
            val title = Label(program.title) {
                horizontalAlignment = JLabel.CENTER
                font = font.deriveFont(font.style or Font.BOLD, 20f)
                cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                toolTipText = "Open in browser"
                addMouseListener(object : MouseAdapter() {
                    override fun mouseClicked(e: MouseEvent?) {
                        openInBrowser("https://yeswehack.com/programs/${program.slug}")
                    }
                })
            }


            val privateLabel = Label {
                if (program.public) {
                    text = "Public"
                    font = font.deriveFont(font.style or Font.BOLD)
                } else {
                    text = "Private"
                    foreground = Color(0xff6633)
                    font = font.deriveFont(font.style or Font.BOLD)
                }
            }
            val configButton = Button("Configure Burp") {
                onClick {
                    createConfigFrame(program)
                }
            }

            matchSizes(privateLabel, configButton)
            add(privateLabel, gridY = 0)
            add(Box.createHorizontalGlue(), gridY = 0, weightX = 1.0, fill = GridBagConstraints.HORIZONTAL)
            add(title, gridY = 0)
            add(Box.createHorizontalGlue(), gridY = 0, weightX = 1.0, fill = GridBagConstraints.HORIZONTAL)
            add(configButton, gridY = 0)
        }
    }

    private class HTMLBox(rules: String) : BorderPanel() {
        init {
            border = EmptyBorder(5, 0, 0, 0)
            val css =
                "html{width:600px;padding:5px;font-family: InriaSans,Arial,sans-serif;} p{text-align: justify} img{max-width:100%}"
            val htmlRules =
                JEditorPane("text/html", "<html><head><style>${css}</style></head><body>${rules}</body></html>")
            htmlRules.isEditable = false
            htmlRules.isOpaque = true
            htmlRules.alignmentY = JEditorPane.TOP_ALIGNMENT
            center = ScrollPane(htmlRules) {
                maximumSize = Dimension(Int.MAX_VALUE, Int.MAX_VALUE)
                verticalScrollBar.unitIncrement = 16
                horizontalScrollBar.unitIncrement = 16
            }
        }
    }


    private class ScrollList(title: String, values: List<String>) : BorderPanel() {
        init {
            addTitleBorder(title)
            center = ScrollPane(SList(values))
        }
    }

    private class ScopeTable(program: Program) : BorderPanel() {
        private class ReadOnlyTable(values: Array<Array<String>>, columns: Array<String>) : JTable(values, columns) {
            override fun editCellAt(row: Int, column: Int, e: EventObject?): Boolean {
                return false
            }
        }

        init {
            addTitleBorder("In scope")
            val columns = arrayOf("Scope", "Type", "Low", "Medium", "High", "Critical")
            val data = program.scopes.map { scope ->
                val rewardGrid = when (scope.asset_value) {
                    "low" -> program.reward_grid_low
                    "medium" -> program.reward_grid_medium
                    "high" -> program.reward_grid_high
                    else -> program.reward_grid_default
                }

                fun Int.withMoneySign(): String? {
                    if (this == 0) return null
                    return if (program.business_unit.currency == "USD") "$$this" else "$this€"
                }
                arrayOf(
                    scope.scope,
                    scope.scope_type,
                    rewardGrid?.bounty_low?.withMoneySign() ?: "-",
                    rewardGrid?.bounty_medium?.withMoneySign() ?: "-",
                    rewardGrid?.bounty_high?.withMoneySign() ?: "-",
                    rewardGrid?.bounty_critical?.withMoneySign() ?: "-"
                )
            }.toTypedArray()
            val scopeList = ReadOnlyTable(data, columns)
            val tableModel = scopeList.columnModel
            for (i in columns.indices) {
                val column = tableModel.getColumn(i)
                column.preferredWidth = if (i == 0) scopeList.preferredSize.width else 20
            }
            center = ScrollPane(scopeList)
        }
    }


    init {
        border = EmptyBorder(5, 0, 5, 5)
        top = TitleBar(program)
        center = TabbedPane {
            addTab("Rules", HTMLBox(program.rules_html))
            addTab("Scopes", BorderPanel {
                center = ScopeTable(program)
                bottom = ScrollList("Out of scope", program.out_of_scope)
            })
            addTab("Qualifying vulnerabilities", GridPanel(0, 2) {
                addPaddingBorder(top = 5)
                add(ScrollList("Qualifying vulnerability", program.qualifying_vulnerability))
                add(ScrollList("Non qualifying vulnerability", program.non_qualifying_vulnerability))
            })
            if (program.account_access_html is String) {
                addTab("Account access", BorderPanel {
                    center = HTMLBox(program.account_access_html)
                })
            }
            selectedIndex = min(Settings.favoriteTab, tabCount - 1)
            addChangeListener {
                Settings.favoriteTab = selectedIndex
            }
        }

    }
}