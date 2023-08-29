package yesweburp.ui.BurpConfig

import swinger.*
import yesweburp.api.Program
import yesweburp.api.Scope
import yesweburp.callbacks
import yesweburp.config.BurpConfig
import yesweburp.config.BurpReplaceRule
import yesweburp.config.BurpScopeRule
import java.awt.Color
import java.awt.Dimension
import java.awt.EventQueue
import java.awt.Font
import javax.swing.*
import javax.swing.table.DefaultTableModel


fun hostToRegex(s: String): String {
    var host = s
    var reg = "^"
    if (host.startsWith("*.")) {
        reg += "(.*\\.)?"
        host = host.substring(2)
    }
    reg += host.replace(".", "\\.")
    reg += "$"
    return reg
}

fun guessScope(scope: Scope): BurpScopeRule? {
    if (scope.scope_type == "ip-address") {
        return BurpScopeRule(host = scope.scope)
    }

    val reg = arrayOf(
            "^(?:(?<protocol>https?):\\/\\/)?",
            "(?<host>[^/:?#\\s]+)",
            "(?::(?<port>(?:\\d+|\\(?(?:\\d+\\|)*\\d+\\))))?",
            "(?<path>\\/.*)?",
    ).joinToString("")
    val match = Regex(reg).matchEntire(scope.scope)

    if (match?.groups != null) {
        val rule = BurpScopeRule()
        val groups = match.groups
        rule.protocol = groups[1]?.value ?: "any"
        rule.host = hostToRegex(groups[2]?.value ?: "")
        rule.port = groups[3]?.value ?: ""
        rule.file = groups[4]?.value ?: ""
        return rule
    }
    return null
}


fun createConfigFrame(program: Program) {
    EventQueue.invokeLater {
        BurpConfigWindow(program)
    }
}

class BurpConfigWindow(program: Program) : JFrame("Configure Burp for ${program.title}") {
    init {
        defaultCloseOperation = DISPOSE_ON_CLOSE
        callbacks.customizeUiComponent(this)
        contentPane = BurpConfigPanel(program)
        val mainWindow = SwingUtilities.getWindowAncestor(this)
        pack()
        setLocationRelativeTo(mainWindow)
        isLocationByPlatform = true
        isVisible = true
        requestFocus()
    }
}

class BurpConfigPanel(program: Program) : ColumnPanel() {

    class ScopeTable(scopes: List<Scope>) : JTable() {
        private val columns = arrayOf("Program rule", "Protocol", "Host", "Port", "File")
        private val scopeRuleInfos: List<Pair<String, BurpScopeRule?>> = scopes.map { Pair(it.scope, guessScope(it)) }


        init {
            getTableHeader().reorderingAllowed = false
            val values = scopeRuleInfos.map { (scope, rule) ->
                        arrayOf(
                                scope,
                                rule?.protocol ?: "",
                                rule?.host ?: "",
                                rule?.port ?: "",
                                rule?.file ?: ""
                        )
                    }.toTypedArray()

            model = DefaultTableModel(values, columns)

            with(columnModel.getColumn(1)) {
                val comboBox = JComboBox<String>()
                comboBox.addItem("any")
                comboBox.addItem("http")
                comboBox.addItem("https")
                cellEditor = DefaultCellEditor(comboBox)
            }
            columnModel.getColumn(1).preferredWidth = 5
            columnModel.getColumn(3).preferredWidth = 5

        }

        fun getSelectedRules(): List<BurpScopeRule> {
            return selectedRows.map { rowIdx ->
                BurpScopeRule(
                        enabled = true,
                        protocol = model.getValueAt(rowIdx, 1) as String,
                        host = model.getValueAt(rowIdx, 2) as String,
                        port = model.getValueAt(rowIdx, 3) as String,
                        file = model.getValueAt(rowIdx, 4) as String,
                )
            }

        }
    }


    init {
        addPaddingBorder(top = 5)
        val scopes = BorderPanel {
            vgap = 5
            addTitleBorder("Scopes")
            val table = ScopeTable(program.scopes)

            val addButton = Button("Add to scope (0)") {
                isEnabled = false
                onClick {
                    BurpConfig.addTargetScope(table.getSelectedRules())
                }
            }
            table.selectionModel.addListSelectionListener {
                addButton.text = "Add to scope (${table.selectedRows.size})"
                addButton.isEnabled = table.selectedRows.isNotEmpty()
            }
            center = ScrollPane(table)
            bottom = addButton
            preferredSize = Dimension(800, preferredSize.height)
        }

        if (program.vpn_active) {
            val lbl = Label("Using YesWeHack VPN is required for this program") {

                foreground = Color(0xff6633)
                font = font.deriveFont(font.style or Font.BOLD)
            }
            lbl.alignmentX = CENTER_ALIGNMENT
            add(lbl)
        }

        add(scopes)

        if (program.user_agent is String) {
            val uaBox = BorderPanel {
                vgap = 5
                addTitleBorder("User-Agent")
                val uaTable = JTable(
                        arrayOf(arrayOf("^User-Agent: (.*)\$", "User-Agent: \$1 ${program.user_agent}")),
                        arrayOf("Match", "Replace")
                )
                uaTable.minimumSize = uaTable.preferredSize
                uaTable.preferredScrollableViewportSize = uaTable.preferredSize
                center = ScrollPane(uaTable)
                bottom = Button("Add match/replace rule") {
                    onClick {
                        val match = uaTable.model.getValueAt(0, 0) as String;
                        val replace = uaTable.model.getValueAt(0, 1) as String;
                        BurpConfig.addMatchReplace(BurpReplaceRule(
                            rule_type = "request_header",
                            string_match = match,
                            string_replace = replace,
                            comment = "${program.slug} - YesWeBurp"
                        ))

                    }
                }

            }
            add(uaBox)
        }
    }
}
