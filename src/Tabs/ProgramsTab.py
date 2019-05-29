3  #!/usr/bin/env python
#
# File: ProgramsTab.py
# by @BitK_
#
import re
import json
from functools import partial
from java.awt import (
    Font,
    Color,
    GridBagLayout,
    GridBagConstraints,
    Dimension,
    Desktop,
    GridLayout,
    BorderLayout,
    FlowLayout,
)
from java.net import URI
from javax.swing import (
    Box,
    BoxLayout,
    SpringLayout,
    JList,
    JTable,
    JPanel,
    JButton,
    JScrollPane,
    JLabel,
    JTextField,
    ListCellRenderer,
    ListSelectionModel,
    DefaultListModel,
)
from BetterJava import (
    ColumnPanel,
    make_constraints,
    RowPanel,
    FixedColumnPanel,
    FixedRowPanel,
    SplitPanel,
    make_title_border,
    HTMLRenderer,
    CallbackActionListener,
)
from javax.swing.BorderFactory import createEmptyBorder
from helpers import async_call, same_size
import context


def guess_scope(s):
    domain_pattern = re.compile(
        (
            r"^"
            r"(?:(?P<protocol>https?)://)?"
            r"(?P<host>"
            r"(?:\*\.)?"  # allow wildcard at the start
            r"[a-zA-Z0-9]+(?:\-[a-zA-Z0-9-]+)*"
            r"(?:\.[a-zA-Z0-9]+(?:\-[a-zA-Z0-9-]+)*)+"
            r")"
            r"(?P<port>:[0-9]+)?"  # potential port
            r"(?:/(?P<file>.*))?"  # potential path
            r"$"
        )
    )
    match = domain_pattern.match(s)
    if match:
        url = {"enabled": True}
        url["protocol"] = match.group("protocol") or "any"
        host = re.escape(match.group("host"))
        host_with_stars = host.replace("\\*", ".*")
        url["host"] = "^{}$".format(host_with_stars)
        if match.group("port"):
            url["port"] = match.group("port")
        if match.group("file"):
            url["file"] = match.group("file")
        return url
    else:
        return None


class ScopesBox(ColumnPanel):
    def __init__(self, scopes):
        ColumnPanel.__init__(self)

        scope_list = JList(tuple(entry.scope for entry in scopes))
        scope_list.setVisibleRowCount(10)
        btn_list = RowPanel()
        select_all = JButton("Select all")
        select_all.setMaximumSize(select_all.getPreferredSize())
        select_all.addActionListener(
            CallbackActionListener(partial(self.do_selection, scope_list, scopes))
        )
        btn_list.add(select_all)

        add_scope = JButton("Add to scope")
        add_scope.setMaximumSize(add_scope.getPreferredSize())
        add_scope.addActionListener(
            CallbackActionListener(partial(self.add_to_scope, scope_list))
        )
        btn_list.add(add_scope)

        self.add(JScrollPane(scope_list))
        self.add(btn_list)
        self.setBorder(make_title_border("Scopes"))
        self.setMaximumSize(Dimension(9999999, self.getPreferredSize().height))

    def add_to_scope(self, scope_list, event):

        config = json.loads(context.callbacks.saveConfigAsJson("target.scope"))
        config["target"]["scope"]["advanced_mode"] = True
        for maybe_url in scope_list.getSelectedValues():
            url = guess_scope(maybe_url)
            if url:
                config["target"]["scope"]["include"].append(url)
        context.callbacks.loadConfigFromJson(json.dumps(config))

    def do_selection(self, scope_list, scopes, event):
        scope_list.setSelectionInterval(0, len(scopes) - 1)


class OutOfScopeBox(ColumnPanel):
    def __init__(self, out_of_scope):
        ColumnPanel.__init__(self)

        out_of_scope_list = JList(tuple(out_of_scope))
        self.add(JScrollPane(out_of_scope_list))
        self.setBorder(make_title_border("Out of scope"))
        self.setMaximumSize(Dimension(9999999, self.getPreferredSize().height))


class RewardBox(JPanel):
    def __init__(self, program):
        self.setLayout(GridLayout())
        self.setBorder(make_title_border("Rewards"))
        rewards = [
            ["minimum", program.bounty_reward_min],
            ["low", program.bounty_reward_low],
            ["medium", program.bounty_reward_medium],
            ["high", program.bounty_reward_high],
            ["critical", program.bounty_reward_critical],
        ]
        table = JTable(rewards, ["level", "reward"])
        table.setMaximumSize(table.getPreferredSize())
        self.add(table)


class StatsBox(JPanel):
    def __init__(self, program):
        self.setLayout(GridLayout())
        self.setBorder(make_title_border("Stats"))
        stats = [
            ["Average response time", program.stats.average_first_time_response],
            ["Reports - total", program.stats.total_reports],
            ["Reports - last month", program.stats.total_reports_current_month],
            ["Reports - last week", program.stats.total_reports_last7_days],
            ["Reports - last 24h", program.stats.total_reports_last24_hours],
            ["Hunter thanked", program.stats.total_hunter_thanked],
        ]
        table = JTable(stats, ["", ""])
        self.add(table)


class RulesBox(JScrollPane):
    def __init__(self, html_rules):
        html = u"<html><body>{}</body></html>".format(html_rules)
        html_renderer = HTMLRenderer(html)
        html_renderer.add_css_file("style.css")
        JScrollPane.__init__(self, html_renderer)
        self.setBorder(make_title_border("Rules"))


class TitleBtnBox(FixedColumnPanel):
    def __init__(self, program):
        url = "https://yeswehack.com/programs/{}".format(program.slug)
        btn = JButton("Open in browser")
        btn.addActionListener(
            CallbackActionListener(lambda _: Desktop.getDesktop().browse(URI(url)))
        )
        self.add(btn)


class UABox(JPanel):
    def __init__(self, program):
        self.setLayout(GridBagLayout())
        self.setBorder(make_title_border("User-Agent", padding=5))
        btn = JButton("Add to settings")
        ua_text = JTextField(program.user_agent)
        self.add(
            ua_text, make_constraints(weightx=4, fill=GridBagConstraints.HORIZONTAL)
        )
        self.add(btn, make_constraints(weightx=1))
        self.setMaximumSize(Dimension(9999999, self.getPreferredSize().height + 10))

        def add_to_options(event):
            prefix = "Generated by YWH-addon"
            config = json.loads(
                context.callbacks.saveConfigAsJson("proxy.match_replace_rules")
            )

            # remove other YWH addon rules
            match_replace_rules = filter(
                lambda rule: not rule["comment"].startswith(prefix),
                config["proxy"]["match_replace_rules"],
            )
            new_rule = {
                "is_simple_match": False,
                "enabled": True,
                "rule_type": "request_header",
                "string_match": "^User-Agent: (.*)$",
                "string_replace": "User-Agent: $1 {}".format(program.user_agent),
                "comment": "{} for {}".format(prefix, program.slug),
            }
            match_replace_rules.append(new_rule)
            config["proxy"]["match_replace_rules"] = match_replace_rules
            context.callbacks.loadConfigFromJson(json.dumps(config))

        btn.addActionListener(CallbackActionListener(add_to_options))


class TitleBox(JPanel):
    def __init__(self, program):
        self.setLayout(BorderLayout())
        title = JLabel(program.title)
        title.setFont(Font("Arial", Font.BOLD, 28))
        title.setHorizontalAlignment(JLabel.CENTER)
        title.setVerticalAlignment(JLabel.CENTER)
        title.setBorder(createEmptyBorder(15, 5, 15, 5))

        if not program.public:
            lbl = JLabel("Private")
            lbl.setFont(Font("Arial", Font.BOLD, 20))
            lbl.setForeground(Color(0xFF2424))
            lbl.setBorder(createEmptyBorder(15, 15, 15, 15))
            leftbox = lbl
        else:
            leftbox = Box.createHorizontalGlue()
        btnbox = TitleBtnBox(program)
        btnbox.setBorder(createEmptyBorder(5, 5, 5, 5))
        self.add(leftbox, BorderLayout.LINE_START)
        self.add(title, BorderLayout.CENTER)
        self.add(btnbox, BorderLayout.LINE_END)

        same_size(leftbox, btnbox)

        self.setMaximumSize(Dimension(99999, self.getPreferredSize().height))


class ProgramPane(JPanel):
    def __init__(self, program):
        self.setLayout(BorderLayout())

        left_col = RulesBox(program.rules_html)

        right_col = ColumnPanel()

        scopes = ScopesBox(program.scopes)
        right_col.add(scopes)

        if program.out_of_scope:
            out_of_scopes = OutOfScopeBox(program.out_of_scope)
            right_col.add(out_of_scopes)
        if program.user_agent:
            right_col.add(UABox(program))

        reward_stat = FixedRowPanel()
        reward_stat.add(RewardBox(program))
        reward_stat.add(StatsBox(program))
        reward_stat.setMaximumSize(
            Dimension(99999, reward_stat.getPreferredSize().height)
        )

        right_col.add(reward_stat)
        right_col.add(Box.createVerticalGlue())

        cols = FixedRowPanel()
        cols.add(left_col)
        cols.add(right_col)

        self.add(TitleBox(program), BorderLayout.PAGE_START)
        self.add(cols, BorderLayout.CENTER)


class ProgramRenderer(ListCellRenderer, JLabel):
    def getListCellRendererComponent(
        self, jlist, program, index, isSelected, cellHashFocus
    ):

        if isSelected:
            self.setBackground(Color(0xFF2424))
            self.setForeground(Color.white)
        else:
            if program.public:
                self.setBackground(Color.white)
            else:
                self.setBackground(Color(0xFFDDDDD))
            self.setForeground(Color.black)

        self.setText(program.title)
        self.setOpaque(1)
        self.setBorder(createEmptyBorder(5, 10, 5, 10))

        return self


class ProgramsTab(JPanel):
    def __init__(self):
        self.programs = []
        self.setLayout(BoxLayout(self, BoxLayout.PAGE_AXIS))

        self.JprogramList = JList()
        self.JprogramList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.JprogramList.addListSelectionListener(self.handle_select)
        scrollPane = JScrollPane(self.JprogramList)
        scrollPane.setMinimumSize(Dimension(300, 0))

        self.splitPane = SplitPanel(scrollPane, JPanel())
        self.add(self.splitPane)
        context.addon.register_on_connect(self.load_program_list)
        context.addon.register_on_error(self.display_error)

    def load_program_list(self):
        self.display_program_list(context.api.get_programs())

    def display_program_list(self, programs):
        self.programs = programs

        model = DefaultListModel()
        for program in programs:
            model.addElement(program)

        self.JprogramList.setModel(model)
        self.JprogramList.setCellRenderer(ProgramRenderer())

        if self.programs:
            async_call(
                lambda: context.api.get_program_details(self.programs[0].slug),
                self.load_program_details,
            )
        else:
            self.splitPane.setRightComponent(JPanel())

    def display_error(self, error):
        self.JprogramList.setListData(tuple())
        self.splitPane.setRightComponent(JLabel("You are disconnected"))

    def load_program_details(self, pgm_details):
        pane = ProgramPane(pgm_details)
        loc = self.splitPane.getDividerLocation()
        self.splitPane.setRightComponent(pane)
        self.splitPane.setDividerLocation(loc)

    def handle_select(self, event):
        jlist = event.source
        if event.valueIsAdjusting:
            return None
        selected_idx = jlist.getSelectedIndex()
        if selected_idx < 0 or selected_idx > len(self.programs):
            return None

        slug = self.programs[selected_idx].slug
        async_call(
            lambda: context.api.get_program_details(slug), self.load_program_details
        )
