#!/usr/bin/env python
#
# File: OptionTab.py
# by @BitK_
#
from java.awt import Color, GridBagLayout, Insets
from java.awt.GridBagConstraints import EAST, WEST
from javax.swing import (
    JTextField,
    JComboBox,
    JPanel,
    JLabel,
    JPasswordField,
    JCheckBox,
    JButton,
    JScrollPane,
)
from BetterJava import (
    ColumnPanel,
    make_title_border,
    make_constraints,
    CallbackActionListener,
)
from helpers import async_call
from api import AuthMethod, Auth

import context


def padding(size):
    return Insets(size, size, size, size)


class StatusText(JTextField):
    def __init__(self, *args, **kwargs):
        JTextField.__init__(self, *args, **kwargs)
        self.setEditable(False)
        self.setRequestFocusEnabled(False)
        self.setHorizontalAlignment(JTextField.CENTER)

    def set(self, text, bg=Color.WHITE, fg=Color.BLACK):
        self.setText(text)
        self.setBackground(bg)
        self.setForeground(fg)


class APIBox(JPanel):
    def __init__(self):
        self.setLayout(GridBagLayout())
        self.setBorder(make_title_border("API"))
        self.setAlignmentX(JPanel.LEFT_ALIGNMENT)

        self.status = StatusText(25)
        self.add(JLabel("Status :"), gridx=0)
        self.add(self.status, gridx=1)

        self.version = StatusText(25)
        self.version.set(context.version, bg=Color.GRAY)
        self.add(JLabel("Version :"), gridx=0)
        self.add(self.version, gridx=1)

        settings = context.settings

        txt_url = JTextField(25)
        txt_url.setText(settings.load("apiurl", "https://api.yeswehack.com/"))
        self.add(JLabel("API URL :"), gridx=0)
        self.add(txt_url, gridx=1)

        combo_auth = JComboBox((AuthMethod.anonymous, AuthMethod.email_pass))
        combo_auth.setSelectedItem(settings.load("auth_method", AuthMethod.anonymous))
        combo_auth.addActionListener(CallbackActionListener(self.auth_method_changed))

        self.add(JLabel("Authentication :"), gridx=0)
        self.add(combo_auth, gridx=1)

        txt_mail = JTextField(25)
        txt_mail.setText(settings.load("email"))
        self.add(JLabel("Email :"), gridx=0)
        self.add(txt_mail, gridx=1)

        txt_pass = JPasswordField(25)
        txt_pass.setText(settings.load("password"))
        self.add(JLabel("Password :"), gridx=0)
        self.add(txt_pass, gridx=1)

        check_remember = JCheckBox()
        check_remember.setSelected(settings.load_bool("remember", True))
        self.add(JLabel("Remember password :"), gridx=0)
        self.add(check_remember, gridx=1)

        check_autoconnect = JCheckBox()
        check_autoconnect.setSelected(settings.load_bool("autoconnect", True))
        self.add(JLabel("Auto reconnect :"), gridx=0)
        self.add(check_autoconnect, gridx=1)

        btn_group = JPanel()

        btn_save = JButton("Save settings")
        btn_save.addActionListener(CallbackActionListener(self.save_settings))
        btn_connect = JButton("Connect")
        btn_connect.addActionListener(CallbackActionListener(self.connect))

        btn_group.add(btn_save)
        btn_group.add(btn_connect)
        self.add(btn_group, gridx=1, anchor=EAST)

        self.inputs = {
            "apiurl": txt_url,
            "auth_method": combo_auth,
            "email": txt_mail,
            "password": txt_pass,
            "remember": check_remember,
            "autoconnect": check_autoconnect,
            "connect": btn_connect,
        }

        self.setMaximumSize(self.getPreferredSize())

        self.set_status_error("Disconnected")
        self.auth_method_changed()

    def auth_method_changed(self, *args):
        method = self.inputs["auth_method"].getSelectedItem()
        if method == AuthMethod.anonymous:
            self.inputs["email"].setEnabled(False)
            self.inputs["password"].setEnabled(False)
            self.inputs["remember"].setEnabled(False)
        elif method == AuthMethod.email_pass:
            self.inputs["email"].setEnabled(True)
            self.inputs["password"].setEnabled(True)
            self.inputs["remember"].setEnabled(True)

    def save_settings(self, event):
        settings = context.settings
        settings.save("apiurl", self.inputs["apiurl"].getText())
        settings.save("auth_method", self.inputs["auth_method"].getSelectedItem())
        settings.save("email", self.inputs["email"].getText())
        if self.inputs["remember"].isSelected():
            settings.save("password", self.inputs["password"].getText())
        else:
            settings.save("password", "")
            self.inputs["password"].setText("")

        settings.save("remember", self.inputs["remember"].isSelected())
        settings.save("autoconnect", self.inputs["autoconnect"].isSelected())

    def connect(self, event):
        api_url = self.inputs["apiurl"].getText()
        auth_method = self.inputs["auth_method"].getSelectedItem()

        context.api.change_server(api_url)
        if auth_method == AuthMethod.anonymous:
            context.api.change_auth(Auth.anonymous())
        if auth_method == AuthMethod.email_pass:
            auth = Auth.email_pass(
                self.inputs["email"].getText(), self.inputs["password"].getText()
            )
            context.api.change_auth(auth)
        context.addon.connect()

    def set_status_success(self, txt):
        self.status.set(txt, Color(0x006400), Color.WHITE)

    def set_status_error(self, txt):
        self.status.set(txt, Color(0xB80000), Color.WHITE)

    def show_error(self, error):
        txt = "ERROR: {}".format(error)
        self.set_status_error(txt)

    def show_username(self):
        hunter = context.api.get_user()
        txt = "Connected as {}".format(hunter.username)
        self.set_status_success(txt)

    def add(self, el, **constraints):
        default = {"insets": padding(5), "anchor": WEST}

        default.update(constraints)
        JPanel.add(self, el, make_constraints(**default))


class OptionsTab(JScrollPane):
    def __init__(self):
        panel = ColumnPanel()
        apibox = APIBox()
        panel.add(apibox)
        JScrollPane.__init__(self, panel)
        context.addon.register_on_connect(apibox.show_username)
        context.addon.register_on_error(apibox.show_error)
