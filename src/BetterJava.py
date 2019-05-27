#!/usr/bin/env python
#
# File: BetterJava.py
# by @BitK_
#
import re
from java.awt import (
    GridBagConstraints,
    FlowLayout,
    GridLayout,
    GridBagLayout,
    Insets,
    Desktop,
)

from java.awt.event import ActionListener
from javax.swing.event import ChangeListener, HyperlinkListener
from javax.swing import (
    JEditorPane,
    JTextField,
    JSplitPane,
    JTextArea,
    JPasswordField,
    JCheckBox,
    JButton,
    JLabel,
    JPanel,
    BoxLayout,
)

from collections import OrderedDict
from javax.swing.BorderFactory import (
    createEtchedBorder,
    createTitledBorder,
    createCompoundBorder,
    createEmptyBorder,
)
from javax.swing.text.html import HTMLEditorKit


def make_title_border(title, padding=None):
    title_border = createTitledBorder(createEtchedBorder(1), title)
    title_border.setTitlePosition(2)
    title_border.setTitleJustification(2)
    if padding is not None:
        pad_border = createEmptyBorder(padding, padding, padding, padding)
        title_border = createCompoundBorder(title_border, pad_border)
    return title_border


def identity(x, *args, **kwargs):
    return x


TEXT_ELEMENTS = (JTextField, JTextArea, JPasswordField, JButton)

BOOL_ELEMENTS = (JCheckBox,)


class HTMLRenderer(JEditorPane):
    def __init__(self, html="", *args, **kwargs):
        JEditorPane.__init__(self)
        self.setEditable(False)

        self.kit = HTMLEditorKit()
        self.setEditorKit(self.kit)
        self.setDocument(self.kit.createDefaultDocument())
        self.setText(html)
        self.addHyperlinkListener(CallbackHyperlinkListener(self.on_link_click))

    def add_css_rule(self, css):
        styleSheet = self.kit.getStyleSheet()
        styleSheet.addRule(css)

    def add_css_file(self, filename):
        with open(filename, "r") as f:
            self.add_css_rule(f.read())

    def on_link_click(self, event):
        if event.getEventType() != event.EventType.ACTIVATED:
            return
        url = event.getURL()
        if url:
            Desktop.getDesktop().browse(url.toURI())


class Field(object):
    def __init__(self, name, element, label=None, validators=[]):
        self.name = name
        self.element = element
        self.default = None

        if label is None:
            self.label = " ".join(s.capitalize() for s in name.split("_"))
        else:
            self.label = label
        self.validators = validators

    def validate(self):
        value = self.value
        for validator in self.validators:
            validator(value)
        return value

    @property
    def value(self):
        if isinstance(self.element, TEXT_ELEMENTS):
            value = self.element.getText()
        elif isinstance(self.element, BOOL_ELEMENTS):
            value = bool(self.element.isSelected())
        else:
            raise NotImplementedError
        return value

    @value.setter
    def value(self, value):
        if value is None:
            return
        if isinstance(self.element, TEXT_ELEMENTS):
            self.element.setText(value)
        elif isinstance(self.element, BOOL_ELEMENTS):
            self.element.setSelected(value)
        else:
            raise NotImplementedError

    def set_default(self, value=None, getter=None):
        if getter:
            self.value = getter(self.name)
        if value is not None:
            self.value = value
        return self

    def readonly(self, state=True):
        self.element.setEnabled(not state)
        return self


class CallbackHyperlinkListener(HyperlinkListener):
    def __init__(self, callback):
        HyperlinkListener.__init__(self)
        self._callback = callback

    def hyperlinkUpdate(self, event):
        self._callback(event)


class CallbackActionListener(ActionListener):
    def __init__(self, callback):
        ActionListener.__init__(self)
        self._callback = callback

    def actionPerformed(self, event):
        self._callback(event)


class CallbackChangeListener(ChangeListener):
    def __init__(self, callback):
        ChangeListener.__init__(self)
        self._callback = callback

    def stateChanged(self, event):
        self._callback(event)


class Validator:
    @classmethod
    def length(cls, min=None, max=None):
        def length_wrapper(value):
            length = len(value)
            if max is not None and length > max:
                raise ValidatorException("Too long {} (max={})".format(length, max))
            if min is not None and length < min:
                raise ValidatorException("Too short {} (min={})".format(length, min))

        return length_wrapper

    @classmethod
    def required(cls, value):
        if not value:
            raise ValidatorException("This field is required")

    @classmethod
    def regex(cls, regex_str):
        reg = re.compile(regex_str)

        def regex_wrapper(value):
            if not reg.match(value):
                raise ValidatorException(
                    'Value do not match regex "{}"'.format(regex_str)
                )

        return regex_wrapper


def make_constraints(**kwargs):
    constraints = GridBagConstraints()
    for name, value in kwargs.items():
        setattr(constraints, name, value)
    return constraints


class SplitPanel(JSplitPane):
    def __init__(
        self,
        left_element,
        right_element,
        direction=JSplitPane.HORIZONTAL_SPLIT,
        expandable=True,
    ):
        JSplitPane.__init__(self, direction, left_element, right_element)
        self.setOneTouchExpandable(expandable)


class FixedRowPanel(JPanel):
    def __init__(self, *args, **kwargs):
        JPanel.__init__(self, *args, **kwargs)
        self.setLayout(GridLayout(1, 0))


class FixedColumnPanel(JPanel):
    def __init__(self, *args, **kwargs):
        JPanel.__init__(self, *args, **kwargs)
        self.setLayout(GridLayout(0, 1))


class RowPanel(JPanel):
    def __init__(self, *args, **kwargs):
        JPanel.__init__(self, *args, **kwargs)
        self.setLayout(FlowLayout())


class ColumnPanel(JPanel):
    def __init__(self, *args, **kwargs):
        JPanel.__init__(self, *args, **kwargs)
        self.setLayout(BoxLayout(self, BoxLayout.PAGE_AXIS))


class ValidatorException(ValueError):
    pass


class DualForm(JPanel):
    def __init__(self, title=None, padding=50):
        super(DualForm, self).__init__()
        self._fields = OrderedDict()
        self.setLayout(GridBagLayout())

        etched_border = createEtchedBorder(1)
        if title is not None:
            title_border = createTitledBorder(etched_border, title)
            title_border.setTitlePosition(2)
            title_border.setTitleJustification(2)

            self.setBorder(title_border)
        else:
            self.setBorder(etched_border)
        self.setAlignmentX(JPanel.LEFT_ALIGNMENT)

    def _update_size(self):
        self.setMaximumSize(self.getPreferredSize())

    def add_field(self, field, anchor=GridBagConstraints.WEST):
        if field.label:
            label = JLabel("{} :".format(field.label), JLabel.LEFT)
            self.add(
                label,
                make_constraints(
                    gridy=len(self._fields), gridx=0, anchor=GridBagConstraints.WEST
                ),
            )

        insets = Insets(3, 3, 3, 3)
        self.add(
            field.element,
            make_constraints(
                gridy=len(self._fields), gridx=1, anchor=anchor, insets=insets
            ),
        )
        self._update_size()
        self._fields[field.name] = field

    def validate(self, onsuccess=identity, onfail=identity):
        def callback(event):
            errors = OrderedDict()
            for field in self._fields.values():
                try:
                    field.validate()
                except ValidatorException as e:
                    errors[field.name] = str(e)
            if errors:
                onfail(self._fields, errors)
            else:
                onsuccess(self._fields)

        return callback

    def getInsets(self):
        size = 15
        return Insets(size + 10, size, size, size)
