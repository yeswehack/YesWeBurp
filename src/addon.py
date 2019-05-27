from burp import IBurpExtender, ITab
from javax.swing import JTabbedPane
from Tabs import OptionsTab, ProgramsTab
from api import Auth, AuthMethod, YWHApi, APIException
from helpers import BurpHTTP
import context


DEFAULT_URI = "https://api.yeswehack.com"
EXTENSION_NAME = "YesWeBurp"
TAB_NAME = "YesWeHack"
VERSION = "1.0.0"


class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        context.version = VERSION
        context.callbacks = callbacks
        context.callbacks.setExtensionName(EXTENSION_NAME)

        api_url = context.settings.load("apiurl", DEFAULT_URI)
        auth_name = context.settings.load("auth_method", AuthMethod.anonymous)

        if auth_name == AuthMethod.email_pass:
            email = context.settings.load("email")
            passwd = context.settings.load("password")
            auth = Auth.email_pass(email, passwd)
        else:
            auth = Auth.anonymous()

        try:
            context.api = YWHApi(api_url, fetcher=BurpHTTP(), auth=auth)
        except APIException:
            context.api = YWHApi(api_url, fetcher=BurpHTTP(), auth=Auth.anonymous())

        context.tabs["Programs"] = ProgramsTab()
        context.tabs["Options"] = OptionsTab()
        tab = JTabbedPane(JTabbedPane.TOP)

        for name, panel in context.tabs.items():
            context.callbacks.customizeUiComponent(panel)
            tab.add(name, panel)

        self.getUiComponent = lambda: tab
        context.callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return TAB_NAME
