package yesweburp.ui.options

import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import swinger.*
import yesweburp.Events.programsLoaded
import yesweburp.Settings
import yesweburp.VERSION
import yesweburp.api.API
import yesweburp.api.AuthMethod
import yesweburp.ui.DisabledTextField
import yesweburp.ui.Padding
import java.awt.Component
import java.awt.Dimension
import java.awt.GridBagConstraints
import javax.swing.Box.createHorizontalGlue
import javax.swing.JTextField

class APIPanel : GridBagPanel() {
    init {
        alignmentX = LEFT_ALIGNMENT
        addTitleBorder("API")
        val auth = AuthMethod.fromValue(Settings.authMethod)

        val email = TextField(Settings.userEmail) {
            isEnabled = auth.requireEmail
        }
        val password = PasswordField(Settings.userPassword) {
            isEnabled = auth.requirePassword
        }
        val otp = TextField {
            isEnabled = auth.requireOTP
        }
        val rememberPassword = CheckBox {
            isSelected = Settings.rememberPassword
            isEnabled = auth.requirePassword
        }
        val errorMsg = DisabledTextField()

        errorMsg.isVisible = false
        val authMethodList = ComboBox(AuthMethod.labels()) {
            selectedIndex = values.indexOf(auth.label)
            onChange { selected ->
                val method = AuthMethod.fromValue(selected)
                email.isEnabled = method.requireEmail
                password.isEnabled = method.requirePassword
                rememberPassword.isEnabled = method.requirePassword
                otp.isEnabled = method.requireOTP
            }
        }

        val fetchButton = Button("Fetch programs") {
            addActionListener {
                val authEmail = email.text
                val authPassword = password.text
                val authOTP = otp.text
                val authMethod = AuthMethod.fromValue(authMethodList.selected)
                Settings.userEmail = authEmail
                if (rememberPassword.isSelected) {
                    Settings.rememberPassword = true
                    Settings.userPassword = authPassword
                } else {
                    Settings.rememberPassword = false
                    Settings.userPassword = ""
                    password.text = ""
                }
                Settings.authMethod = authMethod.label
                otp.text = ""


                errorMsg.isVisible = false
                revalidate()
                this@APIPanel.maximumSize = Dimension(600, this@APIPanel.preferredSize.height)

                GlobalScope.launch {
                    try {
                        when (authMethod) {
                            AuthMethod.EMAIL_PASSWORD -> API.auth(authEmail, authPassword)
                            AuthMethod.EMAIL_PASSWORD_OTP -> API.auth(authEmail, authPassword, authOTP)
                        }

                        isEnabled = false
                        programsLoaded.listenOnce {
                            isEnabled = true
                        }
                        API.fetchPrograms()
                    } catch (e: Exception) {
                        isEnabled = true
                        errorMsg.text = e.message ?: ""
                        errorMsg.isVisible = true
                        revalidate()
                        this@APIPanel.maximumSize = Dimension(600, this@APIPanel.preferredSize.height)
                    }
                }
            }
        }



        addSetting("Version", TextField(VERSION) {
            isEditable = false
            isOpaque = true
            isRequestFocusEnabled = false
            horizontalAlignment = JTextField.CENTER
        })
        addSetting("API URL", DisabledTextField("https://api.yeswehack.com"))
        addSetting("Authentication", authMethodList)
        addSetting("Email", email)
        addSetting("Password", password)
        addSetting("OTP", otp)
        addSetting("Remember password", rememberPassword)
        addSetting(null, fetchButton)
        add(
            errorMsg,
            gridX = 0,
            gridWidth= 2,
            weightX = 2.0,
            fill = GridBagConstraints.HORIZONTAL,
            insets = Padding(5),
            anchor = GridBagConstraints.WEST
        )
        maximumSize = Dimension(600, preferredSize.height)
    }


    private fun addSetting(label: String?, setting: Component) {
        val left = if (label == null) createHorizontalGlue() else Label("$label :")
        add(
            left,
            gridX = 0,
            insets = Padding(5),
            anchor = GridBagConstraints.WEST,
        )
        add(
            setting,
            gridX = 1,
            weightX = 1.0,
            fill = GridBagConstraints.HORIZONTAL,
            insets = Padding(5),
            anchor = GridBagConstraints.WEST
        )
    }

}