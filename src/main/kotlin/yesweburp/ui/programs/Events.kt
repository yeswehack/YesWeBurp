package yesweburp.ui.programs

import yesweburp.EventBus
import yesweburp.api.Program

object  Events {
    val programSelected = EventBus<Program>()
}