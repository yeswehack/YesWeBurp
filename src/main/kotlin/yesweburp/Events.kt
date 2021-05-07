package yesweburp

import yesweburp.api.Program

object  Events {
    val programsLoaded = EventBus<List<Program>>()
}