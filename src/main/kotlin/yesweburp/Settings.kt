package yesweburp

import yesweburp.api.AuthMethod
import kotlin.reflect.KProperty


open class PersistentString(private val key: String, private val default: String = "") {
    operator fun getValue(thisRef: Any?, property: KProperty<*>): String {
        val saved = callbacks.loadExtensionSetting(key)
        if (saved.isNullOrEmpty()) {
            return default
        }
        return saved
    }

    operator fun setValue(thisRef: Any?, property: KProperty<*>, value: String) {
        callbacks.saveExtensionSetting(key, value)
    }
}

class PersistentInt(private val key: String, private val default: Int = 0) {
    operator fun getValue(thisRef: Any?, property: KProperty<*>): Int {
        val saved = callbacks.loadExtensionSetting(key)
        if (saved.isNullOrEmpty()) {
            return default
        }
        return saved.toInt()
    }

    operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Int) {
        callbacks.saveExtensionSetting(key, value.toString())
    }
}

class PersistentBoolean(private val key: String, private val default: Boolean = false) {
    operator fun getValue(thisRef: Any?, property: KProperty<*>): Boolean {
        val saved = callbacks.loadExtensionSetting(key)
        if (saved.isNullOrEmpty()) {
            return default
        }
        return saved.equals("true")
    }

    operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Boolean) {
        callbacks.saveExtensionSetting(key, value.toString())
    }
}

object Settings {
    var userEmail: String by PersistentString("USER_EMAIL")
    var userPassword: String by PersistentString("USER_PASSWORD")
    var rememberPassword: Boolean by PersistentBoolean("REMEMBER_PASSWORD")
    var authMethod: String by PersistentString("AUTH_METHOD", AuthMethod.ANONYMOUS.label)
    var favoriteTab: Int by PersistentInt("FAVORITE_TAB", 0)
}