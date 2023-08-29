package yesweburp.api

class APIException(msg: String?) : Exception(msg)

data class Pagination(val nb_pages: Int, val page: Int, val result_per_page: Int)
data class Page<T>(val items: List<T>, val pagination: Pagination)

data class BusinessUnit(val currency: String)
data class Scope(val scope: String, val scope_type: String, val asset_value: String)
data class ShortProgram(val title: String, val slug: String)
data class RewardGrid(
    val bounty_low: Int? = null,
    val bounty_medium: Int? = null,
    val bounty_high: Int? = null,
    val bounty_critical: Int? = null
)

data class Program(
    val title: String,
    val slug: String,
    val rules_html: String,
    val scopes: List<Scope>,
    val out_of_scope: List<String>,
    val public: Boolean,
    val qualifying_vulnerability: List<String>,
    val non_qualifying_vulnerability: List<String>,
    val business_unit: BusinessUnit,
    val vpn_active: Boolean,
    val user_agent: String? = null,
    val reward_grid_default: RewardGrid? = null,
    val reward_grid_very_low: RewardGrid? = null,
    val reward_grid_low: RewardGrid? = null,
    val reward_grid_medium: RewardGrid? = null,
    val reward_grid_high: RewardGrid? = null,
    val account_access_html: String? = null,
)

data class Login(val email: String, val password: String)
data class LoginOTP(val token: String, val code: String)
data class LoginResponse(val token: String?, val totp_token: String?)
data class LoginResponseTOTP(val totp_token: String)
data class APIError(val code: Int, val message: String)


enum class AuthMethod(val label: String) {
    ANONYMOUS("Anonymous"),
    EMAIL_PASSWORD("Email / Password"),
    EMAIL_PASSWORD_OTP("Email / Password + OTP");

    val requirePassword: Boolean
        get() {
            return this == EMAIL_PASSWORD || this == EMAIL_PASSWORD_OTP
        }
    val requireEmail: Boolean
        get() {
            return this == EMAIL_PASSWORD || this == EMAIL_PASSWORD_OTP
        }

    val requireOTP: Boolean
        get() {
            return this == EMAIL_PASSWORD_OTP
        }

    companion object {
        fun labels(): Array<String> {
            return values().map { it.label }.toTypedArray()
        }

        private val map = values().associateBy(AuthMethod::label)
        fun fromValue(type: String) = map[type] ?: throw RuntimeException("Unreachable")
    }
}