package yesweburp.api


import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import yesweburp.Events.programsLoaded
import yesweburp.VERSION
import yesweburp.callbacks
import yesweburp.helpers


object API {
    private var token: String? = null
    private val jsonMapper = with(jacksonObjectMapper()) {
        configure(
            DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
            false
        )
    }
    private const val host = "api.yeswehack.com"
    private const val port = 443

    private fun sendRequest(request: ByteArray): ByteArray {
        val service = helpers.buildHttpService(host, port, port == 443)
        val response = callbacks.makeHttpRequest(service, request).response
        val responseInfo = helpers.analyzeResponse(response)
        val responseBody = response.slice(responseInfo.bodyOffset until response.size).toByteArray()
        if (responseInfo.statusCode.toInt() != 200) {
            if (responseInfo.headers.any { it == "Content-Type: application/json" }) {
                val err: APIError = jsonMapper.readValue(responseBody)
                throw APIException(err.message)
            }
            throw  APIException("API Error ${responseInfo.statusCode}")
        }
        return responseBody
    }

    private inline fun <reified T> get(path: String): T {
        val headers = mutableListOf(
            "GET $path HTTP/1.1",
            "Host: $host",
            "User-Agent: YesWeBurp $VERSION"
        )
        if (token is String) {
            headers.add("Authorization: Bearer $token")
        }
        val request = helpers.buildHttpMessage(headers, byteArrayOf())
        val response = sendRequest(request)
        return jsonMapper.readValue(response)
    }
    private inline fun <reified TForm, reified TResp> post(path: String, form: TForm): TResp {
        val body = jsonMapper.writeValueAsBytes(form)
        val headers = mutableListOf(
            "POST $path HTTP/1.1",
            "Host: $host",
            "Content-Type: application/json",
            "User-Agent: YesWeBurp $VERSION"
        )
        if (token is String) {
            headers.add("Authorization: Bearer $token")

        }
        val request = helpers.buildHttpMessage(headers, body)
        val response = sendRequest(request)
        return jsonMapper.readValue(response)
    }

    fun auth() {
        token = null
    }

    fun auth(email: String, password: String) {
        token = null
        val response: LoginResponse = post("/login", Login(email, password))
        if (response.totp_token is String) {
            throw APIException("OTP Required")
        }
        token = response.token
    }

    fun auth(email: String, password: String, otp: String) {
        token = null
        val otpResponse: LoginResponseTOTP = post("/login", Login(email, password))
        val response: LoginResponse = post("/account/totp", LoginOTP(otpResponse.totp_token, otp))

        token = response.token
    }

    fun fetchPrograms() {
        GlobalScope.launch {
            val data = mutableListOf<Program>()
            var page = 1
            do {
                val response: Page<ShortProgram> = get("/programs?page=$page")
                response.items.stream().parallel().forEach { data.add(get("/programs/${it.slug}")) }
            } while (page++ < response.pagination.nb_pages)
            val programs = data.sortedBy(Program::title)
            programsLoaded.fire(programs)
        }
    }
}
