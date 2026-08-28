// JWTDecoder.kt
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import com.google.gson.JsonParser

class JWTDecoder(private val token: String, private val key: String?) {
    private var header: JsonObject? = null
    private var payload: JsonObject? = null
    private var signature: String? = null
    private var validSignature: Boolean? = null
    private var expired: Boolean? = null

    fun decode() {
        val parts = token.split(".")
        if (parts.size != 3) throw IllegalArgumentException("Invalid JWT format")

        val headerJson = String(Base64.getUrlDecoder().decode(parts[0]))
        header = JsonParser.parseString(headerJson).asJsonObject

        val payloadJson = String(Base64.getUrlDecoder().decode(parts[1]))
        payload = JsonParser.parseString(payloadJson).asJsonObject

        signature = parts[2]

        // Check exp
        if (payload!!.has("exp")) {
            val exp = payload!!.get("exp").asLong
            expired = System.currentTimeMillis() / 1000 > exp
        }

        // Verify signature
        if (key != null && key.isNotEmpty()) {
            validSignature = verifySignature(parts)
        }
    }

    private fun verifySignature(parts: List<String>): Boolean {
        val data = "${parts[0]}.${parts[1]}"
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(key!!.toByteArray(), "HmacSHA256")
        mac.init(secretKey)
        val sigBytes = mac.doFinal(data.toByteArray())
        val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes)
        return sigB64 == parts[2]
    }

    fun toMap(): Map<String, Any?> {
        val map = mutableMapOf<String, Any?>()
        map["header"] = header
        map["payload"] = payload
        map["signature"] = signature
        map["token"] = token
        if (validSignature != null) map["valid_signature"] = validSignature
        if (expired != null) map["expired"] = expired
        return map
    }

    fun print(color: Boolean) {
        val gson = GsonBuilder().setPrettyPrinting().create()
        println("Header:")
        println(gson.toJson(header))
        println("Payload:")
        println(gson.toJson(payload))
        if (expired != null) {
            println("  Token ${if (expired!!) "expired" else "valid"}")
        }
        if (validSignature != null) {
            println("  Signature ${if (validSignature!!) "verified" else "invalid"}")
        }
        println("Signature: $signature")
    }
}

fun main(args: Array<String>) {
    var token: String? = null
    var key: String? = null
    var file: String? = null
    var jsonOut = false
    var color = false

    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--key" -> key = args[++i]
            "--file" -> file = args[++i]
            "--json" -> jsonOut = true
            "--color" -> color = true
            else -> if (token == null) token = args[i]
        }
        i++
    }

    if (file != null) {
        token = File(file).readText().trim()
    }
    if (token == null) {
        // stdin
        if (System.console() == null) {
            token = Scanner(System.`in`).nextLine().trim()
        } else {
            System.err.println("Error: no token provided")
            System.exit(1)
        }
    }

    val decoder = JWTDecoder(token!!, key)
    try {
        decoder.decode()
    } catch (e: Exception) {
        System.err.println("Error: ${e.message}")
        System.exit(1)
    }

    if (jsonOut) {
        val gson = GsonBuilder().setPrettyPrinting().create()
        println(gson.toJson(decoder.toMap()))
    } else {
        decoder.print(color || System.console() != null)
    }
}
