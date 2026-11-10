package com.proxydroid

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.net.IDN
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.json.JSONObject


data class ProxySettings(
    val host: String = "127.0.0.1",
    val port: String = "1080",
    val username: String = "",
    val password: String = "",
    val upstreamProxy: String = "",
    val upstreamUsername: String = "",
    val upstreamPassword: String = "",
    val printCert: Boolean = false,
    val dnsHost: String = "127.0.0.1",
    val dnsPort: String = "1053",
    val dnsUpstream: String = "1.1.1.1:53",
    val fakeIpRange: String = "198.18.0.0/15",
    val udpOverTcp: Boolean = false,
    val tcpMicroSegmentation: Boolean = false,
    val tcpSegmentSize: String = "512",
    val fragmentTlsClientHello: Boolean = false,
    val tlsFragmentSize: String = "128",
    val tcpFastOpen: Boolean = false,
    val sniOverrideEnabled: Boolean = false,
    val sniOverride: String = "",
) {
    fun validationError(): String? {
        if (host.isBlank() || host.any(Char::isWhitespace)) {
            return "Укажите адрес прослушивания без пробелов."
        }
        val proxyPort = port.toIntOrNull()
        if (proxyPort == null || proxyPort !in 1..65535) {
            return "Порт прокси должен быть числом от 1 до 65535."
        }
        if (username.isBlank() != password.isBlank()) {
            return "Логин и пароль SOCKS5 нужно заполнить вместе."
        }
        if (username.toByteArray(StandardCharsets.UTF_8).size > 255 ||
            password.toByteArray(StandardCharsets.UTF_8).size > 255) {
            return "Логин и пароль SOCKS5 должны быть не длиннее 255 байт."
        }
        if (upstreamUsername.isBlank() != upstreamPassword.isBlank()) {
            return "Логин и пароль внешнего SOCKS5 нужно заполнить вместе."
        }
        if (upstreamUsername.toByteArray(StandardCharsets.UTF_8).size > 255 ||
            upstreamPassword.toByteArray(StandardCharsets.UTF_8).size > 255) {
            return "Логин и пароль внешнего SOCKS5 должны быть не длиннее 255 байт."
        }
        if (upstreamProxy.isNotBlank() && !validProxyAddress(upstreamProxy)) {
            return "Внешний SOCKS5 задаётся как socks5://host:port или host:port; логин и пароль введите отдельно."
        }
        if (dnsHost.isBlank() || dnsHost.any(Char::isWhitespace)) {
            return "Укажите адрес DNS-интерфейса без пробелов."
        }
        val dnsPortNumber = dnsPort.toIntOrNull()
        if (dnsPortNumber == null || dnsPortNumber !in 1..65535) {
            return "DNS-порт должен быть числом от 1 до 65535."
        }
        if (!validHostPort(dnsUpstream)) {
            return "DNS-upstream должен быть адресом вида 1.1.1.1:53 или [IPv6]:53."
        }
        if (!fakeIpRange.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}"))) {
            return "Fake-IP диапазон должен быть IPv4-сетью, например 198.18.0.0/15."
        }
        if (tcpMicroSegmentation) {
            val mss = tcpSegmentSize.toIntOrNull()
            if (mss == null || mss !in 256..1460) {
                return "Размер TCP-сегмента должен быть числом от 256 до 1460 байт."
            }
        }
        if (fragmentTlsClientHello) {
            val fragmentSize = tlsFragmentSize.toIntOrNull()
            if (fragmentSize == null || fragmentSize !in 64..1024) {
                return "Размер фрагмента ClientHello должен быть числом от 64 до 1024 байт."
            }
        }
        if (sniOverrideEnabled) {
            val asciiName = runCatching {
                IDN.toASCII(sniOverride.trim(), IDN.USE_STD3_ASCII_RULES).lowercase()
            }.getOrNull()
            val validLabels = asciiName?.split('.')?.all { label ->
                label.length in 1..63 &&
                    label.first().isLetterOrDigit() && label.last().isLetterOrDigit() &&
                    label.all { it.isLetterOrDigit() || it == '-' }
            } == true
            if (asciiName.isNullOrBlank() || asciiName.length > 253 || !validLabels ||
                asciiName.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}"))) {
                return "Укажите SNI как DNS-имя без схемы, порта и IP-адреса, например www.example.com."
            }
        }
        return null
    }

    fun hasNoAuthentication(): Boolean = username.isBlank() && password.isBlank()

    fun isExposedWithoutAuthentication(): Boolean {
        val normalized = host.lowercase().removeSurrounding("[", "]")
        return normalized !in setOf("127.0.0.1", "::1", "localhost") && hasNoAuthentication()
    }

    fun toPythonMap(): Map<String, Any> = mapOf(
        "host" to host.trim(),
        "port" to (port.toIntOrNull() ?: 1080),
        "username" to username,
        "password" to password,
        "upstreamProxy" to upstreamProxy.trim(),
        "upstreamUsername" to upstreamUsername,
        "upstreamPassword" to upstreamPassword,
        "printCert" to printCert,
        "dnsHost" to dnsHost.trim(),
        "dnsPort" to (dnsPort.toIntOrNull() ?: 1053),
        "dnsUpstream" to dnsUpstream.trim(),
        "fakeIpRange" to fakeIpRange.trim(),
        "udpOverTcp" to udpOverTcp,
        "tcpMaxSegmentSize" to if (tcpMicroSegmentation) {
            tcpSegmentSize.toIntOrNull() ?: 512
        } else {
            0
        },
        "tcpFastOpen" to tcpFastOpen,
        "fragmentClientHello" to fragmentTlsClientHello,
        "tlsFragmentSize" to (tlsFragmentSize.toIntOrNull() ?: 128),
        "sniOverride" to if (sniOverrideEnabled) sniOverride.trim() else "",
    )

    private fun validProxyAddress(value: String): Boolean {
        val input = value.trim()
        if (input.any(Char::isWhitespace)) return false
        val withScheme = if (input.contains("://")) input else "socks5://$input"
        val uri = runCatching { URI(withScheme) }.getOrNull() ?: return false
        val scheme = uri.scheme?.lowercase()
        return scheme in setOf("socks", "socks5", "socks5h") &&
            uri.rawUserInfo == null && uri.rawPath.isNullOrEmpty() &&
            uri.rawQuery == null && uri.rawFragment == null &&
            !uri.host.isNullOrBlank() && (uri.port == -1 || uri.port in 1..65535)
    }

    private fun validHostPort(value: String): Boolean {
        val input = value.trim()
        if (input.isEmpty() || input.any(Char::isWhitespace)) return false
        val host: String
        val portPart: String?
        if (input.startsWith("[")) {
            val end = input.indexOf(']')
            if (end <= 1) return false
            host = input.substring(1, end)
            val suffix = input.substring(end + 1)
            if (suffix.isNotEmpty() && !suffix.startsWith(":")) return false
            portPart = suffix.removePrefix(":").takeIf { it.isNotEmpty() }
        } else if (input.count { it == ':' } == 1) {
            val parts = input.split(':', limit = 2)
            host = parts[0]
            portPart = parts.getOrNull(1)?.takeIf { it.isNotEmpty() }
        } else {
            host = input
            portPart = null
        }
        if (host.isBlank()) return false
        return portPart == null || portPart.toIntOrNull()?.let { it in 1..65535 } == true
    }
}

class ProxySettingsStore(context: Context) {
    private val preferences = context.applicationContext
        .getSharedPreferences("proxy_droid_settings", Context.MODE_PRIVATE)

    fun load(): ProxySettings {
        val encryptedCredentials = preferences.getString(KEY_CREDENTIALS, null)
        val credentials = runCatching {
            encryptedCredentials?.let { encrypted ->
                decrypt(encrypted)?.let { plaintext -> JSONObject(plaintext) }
            }
        }.getOrNull()
        val generatedPassword = UUID.randomUUID().toString().replace("-", "")
        val settings = ProxySettings(
            host = preferences.getString("host", "127.0.0.1") ?: "127.0.0.1",
            port = preferences.getString("port", "1080") ?: "1080",
            username = credentials?.optString("username", "proxydroid") ?: "proxydroid",
            password = credentials?.optString("password", generatedPassword) ?: generatedPassword,
            upstreamProxy = preferences.getString("upstreamProxy", "") ?: "",
            upstreamUsername = credentials?.optString("upstreamUsername", "") ?: "",
            upstreamPassword = credentials?.optString("upstreamPassword", "") ?: "",
            printCert = preferences.getBoolean("printCert", false),
            dnsHost = preferences.getString("dnsHost", "127.0.0.1") ?: "127.0.0.1",
            dnsPort = preferences.getString("dnsPort", "1053") ?: "1053",
            dnsUpstream = preferences.getString("dnsUpstream", "1.1.1.1:53")
                ?: "1.1.1.1:53",
            fakeIpRange = preferences.getString("fakeIpRange", "198.18.0.0/15")
                ?: "198.18.0.0/15",
            udpOverTcp = preferences.getBoolean("udpOverTcp", false),
            tcpMicroSegmentation = preferences.getBoolean("tcpMicroSegmentation", false),
            tcpSegmentSize = preferences.getString("tcpSegmentSize", "512") ?: "512",
            fragmentTlsClientHello = preferences.getBoolean("fragmentTlsClientHello", false),
            tlsFragmentSize = preferences.getString("tlsFragmentSize", "128") ?: "128",
            tcpFastOpen = preferences.getBoolean("tcpFastOpen", false),
            sniOverrideEnabled = preferences.getBoolean("sniOverrideEnabled", false),
            sniOverride = preferences.getString("sniOverride", "") ?: "",
        )
        // Persist generated credentials immediately. Otherwise the first-run UI could
        // claim settings are saved while each load silently creates a new password.
        if (credentials == null || !credentials.has("username") || !credentials.has("password")) {
            save(settings)
        }
        return settings
    }

    fun save(settings: ProxySettings) {
        val credentials = JSONObject()
            .put("username", settings.username)
            .put("password", settings.password)
            .put("upstreamUsername", settings.upstreamUsername)
            .put("upstreamPassword", settings.upstreamPassword)
            .toString()
        preferences.edit()
            .putString("host", settings.host.trim())
            .putString("port", settings.port.trim())
            .putString("upstreamProxy", settings.upstreamProxy.trim())
            .putString(KEY_CREDENTIALS, encrypt(credentials))
            .putBoolean("printCert", settings.printCert)
            .putString("dnsHost", settings.dnsHost.trim())
            .putString("dnsPort", settings.dnsPort.trim())
            .putString("dnsUpstream", settings.dnsUpstream.trim())
            .putString("fakeIpRange", settings.fakeIpRange.trim())
            .putBoolean("udpOverTcp", settings.udpOverTcp)
            .putBoolean("tcpMicroSegmentation", settings.tcpMicroSegmentation)
            .putString("tcpSegmentSize", settings.tcpSegmentSize.trim())
            .putBoolean("fragmentTlsClientHello", settings.fragmentTlsClientHello)
            .putString("tlsFragmentSize", settings.tlsFragmentSize.trim())
            .putBoolean("tcpFastOpen", settings.tcpFastOpen)
            .putBoolean("sniOverrideEnabled", settings.sniOverrideEnabled)
            .putString("sniOverride", settings.sniOverride.trim())
            .apply()
    }

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val encrypted = cipher.iv + cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }

    private fun decrypt(value: String?): String? {
        if (value.isNullOrBlank()) return null
        return runCatching {
            val bytes = Base64.decode(value, Base64.NO_WRAP)
            require(bytes.size > GCM_IV_SIZE)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                key(),
                javax.crypto.spec.GCMParameterSpec(128, bytes.copyOfRange(0, GCM_IV_SIZE)),
            )
            String(cipher.doFinal(bytes.copyOfRange(GCM_IV_SIZE, bytes.size)), StandardCharsets.UTF_8)
        }.getOrNull()
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generateKey()
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "proxydroid.credentials.v1"
        const val KEY_CREDENTIALS = "credentials.v1"
        const val GCM_IV_SIZE = 12
    }
}
