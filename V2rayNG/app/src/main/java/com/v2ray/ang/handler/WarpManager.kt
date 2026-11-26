package com.v2ray.ang.handler

import com.google.gson.Gson
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.UrlContentRequest
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.util.HttpUtil
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.WireGuardBase64
import com.v2ray.ang.util.X25519
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

data class WarpAccount(
    val privateKey: String,
    val peerPublicKey: String,
    val addressV4: String?,
    val addressV6: String?,
    val reserved: String?,
    val endpointHost: String = WarpManager.DEFAULT_ENDPOINT_HOST,
    val endpointPort: Int = WarpManager.DEFAULT_ENDPOINT_PORT,
)

enum class WarpMode(val value: String) {
    OFF("0"),
    IPV6_SERVERS("1"),
    ALL("2");

    companion object {
        fun fromValue(value: String?): WarpMode = entries.firstOrNull { it.value == value } ?: OFF
    }
}

object WarpManager {
    // same API as wgcf / warp-plus
    const val REGISTRATION_URL = "https://api.cloudflareclient.com/v0a2158/reg"
    const val CLIENT_VERSION = "a-6.10-2158"
    const val USER_AGENT = "okhttp/3.12.1"

    const val DEFAULT_ENDPOINT_HOST = "162.159.192.1"
    const val DEFAULT_ENDPOINT_PORT = 2408
    const val DEFAULT_MTU = 1280
    const val DEFAULT_DNS = "1.1.1.1,2606:4700:4700::1111"
    const val DEFAULT_REMARKS = "Cloudflare WARP"

    private const val REGISTRATION_TIMEOUT_MS = 20000

    val registrationHeaders = mapOf(
        "User-Agent" to USER_AGENT,
        "CF-Client-Version" to CLIENT_VERSION,
    )

    fun getAccount(): WarpAccount? =
        accountFromJson(MmkvManager.decodeSettingsString(AppConfig.PREF_WARP_ACCOUNT))

    fun getMode(): WarpMode = WarpMode.fromValue(MmkvManager.decodeSettingsString(AppConfig.PREF_WARP_MODE))

    fun setMode(mode: WarpMode) {
        MmkvManager.encodeSettings(AppConfig.PREF_WARP_MODE, mode.value)
    }

    fun isEnabled(): Boolean = getMode() != WarpMode.OFF && getAccount() != null

    /** Without its own IPv6 the device can reach IPv6 only through WARP. */
    fun shouldRouteIpv6(): Boolean = isEnabled() && !hasGlobalIpv6()

    private fun saveAccount(account: WarpAccount) {
        check(MmkvManager.encodeSettings(AppConfig.PREF_WARP_ACCOUNT, accountToJson(account))) {
            "Failed to save the WARP account"
        }
    }

    /** Registers a new device and replaces the stored account. Null when registration failed. */
    suspend fun createAccount(): WarpAccount? = withContext(Dispatchers.IO) {
        val registered = register() ?: return@withContext null
        val best = bestEndpoint(registered, WarpEndpointScanner.CANDIDATES_AFTER_REGISTRATION)
        val account = best?.let { registered.copy(endpointHost = it.host, endpointPort = it.port) } ?: registered
        saveAccount(account)
        account
    }

    /** Null when there is no account or no address answered. */
    suspend fun findWorkingEndpoint(): WarpAccount? = withContext(Dispatchers.IO) {
        val current = getAccount() ?: return@withContext null
        val best = bestEndpoint(current, WarpEndpointScanner.DEFAULT_CANDIDATES) ?: return@withContext null
        current.copy(endpointHost = best.host, endpointPort = best.port).also { saveAccount(it) }
    }

    private suspend fun bestEndpoint(account: WarpAccount, candidates: Int): WarpEndpointResult? =
        try {
            WarpEndpointScanner.scan(account.privateKey, account.peerPublicKey, candidateCount = candidates).firstOrNull()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "WARP endpoint scan failed", e)
            null
        }

    private fun register(): WarpAccount? {
        val privateKeyBytes = X25519.generatePrivateKey()
        val privateKey = WireGuardBase64.encode(privateKeyBytes)
        val publicKey = WireGuardBase64.encode(X25519.publicKey(privateKeyBytes))
        val body = buildRegistrationBody(publicKey, System.currentTimeMillis())

        // the API is blocked in some countries, so retry through the running proxy
        val requests = listOf(
            UrlContentRequest(url = REGISTRATION_URL, timeout = REGISTRATION_TIMEOUT_MS),
            UrlContentRequest(
                url = REGISTRATION_URL,
                timeout = REGISTRATION_TIMEOUT_MS,
                httpPort = SettingsManager.getHttpPort(),
                proxyUsername = SettingsManager.getSocksUsername(),
                proxyPassword = SettingsManager.getSocksPassword(),
            ),
        )
        for (request in requests) {
            val account = parseRegistrationResponse(HttpUtil.postJson(request, body, registrationHeaders), privateKey)
            if (account != null) return account
            LogUtil.w(AppConfig.TAG, "WARP registration failed, proxy=${request.httpPort != 0}")
        }
        return null
    }

    fun buildRegistrationBody(publicKey: String, nowMillis: Long): String {
        val tos = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date(nowMillis))
        return JsonObject().apply {
            addProperty("key", publicKey)
            addProperty("install_id", "")
            addProperty("fcm_token", "")
            addProperty("tos", tos)
            addProperty("model", "PC")
            addProperty("serial_number", "")
            addProperty("locale", "en_US")
        }.toString()
    }

    fun parseRegistrationResponse(json: String?, privateKey: String): WarpAccount? {
        if (json.isNullOrBlank()) return null
        var root = runCatching { JsonParser.parseString(json) }.getOrNull()?.asObjectOrNull() ?: return null
        if (root.get("config") == null) {
            root = root.get("result")?.asObjectOrNull() ?: return null
        }
        val config = root.get("config")?.asObjectOrNull() ?: return null
        val peer = config.get("peers")?.takeIf { it.isJsonArray }?.asJsonArray?.firstOrNull()?.asObjectOrNull()
        val peerPublicKey = peer?.string("public_key") ?: return null
        val addresses = config.get("interface")?.asObjectOrNull()?.get("addresses")?.asObjectOrNull()
        val (host, port) = parseEndpoint(peer.get("endpoint")?.asObjectOrNull()?.string("v4"))

        return WarpAccount(
            privateKey = privateKey,
            peerPublicKey = peerPublicKey,
            addressV4 = addresses?.string("v4"),
            addressV6 = addresses?.string("v6"),
            reserved = clientIdToReserved(config.string("client_id")),
            endpointHost = host,
            endpointPort = port,
        )
    }

    // reserved = first 3 bytes of client_id
    fun clientIdToReserved(clientId: String?): String? {
        if (clientId.isNullOrBlank()) return null
        val bytes = runCatching { WireGuardBase64.decode(clientId) }.getOrNull() ?: return null
        if (bytes.size < 3) return null
        return bytes.take(3).joinToString(",") { (it.toInt() and 0xff).toString() }
    }

    fun accountToJson(account: WarpAccount): String = Gson().toJson(account)

    fun accountFromJson(json: String?): WarpAccount? {
        if (json.isNullOrBlank()) return null
        val account = runCatching { Gson().fromJson(json, WarpAccount::class.java) }.getOrNull() ?: return null
        // Gson ignores Kotlin nullability
        @Suppress("SENSELESS_COMPARISON")
        if (account.privateKey == null || account.peerPublicKey == null || account.endpointHost == null) return null
        if (account.privateKey.isBlank() || account.peerPublicKey.isBlank() || account.endpointPort !in 1..65535) return null
        return account
    }

    fun toProfileItem(account: WarpAccount): ProfileItem {
        val addresses = listOfNotNull(
            account.addressV4?.let { if (it.contains('/')) it else "$it/32" },
            account.addressV6?.let { if (it.contains('/')) it else "$it/128" },
        )
        return ProfileItem.create(EConfigType.WIREGUARD).apply {
            remarks = DEFAULT_REMARKS
            server = account.endpointHost
            serverPort = account.endpointPort.toString()
            secretKey = account.privateKey
            publicKey = account.peerPublicKey
            localAddress = addresses.joinToString(",")
            reserved = account.reserved ?: "0,0,0"
            mtu = DEFAULT_MTU
            remoteDNS = DEFAULT_DNS
        }
    }

    fun hasGlobalIpv6(): Boolean {
        val addresses = runCatching {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
                .filter { it.isUp && !it.isLoopback && !it.name.startsWith("tun") }
                .flatMap { it.inetAddresses.toList() }
        }.getOrElse { return false }
        return addresses.any(::isGlobalIpv6)
    }

    // 2000::/3
    fun isGlobalIpv6(address: InetAddress): Boolean =
        address is Inet6Address && (address.address[0].toInt() and 0xe0) == 0x20

    private fun parseEndpoint(endpoint: String?): Pair<String, Int> {
        // e.g. "162.159.192.1:0", port 0 = any
        if (endpoint.isNullOrBlank()) return DEFAULT_ENDPOINT_HOST to DEFAULT_ENDPOINT_PORT
        val idx = endpoint.lastIndexOf(':')
        val host = if (idx > 0) endpoint.substring(0, idx) else endpoint
        val port = endpoint.substring(idx + 1).toIntOrNull()?.takeIf { idx > 0 && it in 1..65535 }
            ?: DEFAULT_ENDPOINT_PORT
        return (if (WarpEndpointScanner.isIpv4(host)) host else DEFAULT_ENDPOINT_HOST) to port
    }

    private fun JsonElement.asObjectOrNull(): JsonObject? = if (isJsonObject) asJsonObject else null

    private fun JsonObject.string(name: String): String? =
        get(name)?.takeIf { it.isJsonPrimitive }?.asString?.takeIf { it.isNotBlank() }
}
