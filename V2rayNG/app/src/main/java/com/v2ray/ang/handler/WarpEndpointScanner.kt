package com.v2ray.ang.handler

import com.v2ray.ang.util.WireGuardHandshake
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import kotlin.random.Random

data class WarpEndpointResult(val host: String, val port: Int, val rttMs: Int)

// Some networks block 162.159.192.1:2408 but not other WARP addresses/ports.
// Ranges and ports are taken from warp-plus.
object WarpEndpointScanner {
    // IPv4 only
    val PREFIXES_24 = listOf(
        "162.159.192",
        "162.159.195",
        "188.114.96",
        "188.114.97",
        "188.114.98",
        "188.114.99",
    )

    val PORTS = listOf(
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
        987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476,
        3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
    )

    val PREFERRED_PORTS = listOf(2408, 500, 1701, 4500, 878, 894, 2371, 908)

    const val DEFAULT_CANDIDATES = 100
    const val CANDIDATES_AFTER_REGISTRATION = 60
    const val DEFAULT_CONCURRENCY = 20
    const val DEFAULT_TIMEOUT_MS = 1500

    fun isIpv4(host: String?): Boolean {
        val parts = host?.split('.') ?: return false
        return parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all(Char::isDigit) && p.toInt() <= 255 }
    }

    fun isWarpAddress(host: String?): Boolean =
        isIpv4(host) && host!!.substringBeforeLast('.') in PREFIXES_24

    fun buildCandidates(count: Int, random: Random = Random.Default): List<Pair<String, Int>> {
        val result = LinkedHashSet<Pair<String, Int>>()
        fun add(host: String, port: Int) {
            if (result.size < count) result.add(host to port)
        }

        PREFERRED_PORTS.forEach { add(WarpManager.DEFAULT_ENDPOINT_HOST, it) }
        PREFIXES_24.forEach { add("$it.${random.nextInt(1, 255)}", PREFERRED_PORTS[random.nextInt(PREFERRED_PORTS.size)]) }

        var guard = count * 20
        while (result.size < count && guard-- > 0) {
            add("${PREFIXES_24[random.nextInt(PREFIXES_24.size)]}.${random.nextInt(1, 255)}", PORTS[random.nextInt(PORTS.size)])
        }
        return result.toList()
    }

    /** Returns the round-trip time in ms, or null when nothing answered. */
    fun probe(keys: WireGuardHandshake.StaticKeys, host: String, port: Int, timeoutMs: Int): Int? {
        val senderIndex = SecureRandom().nextInt(Int.MAX_VALUE - 1) + 1
        val packet = WireGuardHandshake.createInitiation(keys, senderIndex, System.currentTimeMillis())
        val socket = try {
            DatagramSocket()
        } catch (_: IOException) {
            return null
        }
        try {
            socket.connect(InetSocketAddress(InetAddress.getByName(host), port))
            val started = System.nanoTime()
            val deadline = started + timeoutMs * 1_000_000L
            socket.send(DatagramPacket(packet, packet.size))
            val buffer = ByteArray(256)
            while (true) {
                val remainingMs = ((deadline - System.nanoTime()) / 1_000_000L).toInt()
                if (remainingMs <= 0) return null
                socket.soTimeout = remainingMs
                val answer = DatagramPacket(buffer, buffer.size)
                socket.receive(answer)
                if (WireGuardHandshake.isAnswerTo(answer.data, answer.length, senderIndex)) {
                    return maxOf(1, ((System.nanoTime() - started) / 1_000_000L).toInt())
                }
            }
        } catch (_: SocketTimeoutException) {
            return null
        } catch (_: IOException) {
            return null
        } catch (_: SecurityException) {
            return null
        } finally {
            socket.close()
        }
    }

    /** Fastest first. */
    suspend fun scan(
        privateKey: String,
        peerPublicKey: String,
        candidateCount: Int = DEFAULT_CANDIDATES,
        concurrency: Int = DEFAULT_CONCURRENCY,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
    ): List<WarpEndpointResult> = withContext(Dispatchers.IO) {
        val keys = WireGuardHandshake.StaticKeys.fromBase64(privateKey, peerPublicKey)
        val limiter = Semaphore(concurrency)
        coroutineScope {
            buildCandidates(candidateCount).map { (host, port) ->
                async {
                    limiter.withPermit {
                        currentCoroutineContext().ensureActive()
                        probe(keys, host, port, timeoutMs)?.let { WarpEndpointResult(host, port, it) }
                    }
                }
            }.awaitAll().filterNotNull().sortedBy { it.rttMs }
        }
    }
}
