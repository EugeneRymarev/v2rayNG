package com.v2ray.ang.handler

import com.v2ray.ang.util.WireGuardBase64
import com.v2ray.ang.util.WireGuardHandshake
import com.v2ray.ang.util.X25519
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread
import kotlin.random.Random

class WarpEndpointScannerTest {

    @Test
    fun warpAddresses() {
        assertTrue(WarpEndpointScanner.isWarpAddress("162.159.192.1"))
        assertTrue(WarpEndpointScanner.isWarpAddress("188.114.99.254"))
        assertFalse(WarpEndpointScanner.isWarpAddress("162.159.193.1"))
        assertFalse(WarpEndpointScanner.isWarpAddress("162.159.192"))
        assertFalse(WarpEndpointScanner.isWarpAddress("162.159.192.300"))
        assertFalse(WarpEndpointScanner.isWarpAddress("engage.cloudflareclient.com"))
        assertFalse(WarpEndpointScanner.isWarpAddress(null))
    }

    @Test
    fun candidates() {
        val candidates = WarpEndpointScanner.buildCandidates(100, Random(42))
        assertEquals(100, candidates.size)
        assertEquals(candidates.size, candidates.toSet().size)
        assertEquals(
            WarpEndpointScanner.PREFERRED_PORTS.map { WarpManager.DEFAULT_ENDPOINT_HOST to it },
            candidates.take(WarpEndpointScanner.PREFERRED_PORTS.size)
        )
        val ranges = candidates.drop(WarpEndpointScanner.PREFERRED_PORTS.size)
            .take(WarpEndpointScanner.PREFIXES_24.size)
            .map { it.first.substringBeforeLast('.') }
        assertEquals(WarpEndpointScanner.PREFIXES_24, ranges)
        candidates.forEach { (host, port) ->
            assertTrue(WarpEndpointScanner.isWarpAddress(host), host)
            assertTrue(port in WarpEndpointScanner.PORTS, port.toString())
        }
    }

    @Test
    fun candidateCount() {
        assertEquals(3, WarpEndpointScanner.buildCandidates(3).size)
        assertTrue(WarpEndpointScanner.buildCandidates(0).isEmpty())
    }

    @Test
    fun probeAnswered() {
        val serverPrivate = X25519.generatePrivateKey()
        val keys = WireGuardHandshake.StaticKeys.fromBase64(
            WireGuardBase64.encode(X25519.generatePrivateKey()),
            WireGuardBase64.encode(X25519.publicKey(serverPrivate)),
        )
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { server ->
            val responder = thread {
                val buffer = ByteArray(256)
                val request = DatagramPacket(buffer, buffer.size)
                server.receive(request)
                // garbage first, then the real response
                server.send(DatagramPacket(ByteArray(10), 10, request.socketAddress))
                val answer = ByteArray(92)
                answer[0] = WireGuardHandshake.TYPE_RESPONSE
                System.arraycopy(buffer, 4, answer, 8, 4)
                server.send(DatagramPacket(answer, answer.size, request.socketAddress))
            }
            val rtt = WarpEndpointScanner.probe(keys, "127.0.0.1", server.localPort, 2000)
            responder.join()
            assertNotNull(rtt)
            assertTrue(rtt!! >= 1)
        }
    }

    @Test
    fun probeNoAnswer() {
        val keys = WireGuardHandshake.StaticKeys(X25519.generatePrivateKey(), X25519.publicKey(X25519.generatePrivateKey()))
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { silent ->
            assertNull(WarpEndpointScanner.probe(keys, "127.0.0.1", silent.localPort, 300))
        }
    }
}
