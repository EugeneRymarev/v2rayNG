package com.v2ray.ang.util

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WarpCryptoTest {

    private fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    @Test
    fun x25519Rfc7748() {
        val scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        val u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        assertEquals(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            X25519.scalarMult(scalar, u).toHex()
        )
    }

    @Test
    fun x25519Rfc7748Dh() {
        val alicePrivate = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bobPrivate = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val alicePublic = X25519.publicKey(alicePrivate)
        val bobPublic = X25519.publicKey(bobPrivate)
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", alicePublic.toHex())
        assertEquals("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bobPublic.toHex())
        val shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        assertEquals(shared, X25519.scalarMult(alicePrivate, bobPublic).toHex())
        assertEquals(shared, X25519.scalarMult(bobPrivate, alicePublic).toHex())
    }

    @Test
    fun privateKeyClamped() {
        val key = X25519.generatePrivateKey()
        assertEquals(32, key.size)
        assertEquals(0, key[0].toInt() and 7)
        assertEquals(64, key[31].toInt() and 0xc0)
    }

    @Test
    fun blake2s() {
        assertEquals(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            Blake2s.hash("abc".toByteArray()).toHex()
        )
        assertEquals(
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
            Blake2s.hash(ByteArray(0)).toHex()
        )
        // BLAKE2 reference vectors, key 00..1f
        val key = ByteArray(32) { it.toByte() }
        assertEquals(
            "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
            Blake2s.digest(ByteArray(0), 32, key).toHex()
        )
        assertEquals(
            "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4",
            Blake2s.digest(ByteArray(64) { it.toByte() }, 32, key).toHex()
        )
    }

    @Test
    fun chaCha20Poly1305Rfc8439() {
        val plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, " +
            "sunscreen would be it.").toByteArray()
        val aad = hex("50515253c0c1c2c3c4c5c6c7")
        val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = hex("070000004041424344454647")
        val sealed = ChaCha20Poly1305.seal(key, nonce, plaintext, aad)
        assertEquals(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b" +
                "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b6116",
            sealed.copyOfRange(0, plaintext.size).toHex()
        )
        assertEquals("1ae10b594f09e26a7e902ecbd0600691", sealed.copyOfRange(plaintext.size, sealed.size).toHex())
    }

    @Test
    fun base64() {
        for (size in 0..40) {
            val data = ByteArray(size) { (it * 37 + 11).toByte() }
            val encoded = WireGuardBase64.encode(data)
            assertEquals(java.util.Base64.getEncoder().encodeToString(data), encoded)
            assertArrayEquals(data, WireGuardBase64.decode(encoded))
        }
        assertArrayEquals(byteArrayOf(-5, -1), WireGuardBase64.decode("-_8"))
        assertThrows(IllegalArgumentException::class.java) { WireGuardBase64.decode("ab*c") }
    }

    @Test
    fun tai64n() {
        assertEquals("400000000000000a00000000", WireGuardHandshake.tai64n(0).toHex())
        assertEquals("400000000000000b1dcd6500", WireGuardHandshake.tai64n(1500).toHex())
    }

    @Test
    fun handshakeInitiation() {
        val initiatorPrivate = X25519.clamp(ByteArray(32) { (it + 1).toByte() })
        val responderPrivate = X25519.clamp(ByteArray(32) { (it + 101).toByte() })
        val responderPublic = X25519.publicKey(responderPrivate)
        val ephemeralPrivate = X25519.clamp(ByteArray(32) { (it + 201).toByte() })
        val keys = WireGuardHandshake.StaticKeys(initiatorPrivate, responderPublic)

        val msg = WireGuardHandshake.createInitiation(keys, 0x01020304, 1_700_000_000_000L, ephemeralPrivate)
        assertEquals(WireGuardHandshake.INITIATION_LENGTH, msg.size)
        assertEquals(1, msg[0].toInt())
        assertEquals(listOf(0, 0, 0), listOf(msg[1], msg[2], msg[3]).map { it.toInt() })
        assertEquals("04030201", msg.copyOfRange(4, 8).toHex())
        assertArrayEquals(X25519.publicKey(ephemeralPrivate), msg.copyOfRange(8, 40))

        // responder side
        val construction = Blake2s.hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray())
        var h = Blake2s.hash(Blake2s.hash(construction, "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray()), responderPublic)
        val ephemeralPublic = msg.copyOfRange(8, 40)
        var c = Blake2s.hmac(Blake2s.hmac(construction, ephemeralPublic), byteArrayOf(1))
        h = Blake2s.hash(h, ephemeralPublic)
        val t0 = Blake2s.hmac(c, X25519.scalarMult(responderPrivate, ephemeralPublic))
        c = Blake2s.hmac(t0, byteArrayOf(1))
        val k1 = Blake2s.hmac(t0, Blake2s.concat(c, byteArrayOf(2)))
        val expectedStatic = ChaCha20Poly1305.seal(k1, ByteArray(12), X25519.publicKey(initiatorPrivate), h)
        assertArrayEquals(expectedStatic, msg.copyOfRange(40, 88))

        h = Blake2s.hash(h, expectedStatic)
        val t0b = Blake2s.hmac(c, X25519.scalarMult(responderPrivate, X25519.publicKey(initiatorPrivate)))
        val k2 = Blake2s.hmac(t0b, Blake2s.concat(Blake2s.hmac(t0b, byteArrayOf(1)), byteArrayOf(2)))
        val expectedTimestamp = ChaCha20Poly1305.seal(k2, ByteArray(12), WireGuardHandshake.tai64n(1_700_000_000_000L), h)
        assertArrayEquals(expectedTimestamp, msg.copyOfRange(88, 116))

        val mac1Key = Blake2s.hash("mac1----".toByteArray(), responderPublic)
        assertArrayEquals(Blake2s.digest(msg.copyOfRange(0, 116), 16, mac1Key), msg.copyOfRange(116, 132))
        assertTrue(msg.copyOfRange(132, 148).all { it.toInt() == 0 })
    }

    @Test
    fun answerDetection() {
        val index = 0x0a0b0c0d
        val response = ByteArray(92).also {
            it[0] = 2
            it[8] = 0x0d; it[9] = 0x0c; it[10] = 0x0b; it[11] = 0x0a
        }
        assertTrue(WireGuardHandshake.isAnswerTo(response, 92, index))
        assertFalse(WireGuardHandshake.isAnswerTo(response, 91, index))
        assertFalse(WireGuardHandshake.isAnswerTo(response, 92, index + 1))

        val cookie = ByteArray(64).also {
            it[0] = 3
            it[4] = 0x0d; it[5] = 0x0c; it[6] = 0x0b; it[7] = 0x0a
        }
        assertTrue(WireGuardHandshake.isAnswerTo(cookie, 64, index))
        assertFalse(WireGuardHandshake.isAnswerTo(ByteArray(148).also { it[0] = 1 }, 148, 0))
        assertFalse(WireGuardHandshake.isAnswerTo(ByteArray(4), 4, 0))
    }
}
