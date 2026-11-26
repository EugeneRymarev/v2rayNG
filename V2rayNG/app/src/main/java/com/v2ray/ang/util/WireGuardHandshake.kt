package com.v2ray.ang.util

import java.security.SecureRandom

/** WireGuard handshake initiation, see https://www.wireguard.com/protocol/ */
object WireGuardHandshake {
    const val INITIATION_LENGTH = 148
    const val TYPE_INITIATION: Byte = 1
    const val TYPE_RESPONSE: Byte = 2
    const val TYPE_COOKIE_REPLY: Byte = 3

    private val CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray(Charsets.US_ASCII)
    private val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray(Charsets.US_ASCII)
    private val LABEL_MAC1 = "mac1----".toByteArray(Charsets.US_ASCII)

    // TAI64: 2^62 + 10
    private const val TAI64_EPOCH = 0x400000000000000AL

    // static DH is computed once per account
    class StaticKeys(staticPrivate: ByteArray, val peerPublic: ByteArray) {
        val staticPublic: ByteArray = X25519.publicKey(staticPrivate)
        val staticShared: ByteArray = X25519.scalarMult(staticPrivate, peerPublic)
        val mac1Key: ByteArray = Blake2s.hash(LABEL_MAC1, peerPublic)
        val initialChainKey: ByteArray = Blake2s.hash(CONSTRUCTION)
        val initialHash: ByteArray = Blake2s.hash(Blake2s.hash(initialChainKey, IDENTIFIER), peerPublic)

        companion object {
            fun fromBase64(privateKey: String, peerPublicKey: String): StaticKeys {
                val priv = WireGuardBase64.decode(privateKey)
                val peer = WireGuardBase64.decode(peerPublicKey)
                require(priv.size == X25519.KEY_SIZE && peer.size == X25519.KEY_SIZE) { "WireGuard keys must be 32 bytes" }
                return StaticKeys(priv, peer)
            }
        }
    }

    fun createInitiation(
        keys: StaticKeys,
        senderIndex: Int,
        nowMillis: Long,
        ephemeralPrivate: ByteArray = X25519.generatePrivateKey(SecureRandom()),
    ): ByteArray {
        val ephemeralPublic = X25519.publicKey(ephemeralPrivate)

        var c = keys.initialChainKey
        var h = keys.initialHash

        c = kdf1(c, ephemeralPublic)
        h = Blake2s.hash(h, ephemeralPublic)

        val (c1, k1) = kdf2(c, X25519.scalarMult(ephemeralPrivate, keys.peerPublic))
        c = c1
        val encryptedStatic = seal(k1, keys.staticPublic, h)
        h = Blake2s.hash(h, encryptedStatic)

        val (_, k2) = kdf2(c, keys.staticShared)
        val encryptedTimestamp = seal(k2, tai64n(nowMillis), h)

        val msg = ByteArray(INITIATION_LENGTH)
        msg[0] = TYPE_INITIATION
        writeIntLe(msg, 4, senderIndex)
        System.arraycopy(ephemeralPublic, 0, msg, 8, 32)
        System.arraycopy(encryptedStatic, 0, msg, 40, encryptedStatic.size)
        System.arraycopy(encryptedTimestamp, 0, msg, 88, encryptedTimestamp.size)
        val mac1 = Blake2s.digest(msg.copyOfRange(0, 116), 16, keys.mac1Key)
        System.arraycopy(mac1, 0, msg, 116, 16)
        // mac2 stays zero, it is needed only after a cookie
        return msg
    }

    // handshake response or cookie reply
    fun isAnswerTo(packet: ByteArray, length: Int, senderIndex: Int): Boolean {
        if (length < 8) return false
        val receiverOffset = when {
            packet[0] == TYPE_RESPONSE && length >= 92 -> 8
            packet[0] == TYPE_COOKIE_REPLY && length >= 64 -> 4
            else -> return false
        }
        return readIntLe(packet, receiverOffset) == senderIndex
    }

    fun tai64n(nowMillis: Long): ByteArray {
        val seconds = Math.floorDiv(nowMillis, 1000L)
        val nanos = (Math.floorMod(nowMillis, 1000L) * 1_000_000L).toInt()
        val out = ByteArray(12)
        val label = TAI64_EPOCH + seconds
        for (i in 0 until 8) out[i] = (label ushr (56 - 8 * i)).toByte()
        for (i in 0 until 4) out[8 + i] = (nanos ushr (24 - 8 * i)).toByte()
        return out
    }

    private fun kdf1(key: ByteArray, input: ByteArray): ByteArray {
        val t0 = Blake2s.hmac(key, input)
        return Blake2s.hmac(t0, byteArrayOf(1))
    }

    private fun kdf2(key: ByteArray, input: ByteArray): Pair<ByteArray, ByteArray> {
        val t0 = Blake2s.hmac(key, input)
        val t1 = Blake2s.hmac(t0, byteArrayOf(1))
        val t2 = Blake2s.hmac(t0, Blake2s.concat(t1, byteArrayOf(2)))
        return t1 to t2
    }

    private fun seal(key: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray =
        ChaCha20Poly1305.seal(key, ByteArray(ChaCha20Poly1305.NONCE_SIZE), plaintext, associatedData)

    private fun writeIntLe(buf: ByteArray, offset: Int, value: Int) {
        for (i in 0 until 4) buf[offset + i] = (value ushr (8 * i)).toByte()
    }

    private fun readIntLe(buf: ByteArray, offset: Int): Int =
        (buf[offset].toInt() and 0xff) or
            ((buf[offset + 1].toInt() and 0xff) shl 8) or
            ((buf[offset + 2].toInt() and 0xff) shl 16) or
            ((buf[offset + 3].toInt() and 0xff) shl 24)
}

// java.util.Base64 needs API 26, android.util.Base64 does not work in unit tests
object WireGuardBase64 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun encode(data: ByteArray): String {
        val sb = StringBuilder((data.size + 2) / 3 * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xff
            val b1 = if (i + 1 < data.size) data[i + 1].toInt() and 0xff else 0
            val b2 = if (i + 2 < data.size) data[i + 2].toInt() and 0xff else 0
            sb.append(ALPHABET[b0 ushr 2])
            sb.append(ALPHABET[((b0 and 3) shl 4) or (b1 ushr 4)])
            sb.append(if (i + 1 < data.size) ALPHABET[((b1 and 15) shl 2) or (b2 ushr 6)] else '=')
            sb.append(if (i + 2 < data.size) ALPHABET[b2 and 63] else '=')
            i += 3
        }
        return sb.toString()
    }

    // standard or URL-safe, padding optional
    fun decode(text: String): ByteArray {
        val clean = text.trim().trimEnd('=').replace('-', '+').replace('_', '/')
        require(clean.length % 4 != 1) { "Invalid Base64 length" }
        val out = java.io.ByteArrayOutputStream(clean.length * 3 / 4)
        var buffer = 0
        var bits = 0
        for (ch in clean) {
            val value = ALPHABET.indexOf(ch)
            require(value >= 0) { "Invalid Base64 character" }
            buffer = (buffer shl 6) or value
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((buffer ushr bits) and 0xff)
            }
        }
        return out.toByteArray()
    }
}
