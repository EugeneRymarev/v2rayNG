package com.v2ray.ang.util

import java.math.BigInteger

/** ChaCha20-Poly1305 (RFC 8439). The platform cipher needs API 28. */
object ChaCha20Poly1305 {
    const val KEY_SIZE = 32
    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16

    private val P1305: BigInteger = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5))
    private val MASK128: BigInteger = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)
    private val CLAMP_R = BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16)

    /** Returns ciphertext + 16-byte tag. */
    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "ChaCha20 key must be 32 bytes" }
        require(nonce.size == NONCE_SIZE) { "ChaCha20 nonce must be 12 bytes" }

        val polyKey = chacha20Block(key, 0, nonce).copyOf(32)
        val ciphertext = chacha20Xor(key, 1, nonce, plaintext)

        val macData = Blake2s.concat(
            associatedData, ByteArray(pad16(associatedData.size)),
            ciphertext, ByteArray(pad16(ciphertext.size)),
            longLe(associatedData.size.toLong()), longLe(ciphertext.size.toLong())
        )
        return Blake2s.concat(ciphertext, poly1305(polyKey, macData))
    }

    fun chacha20Block(key: ByteArray, counter: Int, nonce: ByteArray): ByteArray {
        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for (i in 0 until 8) state[4 + i] = intLe(key, i * 4)
        state[12] = counter
        for (i in 0 until 3) state[13 + i] = intLe(nonce, i * 4)

        val x = state.copyOf()
        repeat(10) {
            quarterRound(x, 0, 4, 8, 12)
            quarterRound(x, 1, 5, 9, 13)
            quarterRound(x, 2, 6, 10, 14)
            quarterRound(x, 3, 7, 11, 15)
            quarterRound(x, 0, 5, 10, 15)
            quarterRound(x, 1, 6, 11, 12)
            quarterRound(x, 2, 7, 8, 13)
            quarterRound(x, 3, 4, 9, 14)
        }
        val out = ByteArray(64)
        for (i in 0 until 16) {
            val v = x[i] + state[i]
            out[i * 4] = v.toByte()
            out[i * 4 + 1] = (v ushr 8).toByte()
            out[i * 4 + 2] = (v ushr 16).toByte()
            out[i * 4 + 3] = (v ushr 24).toByte()
        }
        return out
    }

    fun poly1305(oneTimeKey: ByteArray, message: ByteArray): ByteArray {
        val r = leToBig(oneTimeKey, 0, 16).and(CLAMP_R)
        val s = leToBig(oneTimeKey, 16, 16)
        var acc = BigInteger.ZERO
        var offset = 0
        while (offset < message.size) {
            val length = minOf(16, message.size - offset)
            val block = message.copyOfRange(offset, offset + length) + byteArrayOf(1)
            acc = acc.add(leToBig(block, 0, block.size)).multiply(r).mod(P1305)
            offset += length
        }
        val tag = acc.add(s).and(MASK128)
        val out = ByteArray(TAG_SIZE)
        val bigEndian = tag.toByteArray()
        for (i in 0 until minOf(TAG_SIZE, bigEndian.size)) {
            out[i] = bigEndian[bigEndian.size - 1 - i]
        }
        return out
    }

    private fun chacha20Xor(key: ByteArray, initialCounter: Int, nonce: ByteArray, input: ByteArray): ByteArray {
        val out = ByteArray(input.size)
        var counter = initialCounter
        var offset = 0
        while (offset < input.size) {
            val keyStream = chacha20Block(key, counter++, nonce)
            val length = minOf(64, input.size - offset)
            for (i in 0 until length) {
                out[offset + i] = (input[offset + i].toInt() xor keyStream[i].toInt()).toByte()
            }
            offset += length
        }
        return out
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] xor x[a], 16)
        x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] xor x[c], 12)
        x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] xor x[a], 8)
        x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] xor x[c], 7)
    }

    private fun pad16(length: Int): Int = (16 - length % 16) % 16

    private fun intLe(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)

    private fun longLe(value: Long): ByteArray = ByteArray(8) { (value ushr (8 * it)).toByte() }

    private fun leToBig(bytes: ByteArray, offset: Int, length: Int): BigInteger =
        BigInteger(1, bytes.copyOfRange(offset, offset + length).reversedArray())
}
