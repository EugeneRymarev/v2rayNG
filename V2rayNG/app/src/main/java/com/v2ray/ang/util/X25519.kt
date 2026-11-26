package com.v2ray.ang.util

import java.math.BigInteger
import java.security.SecureRandom

/** X25519 (RFC 7748). The platform one needs API 33. */
object X25519 {
    const val KEY_SIZE = 32

    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val A24: BigInteger = BigInteger.valueOf(121665)
    private val BASE_POINT = ByteArray(KEY_SIZE).also { it[0] = 9 }

    fun clamp(privateKey: ByteArray): ByteArray {
        require(privateKey.size == KEY_SIZE) { "X25519 key must be 32 bytes" }
        privateKey[0] = (privateKey[0].toInt() and 248).toByte()
        privateKey[31] = ((privateKey[31].toInt() and 127) or 64).toByte()
        return privateKey
    }

    fun generatePrivateKey(random: SecureRandom = SecureRandom()): ByteArray {
        val key = ByteArray(KEY_SIZE)
        random.nextBytes(key)
        return clamp(key)
    }

    fun publicKey(privateKey: ByteArray): ByteArray = scalarMult(privateKey, BASE_POINT)

    fun scalarMult(scalar: ByteArray, uCoordinate: ByteArray): ByteArray {
        require(scalar.size == KEY_SIZE && uCoordinate.size == KEY_SIZE) { "X25519 input must be 32 bytes" }
        val k = decodeLittleEndian(clamp(scalar.copyOf()))
        val uBytes = uCoordinate.copyOf().also { it[31] = (it[31].toInt() and 127).toByte() }
        val x1 = decodeLittleEndian(uBytes).mod(P)

        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val bit = if (k.testBit(t)) 1 else 0
            swap = swap xor bit
            if (swap == 1) {
                x2 = x3.also { x3 = x2 }
                z2 = z3.also { z3 = z2 }
            }
            swap = bit

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)
            x3 = da.add(cb).pow(2).mod(P)
            z3 = x1.multiply(da.subtract(cb).pow(2)).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e))).mod(P)
        }
        if (swap == 1) {
            x2 = x3
            z2 = z3
        }
        val result = x2.multiply(z2.modPow(P.subtract(BigInteger.valueOf(2)), P)).mod(P)
        return encodeLittleEndian(result)
    }

    private fun decodeLittleEndian(bytes: ByteArray): BigInteger =
        BigInteger(1, bytes.reversedArray())

    private fun encodeLittleEndian(value: BigInteger): ByteArray {
        val bigEndian = value.toByteArray()
        val out = ByteArray(KEY_SIZE)
        for (i in 0 until minOf(KEY_SIZE, bigEndian.size)) {
            out[i] = bigEndian[bigEndian.size - 1 - i]
        }
        return out
    }
}
