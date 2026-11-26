package com.v2ray.ang.util

/** BLAKE2s (RFC 7693), Java has none built in. */
object Blake2s {
    const val BLOCK_SIZE = 64
    const val HASH_SIZE = 32

    private val IV = intArrayOf(
        0x6A09E667, 0xBB67AE85L.toInt(), 0x3C6EF372, 0xA54FF53AL.toInt(),
        0x510E527F, 0x9B05688CL.toInt(), 0x1F83D9AB, 0x5BE0CD19
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    )

    fun hash(vararg parts: ByteArray): ByteArray = digest(concat(*parts), HASH_SIZE, ByteArray(0))

    fun digest(data: ByteArray, outLength: Int = HASH_SIZE, key: ByteArray = ByteArray(0)): ByteArray {
        require(outLength in 1..HASH_SIZE) { "BLAKE2s output must be 1..32 bytes" }
        require(key.size <= HASH_SIZE) { "BLAKE2s key must be at most 32 bytes" }

        val h = IV.copyOf()
        h[0] = h[0] xor (0x01010000 or (key.size shl 8) or outLength)

        val input = if (key.isNotEmpty()) concat(key.copyOf(BLOCK_SIZE), data) else data
        var counter = 0L
        var offset = 0
        val block = ByteArray(BLOCK_SIZE)

        if (input.isEmpty()) {
            compress(h, block, 0L, true)
        } else {
            while (offset < input.size) {
                val length = minOf(BLOCK_SIZE, input.size - offset)
                block.fill(0)
                System.arraycopy(input, offset, block, 0, length)
                offset += length
                counter += length
                compress(h, block, counter, offset >= input.size)
            }
        }

        val out = ByteArray(HASH_SIZE)
        for (i in 0 until 8) {
            val v = h[i]
            out[i * 4] = v.toByte()
            out[i * 4 + 1] = (v ushr 8).toByte()
            out[i * 4 + 2] = (v ushr 16).toByte()
            out[i * 4 + 3] = (v ushr 24).toByte()
        }
        return out.copyOf(outLength)
    }

    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val k = if (key.size > BLOCK_SIZE) hash(key) else key
        val padded = k.copyOf(BLOCK_SIZE)
        val inner = ByteArray(BLOCK_SIZE) { (padded[it].toInt() xor 0x36).toByte() }
        val outer = ByteArray(BLOCK_SIZE) { (padded[it].toInt() xor 0x5c).toByte() }
        return hash(outer, hash(inner, data))
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var pos = 0
        for (part in parts) {
            System.arraycopy(part, 0, out, pos, part.size)
            pos += part.size
        }
        return out
    }

    private fun compress(h: IntArray, block: ByteArray, counter: Long, last: Boolean) {
        val m = IntArray(16) { i ->
            (block[i * 4].toInt() and 0xff) or
                ((block[i * 4 + 1].toInt() and 0xff) shl 8) or
                ((block[i * 4 + 2].toInt() and 0xff) shl 16) or
                ((block[i * 4 + 3].toInt() and 0xff) shl 24)
        }
        val v = IntArray(16)
        System.arraycopy(h, 0, v, 0, 8)
        System.arraycopy(IV, 0, v, 8, 8)
        v[12] = v[12] xor counter.toInt()
        v[13] = v[13] xor (counter ushr 32).toInt()
        if (last) {
            v[14] = v[14].inv()
        }

        for (round in 0 until 10) {
            val s = SIGMA[round]
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for (i in 0 until 8) {
            h[i] = h[i] xor v[i] xor v[i + 8]
        }
    }

    private fun g(v: IntArray, a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
        v[a] = v[a] + v[b] + x
        v[d] = Integer.rotateRight(v[d] xor v[a], 16)
        v[c] = v[c] + v[d]
        v[b] = Integer.rotateRight(v[b] xor v[c], 12)
        v[a] = v[a] + v[b] + y
        v[d] = Integer.rotateRight(v[d] xor v[a], 8)
        v[c] = v[c] + v[d]
        v[b] = Integer.rotateRight(v[b] xor v[c], 7)
    }
}
