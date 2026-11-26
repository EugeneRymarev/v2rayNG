package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.V2rayConfig
import com.v2ray.ang.dto.V2rayConfig.OutboundBean
import com.v2ray.ang.handler.WarpMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WarpTransportTest {

    private fun proxy(tag: String, address: String, dialer: String? = null) = OutboundBean(
        tag = tag,
        protocol = "vless",
        settings = OutboundBean.OutSettingsBean(address = address, port = 443),
    ).also { outbound -> dialer?.let { outbound.ensureSockopt().dialerProxy = it } }

    private fun plain(tag: String, protocol: String) = OutboundBean(tag = tag, protocol = protocol)

    private fun warp() = OutboundBean(
        tag = "will-be-replaced",
        protocol = "wireguard",
        settings = OutboundBean.OutSettingsBean(peers = listOf(OutboundBean.OutSettingsBean.WireGuardBean(endpoint = "162.159.192.1:2408"))),
    )

    private fun config(vararg outbounds: OutboundBean): V2rayConfig {
        val config = com.google.gson.Gson().fromJson(MINIMAL_CONFIG, V2rayConfig::class.java)
        config.outbounds.clear()
        config.outbounds.addAll(outbounds)
        return config
    }

    @Test
    fun allMode() {
        val cfg = config(
            proxy("proxy", "example.com"),
            proxy("proxy-2", "2001:db8::1"),
            plain(AppConfig.TAG_DIRECT, "freedom"),
            plain(AppConfig.TAG_BLOCKED, "blackhole"),
        )
        val routed = WarpTransport.apply(cfg, warp(), WarpMode.ALL)
        assertEquals(listOf("proxy", "proxy-2"), routed)
        assertEquals(AppConfig.TAG_WARP, cfg.outbounds[0].streamSettings?.sockopt?.dialerProxy)
        assertEquals(AppConfig.TAG_WARP, cfg.outbounds[1].streamSettings?.sockopt?.dialerProxy)
        assertNull(cfg.outbounds[2].streamSettings)
        assertNull(cfg.outbounds[3].streamSettings)
        assertEquals(AppConfig.TAG_WARP, cfg.outbounds.last().tag)
        assertNull(cfg.outbounds.last().streamSettings?.sockopt?.dialerProxy)
    }

    @Test
    fun chainFirstHopOnly() {
        val cfg = config(proxy("proxy", "exit.example.com", dialer = "proxy-proxy-1"), proxy("proxy-proxy-1", "entry.example.com"))
        assertEquals(listOf("proxy-proxy-1"), WarpTransport.apply(cfg, warp(), WarpMode.ALL))
        assertEquals("proxy-proxy-1", cfg.outbounds[0].streamSettings?.sockopt?.dialerProxy)
        assertEquals(AppConfig.TAG_WARP, cfg.outbounds[1].streamSettings?.sockopt?.dialerProxy)
    }

    @Test
    fun ipv6Mode() {
        val cfg = config(
            proxy("proxy", "203.0.113.5"),
            proxy("v6-literal", "2001:db8::1"),
            proxy("v6-domain", "v6only.example.com"),
            proxy("dual-domain", "dual.example.com"),
        )
        val hosts = mapOf<String, Any>(
            "v6only.example.com" to listOf("2001:db8::2"),
            "dual.example.com" to listOf("198.51.100.1", "2001:db8::3"),
        )
        assertEquals(listOf("v6-literal", "v6-domain"), WarpTransport.apply(cfg, warp(), WarpMode.IPV6_SERVERS, hosts))
        assertNull(cfg.outbounds[0].streamSettings)
        assertNull(cfg.outbounds[3].streamSettings)
    }

    @Test
    fun noChanges() {
        val off = config(proxy("proxy", "2001:db8::1"))
        assertTrue(WarpTransport.apply(off, warp(), WarpMode.OFF).isEmpty())
        assertEquals(1, off.outbounds.size)

        val v4only = config(proxy("proxy", "203.0.113.5"))
        assertTrue(WarpTransport.apply(v4only, warp(), WarpMode.IPV6_SERVERS).isEmpty())
        assertEquals(1, v4only.outbounds.size)
        assertNull(v4only.outbounds[0].streamSettings)
    }

    @Test
    fun ipv6Rule() {
        val cfg = config(proxy("proxy", "203.0.113.5"))
        cfg.routing.rules.add(V2rayConfig.RoutingBean.RulesBean(inboundTag = listOf("socks"), port = "53", outboundTag = "dns-out"))
        cfg.routing.rules.add(V2rayConfig.RoutingBean.RulesBean(ip = listOf("geoip:private"), outboundTag = AppConfig.TAG_DIRECT))
        assertTrue(WarpTransport.apply(cfg, warp(), WarpMode.IPV6_SERVERS, ipv6Inbounds = listOf("socks")).isEmpty())
        assertEquals(AppConfig.TAG_WARP, cfg.outbounds.last().tag)
        val rule = cfg.routing.rules[1]
        assertEquals(listOf("socks"), rule.inboundTag)
        assertEquals(listOf(WarpTransport.GLOBAL_IPV6), rule.ip)
        assertEquals(AppConfig.TAG_WARP, rule.outboundTag)
        assertNull(cfg.outbounds[0].streamSettings)
    }

    @Test
    fun appliesOnlyOnce() {
        val cfg = config(proxy("proxy", "example.com"))
        WarpTransport.apply(cfg, warp(), WarpMode.ALL)
        assertTrue(WarpTransport.apply(cfg, warp(), WarpMode.ALL).isEmpty())
        assertEquals(1, cfg.outbounds.count { it.tag == AppConfig.TAG_WARP })
    }

    @Test
    fun ipv6Detection() {
        assertTrue(WarpTransport.isIpv6Literal("2001:db8::1"))
        assertTrue(WarpTransport.isIpv6Literal("[2001:db8::1]"))
        assertTrue(WarpTransport.isIpv6Literal("::ffff:1.2.3.4"))
        assertTrue(WarpTransport.isIpv6Literal("fe80::1%wlan0"))
        assertFalse(WarpTransport.isIpv6Literal("1.2.3.4"))
        assertFalse(WarpTransport.isIpv6Literal("example.com"))
        assertFalse(WarpTransport.isIpv6Literal("host:443"))
        assertFalse(WarpTransport.isIpv6Server(null))
        assertFalse(WarpTransport.isIpv6Server("example.com", mapOf("example.com" to "1.2.3.4")))
        assertTrue(WarpTransport.isIpv6Server("example.com", mapOf("example.com" to "2001:db8::9")))
        assertFalse(WarpTransport.isIpv6Server("example.com", mapOf("example.com" to emptyList<String>())))
    }

    private companion object {
        const val MINIMAL_CONFIG = """{"log":{},"inbounds":[],"outbounds":[],"routing":{"domainStrategy":"AsIs","rules":[]},"dns":{"servers":[]}}"""
    }
}
