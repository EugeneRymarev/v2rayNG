package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.V2rayConfig
import com.v2ray.ang.handler.WarpMode

/** Dials proxy servers through Cloudflare WARP, so IPv6 servers work on IPv4-only networks. */
object WarpTransport {
    const val GLOBAL_IPV6 = "2000::/3"

    /**
     * Only the first hop of a chain is changed, the rest are dialed through it.
     * [ipv6Inbounds]: VPN inbounds whose IPv6 traffic should go through WARP.
     * Returns the tags of outbounds dialed through WARP.
     */
    fun apply(
        config: V2rayConfig,
        warpOutbound: V2rayConfig.OutboundBean,
        mode: WarpMode,
        dnsHosts: Map<String, Any>? = null,
        ipv6Inbounds: List<String> = emptyList(),
    ): List<String> {
        if (mode == WarpMode.OFF) return emptyList()
        if (config.outbounds.any { it.tag == AppConfig.TAG_WARP }) return emptyList()

        val targets = config.getAllProxyOutbound().filter { outbound ->
            outbound.streamSettings?.sockopt?.dialerProxy.isNullOrEmpty() &&
                (mode == WarpMode.ALL || isIpv6Server(outbound.getServerAddress(), dnsHosts))
        }
        if (targets.isEmpty() && ipv6Inbounds.isEmpty()) return emptyList()

        warpOutbound.tag = AppConfig.TAG_WARP
        targets.forEach { it.ensureSockopt().dialerProxy = AppConfig.TAG_WARP }
        config.outbounds.add(warpOutbound)
        if (ipv6Inbounds.isNotEmpty()) {
            addIpv6Rule(config, ipv6Inbounds)
        }
        return targets.mapNotNull { it.tag }
    }

    // after the DNS rules, before the user's rules
    private fun addIpv6Rule(config: V2rayConfig, inbounds: List<String>) {
        val rules = config.routing.rules
        val index = rules.indexOfFirst { it.outboundTag != "dns-out" }.takeIf { it >= 0 } ?: rules.size
        rules.add(
            index,
            V2rayConfig.RoutingBean.RulesBean(
                inboundTag = inbounds,
                ip = listOf(GLOBAL_IPV6),
                outboundTag = AppConfig.TAG_WARP,
            )
        )
    }

    fun isIpv6Server(address: String?, dnsHosts: Map<String, Any>? = null): Boolean {
        if (address.isNullOrBlank()) return false
        if (isIpv6Literal(address)) return true
        val resolved = when (val entry = dnsHosts?.get(address)) {
            is String -> listOf(entry)
            is Collection<*> -> entry.filterIsInstance<String>()
            else -> return false
        }
        return resolved.isNotEmpty() && resolved.all(::isIpv6Literal)
    }

    fun isIpv6Literal(value: String): Boolean {
        val address = value.trim().removePrefix("[").substringBefore(']').substringBefore('%')
        return address.count { it == ':' } >= 2 &&
            address.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
    }
}
