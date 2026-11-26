package com.v2ray.ang.handler

import com.google.gson.JsonParser
import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

class WarpManagerTest {

    private val sampleResponse = """
        {
          "id": "device-id",
          "token": "secret-token",
          "config": {
            "client_id": "AQID",
            "peers": [{
              "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
              "endpoint": {"v4": "162.159.192.5:0", "v6": "[2606:4700:d0::a29f:c005]:0", "host": "engage.cloudflareclient.com:2408"}
            }],
            "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a36:df92:102a:9602:fa18"}}
          }
        }
    """.trimIndent()

    @Test
    fun registrationBody() {
        val body = JsonParser.parseString(WarpManager.buildRegistrationBody("PUB", 0L)).asJsonObject
        assertEquals("PUB", body.get("key").asString)
        assertEquals("1970-01-01T00:00:00.000Z", body.get("tos").asString)
        assertEquals("", body.get("install_id").asString)
        assertEquals("en_US", body.get("locale").asString)
    }

    @Test
    fun parseResponse() {
        val account = WarpManager.parseRegistrationResponse(sampleResponse, "PRIV")
        assertNotNull(account)
        account!!
        assertEquals("PRIV", account.privateKey)
        assertEquals("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", account.peerPublicKey)
        assertEquals("172.16.0.2", account.addressV4)
        assertEquals("2606:4700:110:8a36:df92:102a:9602:fa18", account.addressV6)
        assertEquals("1,2,3", account.reserved)
        assertEquals("162.159.192.5", account.endpointHost)
        assertEquals(WarpManager.DEFAULT_ENDPOINT_PORT, account.endpointPort)
    }

    @Test
    fun parseWrappedResponse() {
        val wrapped = """{"success":true,"result":$sampleResponse}"""
        assertEquals("1,2,3", WarpManager.parseRegistrationResponse(wrapped, "PRIV")?.reserved)
    }

    @Test
    fun badResponses() {
        assertNull(WarpManager.parseRegistrationResponse(null, "PRIV"))
        assertNull(WarpManager.parseRegistrationResponse("", "PRIV"))
        assertNull(WarpManager.parseRegistrationResponse("not json", "PRIV"))
        assertNull(WarpManager.parseRegistrationResponse("""{"errors":[{"code":1015}]}""", "PRIV"))
        assertNull(WarpManager.parseRegistrationResponse("""{"config":{"peers":[]}}""", "PRIV"))
    }

    @Test
    fun defaultEndpoint() {
        val json = """{"config":{"peers":[{"public_key":"K"}]}}"""
        val account = WarpManager.parseRegistrationResponse(json, "PRIV")!!
        assertEquals(WarpManager.DEFAULT_ENDPOINT_HOST, account.endpointHost)
        assertEquals(WarpManager.DEFAULT_ENDPOINT_PORT, account.endpointPort)
        assertNull(account.reserved)
    }

    @Test
    fun clientIdToReserved() {
        assertEquals("1,2,3", WarpManager.clientIdToReserved("AQID"))
        assertEquals("255,254,253", WarpManager.clientIdToReserved("//79"))
        assertNull(WarpManager.clientIdToReserved("AQ=="))
        assertNull(WarpManager.clientIdToReserved(null))
        assertNull(WarpManager.clientIdToReserved("***"))
    }

    @Test
    fun profileItem() {
        val account = WarpManager.parseRegistrationResponse(sampleResponse, "PRIV")!!
        val profile = WarpManager.toProfileItem(account)
        assertEquals(EConfigType.WIREGUARD, profile.configType)
        assertEquals(WarpManager.DEFAULT_REMARKS, profile.remarks)
        assertEquals("162.159.192.5", profile.server)
        assertEquals("2408", profile.serverPort)
        assertEquals("PRIV", profile.secretKey)
        assertEquals(account.peerPublicKey, profile.publicKey)
        assertEquals("172.16.0.2/32,2606:4700:110:8a36:df92:102a:9602:fa18/128", profile.localAddress)
        assertEquals("1,2,3", profile.reserved)
        assertEquals(1280, profile.mtu)
    }

    @Test
    fun accountJson() {
        val account = WarpManager.parseRegistrationResponse(sampleResponse, "PRIV")!!
            .copy(endpointHost = "188.114.97.3", endpointPort = 4500)
        assertEquals(account, WarpManager.accountFromJson(WarpManager.accountToJson(account)))
    }

    @Test
    fun badAccountJson() {
        assertNull(WarpManager.accountFromJson(null))
        assertNull(WarpManager.accountFromJson(""))
        assertNull(WarpManager.accountFromJson("{"))
        assertNull(WarpManager.accountFromJson("""{"peerPublicKey":"K","endpointHost":"1.2.3.4","endpointPort":2408}"""))
        assertNull(WarpManager.accountFromJson("""{"privateKey":"P","peerPublicKey":"K","endpointHost":"1.2.3.4","endpointPort":0}"""))
    }

    @Test
    fun globalIpv6() {
        assertTrue(WarpManager.isGlobalIpv6(InetAddress.getByName("2001:db8::1")))
        assertTrue(WarpManager.isGlobalIpv6(InetAddress.getByName("2a0d:9ec0::1")))
        assertFalse(WarpManager.isGlobalIpv6(InetAddress.getByName("fe80::1")))
        assertFalse(WarpManager.isGlobalIpv6(InetAddress.getByName("fd66::1")))
        assertFalse(WarpManager.isGlobalIpv6(InetAddress.getByName("::1")))
        assertFalse(WarpManager.isGlobalIpv6(InetAddress.getByName("192.0.2.1")))
    }

    @Test
    fun modeFromValue() {
        assertEquals(WarpMode.OFF, WarpMode.fromValue(null))
        assertEquals(WarpMode.OFF, WarpMode.fromValue("x"))
        assertEquals(WarpMode.OFF, WarpMode.fromValue("0"))
        assertEquals(WarpMode.IPV6_SERVERS, WarpMode.fromValue("1"))
        assertEquals(WarpMode.ALL, WarpMode.fromValue("2"))
    }

}
