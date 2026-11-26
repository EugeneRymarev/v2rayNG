package com.v2ray.ang.ui.settings

import android.app.Application
import android.content.Intent
import android.provider.Settings
import androidx.lifecycle.viewModelScope
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.handler.WarpAccount
import com.v2ray.ang.handler.WarpManager
import com.v2ray.ang.handler.WarpMode
import com.v2ray.ang.root.RootManager
import com.v2ray.ang.ui.base.BaseViewModel
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class WarpUiState(
    val mode: WarpMode = WarpMode.OFF,
    val endpoint: String? = null, // null = no account yet
    val isWorking: Boolean = false,
)

class SettingsViewModel(application: Application) : BaseViewModel(application) {

    private val _warpState = MutableStateFlow(WarpUiState())
    val warpState: StateFlow<WarpUiState> = _warpState.asStateFlow()
    private var warpJob: Job? = null

    suspend fun refreshWarpState() {
        val (mode, account) = withContext(Dispatchers.IO) { WarpManager.getMode() to WarpManager.getAccount() }
        _warpState.update { it.copy(mode = mode, endpoint = account?.endpointText()) }
    }

    // turning WARP on without an account creates one first
    fun setWarpMode(mode: WarpMode) {
        if (mode == WarpMode.OFF) {
            warpJob?.cancel()
            saveWarpMode(mode)
            return
        }
        if (_warpState.value.endpoint != null) {
            saveWarpMode(mode)
            return
        }
        runWarp(R.string.toast_warp_registering, R.string.toast_warp_register_failed) {
            WarpManager.createAccount()?.also { WarpManager.setMode(mode) }
        }
    }

    fun createWarpAccount() =
        runWarp(R.string.toast_warp_registering, R.string.toast_warp_register_failed) { WarpManager.createAccount() }

    fun findWarpEndpoint() =
        runWarp(R.string.toast_warp_searching, R.string.toast_warp_no_endpoint) { WarpManager.findWorkingEndpoint() }

    private fun saveWarpMode(mode: WarpMode) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { WarpManager.setMode(mode) }
            _warpState.update { it.copy(mode = mode) }
        }
    }

    private fun runWarp(progressRes: Int, errorRes: Int, operation: suspend () -> WarpAccount?) {
        if (_warpState.value.isWorking) return
        toast(progressRes)
        _warpState.update { it.copy(isWorking = true) }
        warpJob = viewModelScope.launch {
            val account = try {
                operation()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "WARP operation failed", e)
                null
            } finally {
                _warpState.update { it.copy(isWorking = false) }
            }
            if (account == null) {
                toastError(errorRes)
                return@launch
            }
            val mode = withContext(Dispatchers.IO) { WarpManager.getMode() }
            _warpState.update { it.copy(mode = mode, endpoint = account.endpointText()) }
            toastSuccess(getString(R.string.toast_warp_ready, account.endpointText()))
        }
    }

    private fun WarpAccount.endpointText(): String = "$endpointHost:$endpointPort"

    private val _systemVpnSettingsAvailable = MutableStateFlow(false)
    val systemVpnSettingsAvailable = _systemVpnSettingsAvailable.asStateFlow()

    suspend fun refreshSystemVpnSettingsAvailability() {
        _systemVpnSettingsAvailable.value = withContext(Dispatchers.IO) {
            // Android exposes the VPN page, not a direct link to the Always-on VPN switch.
            Intent(Settings.ACTION_VPN_SETTINGS).resolveActivity(getApplication<Application>().packageManager) != null
        }
    }

    /**
     * Checks for root access and requests it if necessary.
     * Updates [isLoading] during the process.
     */
    fun checkAndRequestRoot(onSuccess: () -> Unit) {
        launchLoading {
            val hasRoot = withContext(Dispatchers.IO) {
                RootManager.refresh()
            }
            if (hasRoot) {
                onSuccess()
            } else {
                toastError(R.string.toast_root_required)
            }
        }
    }

    /**
     * Validates if the given string is a valid observatory duration.
     * Shows error toast if invalid.
     * @return The trimmed value if valid, null otherwise.
     */
    fun validateObservatoryDuration(value: String): String? {
        val duration = value.trim()
        return if (AppConfig.OBSERVATORY_DURATION_PATTERN.matches(duration)) {
            duration
        } else {
            toastError(R.string.toast_invalid_observatory_duration)
            null
        }
    }

    /**
     * Validates if the given string is a valid observatory sampling value.
     * Shows error toast if invalid.
     * @return The value if valid, null otherwise.
     */
    fun validateObservatorySampling(value: String): String? {
        val sampling = value.trim().toIntOrNull()?.takeIf { it > 0 }
        return if (sampling != null) {
            sampling.toString()
        } else {
            toastError(R.string.toast_invalid_observatory_sampling)
            null
        }
    }
}
