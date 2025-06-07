package com.plcoding.bluetoothchat.presentation

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.plcoding.bluetoothchat.data.chat.BluetoothControllerWrapper
import com.plcoding.bluetoothchat.domain.chat.BluetoothController
import com.plcoding.bluetoothchat.domain.chat.BluetoothDeviceDomain
import com.plcoding.bluetoothchat.domain.chat.BluetoothMessage
import com.plcoding.bluetoothchat.domain.chat.ConnectionResult
import com.plcoding.bluetoothchat.presentation.IDS.IDSModel
import com.plcoding.bluetoothchat.presentation.components.SecurityAlertHandler
import dagger.assisted.Assisted
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class BluetoothViewModel @Inject constructor(
    private val bluetoothController: BluetoothController,
    private val idsModel: IDSModel,
    private val controllerWrapper: BluetoothControllerWrapper,
    private val savedStateHandle: SavedStateHandle,
): ViewModel(), SecurityAlertHandler {
    private val _securityAlert = MutableStateFlow<SecurityAlert?>(null)
    val securityAlert = _securityAlert.asStateFlow()

    private val _state = MutableStateFlow(BluetoothUiState())
    val state = combine(
        bluetoothController.scannedDevices,
        bluetoothController.pairedDevices,
        _state
    ) { scannedDevices, pairedDevices, state ->
        state.copy(
            scannedDevices = scannedDevices,
            pairedDevices = pairedDevices,
            messages = if(state.isConnected) state.messages else emptyList()
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), _state.value)

    private var deviceConnectionJob: Job? = null

    init {
        controllerWrapper.setSecurityAlertCallback { alert ->
            _securityAlert.value = alert
        }
        bluetoothController.isConnected.onEach { isConnected ->
            _state.update { it.copy(isConnected = isConnected) }
        }.launchIn(viewModelScope)

        bluetoothController.errors.onEach { error ->
            _state.update { it.copy(
                errorMessage = error
            ) }
        }.launchIn(viewModelScope)
    }

    fun connectToDevice(device: BluetoothDeviceDomain) {
        _state.update { it.copy(isConnecting = true) }
        deviceConnectionJob = bluetoothController
            .connectToDevice(device)
            .listen()
    }

    fun disconnectFromDevice() {
        deviceConnectionJob?.cancel()
        bluetoothController.closeConnection()
        _state.update { it.copy(
            isConnecting = false,
            isConnected = false
        ) }
    }

    fun waitForIncomingConnections() {
        _state.update { it.copy(isConnecting = true) }
        deviceConnectionJob = bluetoothController
            .startBluetoothServer()
            .listen()
    }

    fun sendMessage(message: String) {
        viewModelScope.launch {
            val bluetoothMessage = bluetoothController.trySendMessage(message)
            if(bluetoothMessage != null) {
                _state.update { it.copy(
                    messages = it.messages + bluetoothMessage
                ) }
            }
        }
    }

    fun startScan() {
        bluetoothController.startDiscovery()
    }

    fun stopScan() {
        bluetoothController.stopDiscovery()
    }

    private fun Flow<ConnectionResult>.listen(): Job {
        return onEach { result ->
            when(result) {
                ConnectionResult.ConnectionEstablished -> {
                    _state.update { it.copy(
                        isConnected = true,
                        isConnecting = false,
                        errorMessage = null
                    ) }
                }
                is ConnectionResult.TransferSucceeded -> {
                    _state.update { it.copy(
                        messages = it.messages + result.message
                    ) }
                }
                is ConnectionResult.Error -> {
                    _state.update { it.copy(
                        isConnected = false,
                        isConnecting = false,
                        errorMessage = result.message
                    ) }
                }
                ConnectionResult.Disconnected -> {
                    _state.update { it.copy(
                        isConnected = false,
                        isConnecting = false,
                        errorMessage = null
                    ) }
                }
            }
        }
            .catch { throwable ->
                bluetoothController.closeConnection()
                _state.update { it.copy(
                    isConnected = false,
                    isConnecting = false,
                ) }
            }
            .launchIn(viewModelScope)
    }

    override fun onCleared() {
        super.onCleared()
        bluetoothController.release()
    }

    override fun onSecurityAlert(alert: SecurityAlert) {
        _securityAlert.value = alert
    }

    fun clearSecurityAlert() {
        _securityAlert.value = null
    }

    enum class AttackType { SPOOFING, INJECTION, FLOODING, None }

    suspend fun simulateAttack(type: AttackType) {
        when (type) {
            AttackType.SPOOFING -> simulateSpoofing()
            AttackType.INJECTION -> simulateInjection()
            AttackType.FLOODING -> simulateFlooding()
            AttackType.None -> return
        }
    }

    private suspend fun simulateSpoofing() {
        val message = "URGENT: Your account will be locked! Click http://malicious.link"
        bluetoothController.trySendMessage(message)
    }

    private suspend fun simulateInjection() {
        val message = "ADMIN COMMAND: {malicious: payload, exploit: true}"
        bluetoothController.trySendMessage(message)
    }

    private suspend fun simulateFlooding() {
        repeat(50) {
            bluetoothController.trySendMessage("FLOOD_${System.currentTimeMillis()}")
            delay(100)
        }
    }

    fun blockDevice(deviceAddress: String) {
        // Implementation to block the device
    }

    private val _detectionExplanation = MutableStateFlow<String?>(null)
    val detectionExplanation: StateFlow<String?> = _detectionExplanation.asStateFlow()

    suspend fun processIncomingMessage(message: BluetoothMessage) {
        val result = idsModel.analyzeMessage(message.message)

        if (result.isAttack) {
            _detectionExplanation.value = """
                🚨 Attack Detected: ${result.attackType}
                🔍 Detection Method: ${if (result.aiDetected) "AI Model (${idsModel.modelName})" else "Rule-based"}
                📝 Pattern: ${result.matchedPattern}
                ℹ️ ${result.explanation}
            """.trimIndent()

            bluetoothController.trySendMessage(
                "[IDS Alert] ${result.attackType} detected"
            )
        }
    }
}