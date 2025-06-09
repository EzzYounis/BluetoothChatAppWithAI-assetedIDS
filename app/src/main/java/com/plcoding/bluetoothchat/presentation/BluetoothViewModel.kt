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
import android.util.Log
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

    // Detection explanation for UI
    private val _detectionExplanation = MutableStateFlow<String?>(null)
    val detectionExplanation: StateFlow<String?> = _detectionExplanation.asStateFlow()

    init {
        controllerWrapper.setSecurityAlertCallback { alert ->
            Log.d("ViewModel", "Security alert received: ${alert.attackType}")
            _securityAlert.value = alert

            // Show detection explanation
            _detectionExplanation.value = """
                🚨 Security Alert: ${alert.attackType}
                🔍 Detection Method: ${alert.detectionMethod}
                📱 Device: ${alert.deviceName} (${alert.deviceAddress})
                📝 Message: "${alert.message}"
                ℹ️ ${alert.explanation}
            """.trimIndent()
        }

        bluetoothController.isConnected.onEach { isConnected ->
            _state.update { it.copy(isConnected = isConnected) }
            if (isConnected) {
                Log.d("ViewModel", "Connected - IDS system is active")
            }
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
            Log.d("ViewModel", "Sending message: '$message'")
            val bluetoothMessage = bluetoothController.trySendMessage(message)
            if(bluetoothMessage != null) {
                _state.update { it.copy(
                    messages = it.messages + bluetoothMessage
                ) }
                Log.d("ViewModel", "Message added to UI")
            } else {
                Log.w("ViewModel", "Failed to send message")
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
                    Log.d("ViewModel", "Connection established - IDS monitoring active")
                }
                is ConnectionResult.TransferSucceeded -> {
                    Log.d("ViewModel", "Message received: ${result.message.message}, isAttack: ${result.message.isAttack}")
                    _state.update { it.copy(
                        messages = it.messages + result.message
                    ) }

                    // Process the message for additional IDS analysis if needed
                    processIncomingMessage(result.message)
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
                    Log.d("ViewModel", "Disconnected - IDS monitoring stopped")
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
        Log.d("ViewModel", "Security alert handler called: ${alert.attackType}")
        _securityAlert.value = alert
    }

    fun clearSecurityAlert() {
        _securityAlert.value = null
        _detectionExplanation.value = null
    }

    enum class AttackType {
        SPOOFING,
        INJECTION,
        FLOODING,
        NONE
    }

    // Enhanced attack simulation for testing
    suspend fun simulateAttack(type: AttackType) {
        Log.d("ViewModel", "Simulating attack: $type")
        when (type) {
            AttackType.SPOOFING -> {
                val messages = listOf(
                    "URGENT: Your account will be suspended! Click http://malicious-site.com to verify immediately",
                    "Security Alert: Please enter your password at https://fake-bank.com/login",
                    "Winner! You've won $1000! Click www.scam-site.org to claim your prize"
                )
                messages.forEach { msg ->
                    sendMessage(msg)
                    delay(1000)
                }
            }
            AttackType.INJECTION -> {
                val messages = listOf(
                    "ADMIN COMMAND: {execute: true, payload: 'rm -rf /', escalate: 'root'}",
                    "<script>alert('XSS Attack')</script>",
                    "'; DROP TABLE users; --",
                    "System command: eval('malicious_code()')"
                )
                messages.forEach { msg ->
                    sendMessage(msg)
                    delay(1000)
                }
            }
            AttackType.FLOODING -> {
                repeat(10) { i ->
                    sendMessage("FLOOD_${System.currentTimeMillis()}_$i")
                    delay(50) // Send very fast to trigger flood detection
                }
            }
            AttackType.NONE -> {
                sendMessage("Hello, this is a normal message for testing purposes.")
            }
        }
    }

    fun blockDevice(deviceAddress: String) {
        // Implementation to block the device
        Log.d("ViewModel", "Blocking device: $deviceAddress")
        // You can implement actual blocking logic here
    }

    suspend fun processIncomingMessage(message: BluetoothMessage) {
        // Additional processing if needed
        if (message.isAttack) {
            Log.w("ViewModel", "Attack message processed: ${message.message}")
        }
    }

    // Test IDS functionality
    fun testIDSSystem() {
        viewModelScope.launch {
            Log.d("ViewModel", "Testing IDS system...")
            val testResults = idsModel.runTestCases()

            Log.d("ViewModel", "=== IDS Test Results ===")
            testResults.forEach { (message, result) ->
                Log.d("ViewModel", "Test: '$message'")
                Log.d("ViewModel", "  -> Attack: ${result.isAttack}")
                Log.d("ViewModel", "  -> Type: ${result.attackType}")
                Log.d("ViewModel", "  -> Confidence: ${String.format("%.2f", result.confidence)}")
                Log.d("ViewModel", "  -> Explanation: ${result.explanation}")
                Log.d("ViewModel", "---")
            }
            Log.d("ViewModel", "=== End IDS Test ===")
        }
    }

    // Manual message analysis for testing
    fun analyzeMessage(message: String) {
        viewModelScope.launch {
            val result = idsModel.analyzeMessage(message)
            Log.d("ViewModel", "Manual analysis of '$message':")
            Log.d("ViewModel", "Result: ${result.isAttack}, Type: ${result.attackType}, Confidence: ${result.confidence}")

            if (result.isAttack) {
                _detectionExplanation.value = """
                    🔍 Manual Analysis Result:
                    🚨 Attack Type: ${result.attackType}
                    📊 Confidence: ${String.format("%.1f", result.confidence * 100)}%
                    🤖 Detection: ${if (result.isAttack) "AI Model" else "Rule-based"}
                    📝 Pattern: ${result.patternMatch}
                    ℹ️ ${result.explanation}
                """.trimIndent()
            }
        }
    }
}