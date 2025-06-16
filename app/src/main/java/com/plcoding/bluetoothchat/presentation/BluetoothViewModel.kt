package com.plcoding.bluetoothchat.presentation

import android.util.Log
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.plcoding.bluetoothchat.domain.chat.BluetoothController
import com.plcoding.bluetoothchat.domain.chat.BluetoothDeviceDomain
import com.plcoding.bluetoothchat.domain.chat.BluetoothMessage
import com.plcoding.bluetoothchat.domain.chat.ConnectionResult
import com.plcoding.bluetoothchat.presentation.IDS.IDSModel
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
    private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    // UI State
    private val _state = MutableStateFlow(BluetoothUiState())
    val state = combine(
        bluetoothController.scannedDevices,
        bluetoothController.pairedDevices,
        _state
    ) { scannedDevices, pairedDevices, state ->
        state.copy(
            scannedDevices = scannedDevices,
            pairedDevices = pairedDevices,
            messages = if (state.isConnected) state.messages else emptyList()
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), _state.value)

    // Security Alert State
    private val _securityAlert = MutableStateFlow<SecurityAlertUI?>(null)
    val securityAlert = _securityAlert.asStateFlow()

    // Detection explanation for UI
    private val _detectionExplanation = MutableStateFlow<String?>(null)
    val detectionExplanation: StateFlow<String?> = _detectionExplanation.asStateFlow()

    // Attack notifications from IDS
    private val _attackNotifications = MutableStateFlow<List<AttackNotificationUI>>(emptyList())
    val attackNotifications: StateFlow<List<AttackNotificationUI>> = _attackNotifications.asStateFlow()

    private var deviceConnectionJob: Job? = null

    // Data classes for UI
    data class SecurityAlertUI(
        val deviceAddress: String,
        val deviceName: String,
        val attackType: String,
        val confidence: Double,
        val message: String,
        val explanation: String,
        val patternMatch: String,
        val severity: AttackSeverity,
        val recommendedActions: List<String>,
        val timestamp: Long = System.currentTimeMillis()
    )

    data class AttackNotificationUI(
        val id: String = java.util.UUID.randomUUID().toString(),
        val deviceName: String,
        val attackType: String,
        val severity: AttackSeverity,
        val message: String,
        val timestamp: Long,
        val actionTaken: Boolean = false
    )

    enum class AttackSeverity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    enum class AttackType {
        SPOOFING,
        INJECTION,
        FLOODING,
        NONE
    }

    // Get connected device address from controller
    val connectedDeviceAddress: String?
        get() = bluetoothController.connectedDeviceAddress

    init {
        // Subscribe to IDS attack notifications
        viewModelScope.launch {
            idsModel.getAttackNotificationFlow().collect { notification ->
                handleAttackNotification(notification)
            }
        }

        // Monitor connection state
        bluetoothController.isConnected.onEach { isConnected ->
            _state.update { it.copy(isConnected = isConnected) }
            if (isConnected) {
                Log.d("BluetoothViewModel", "Connected - IDS monitoring active")
            }
        }.launchIn(viewModelScope)

        // Monitor errors
        bluetoothController.errors.onEach { error ->
            _state.update { it.copy(errorMessage = error) }
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
            Log.d("BluetoothViewModel", "Sending message: '$message'")

            // Analyze outgoing message with IDS
            val analysis = idsModel.analyzeMessage(
                message = message,
                fromDevice = "local",
                toDevice = connectedDeviceAddress ?: "remote",
                direction = "OUTGOING"
            )

            if (analysis.isAttack) {
                Log.w("BluetoothViewModel", "Warning: Outgoing message flagged as ${analysis.attackType}")
            }

            val bluetoothMessage = bluetoothController.trySendMessage(message)
            if (bluetoothMessage != null) {
                _state.update { it.copy(
                    messages = it.messages + bluetoothMessage
                ) }
                Log.d("BluetoothViewModel", "Message sent and added to UI")
            } else {
                Log.w("BluetoothViewModel", "Failed to send message")
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
            when (result) {
                ConnectionResult.ConnectionEstablished -> {
                    _state.update { it.copy(
                        isConnected = true,
                        isConnecting = false,
                        errorMessage = null
                    ) }
                    Log.d("BluetoothViewModel", "Connection established - IDS monitoring active")
                }

                is ConnectionResult.TransferSucceeded -> {
                    Log.d("BluetoothViewModel", "Message received: ${result.message.message}")

                    // The message has already been analyzed by BluetoothDataTransferService
                    // Just add it to the UI
                    _state.update { it.copy(
                        messages = it.messages + result.message
                    ) }

                    if (result.message.isAttack) {
                        Log.w("BluetoothViewModel", "Attack message received: ${result.message.message}")
                    }
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
                    Log.d("BluetoothViewModel", "Disconnected - IDS monitoring stopped")
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

    private suspend fun handleAttackNotification(notification: IDSModel.AttackNotification) {
        // Determine severity
        val severity = when {
            notification.attackType == "EXPLOIT" && notification.confidence > 0.8 -> AttackSeverity.CRITICAL
            notification.attackType == "INJECTION" && notification.confidence > 0.7 -> AttackSeverity.HIGH
            notification.attackType == "SPOOFING" -> AttackSeverity.MEDIUM
            notification.attackType == "FLOODING" && notification.count > 10 -> AttackSeverity.HIGH
            else -> AttackSeverity.LOW
        }

        // Get device name
        val deviceName = getDeviceName(notification.deviceId)

        // Create UI notification
        val uiNotification = AttackNotificationUI(
            deviceName = deviceName,
            attackType = notification.attackType,
            severity = severity,
            message = formatAttackMessage(notification),
            timestamp = notification.timestamp
        )

        // Add to notifications
        _attackNotifications.value = (_attackNotifications.value + uiNotification)
            .sortedByDescending { it.timestamp }
            .take(10)

        // Show alert for high severity
        if (severity >= AttackSeverity.HIGH) {
            showSecurityAlert(notification, deviceName, severity)
        }

        // Show detection explanation
        _detectionExplanation.value = """
            🚨 Security Alert: ${notification.attackType}
            📱 Device: $deviceName
            📊 Confidence: ${String.format("%.1f", notification.confidence * 100)}%
            🔢 Count: ${notification.count} attacks in ${formatTimeWindow(notification.timeWindow)}
            📝 Sample: "${notification.sampleMessage.take(50)}..."
        """.trimIndent()
    }

    fun onSecurityAlert(alert: SecurityAlert) {
        Log.d("BluetoothViewModel", "Security alert received: ${alert.attackType}")

        // Convert SecurityAlert to SecurityAlertUI
        val severity = when {
            alert.attackType == "EXPLOIT" -> AttackSeverity.CRITICAL
            alert.attackType == "INJECTION" -> AttackSeverity.HIGH
            alert.attackType == "SPOOFING" -> AttackSeverity.MEDIUM
            alert.attackType == "FLOODING" -> AttackSeverity.HIGH
            else -> AttackSeverity.LOW
        }

        _securityAlert.value = SecurityAlertUI(
            deviceAddress = alert.deviceAddress,
            deviceName = alert.deviceName,
            attackType = alert.attackType,
            confidence = 0.9, // Default high confidence for manual alerts
            message = alert.message,
            explanation = alert.explanation,
            patternMatch = "",
            severity = severity,
            recommendedActions = getRecommendedActions(alert.attackType)
        )
    }

    private fun showSecurityAlert(
        notification: IDSModel.AttackNotification,
        deviceName: String,
        severity: AttackSeverity
    ) {
        val recommendedActions = getRecommendedActions(notification.attackType)

        _securityAlert.value = SecurityAlertUI(
            deviceAddress = notification.deviceId,
            deviceName = deviceName,
            attackType = notification.attackType,
            confidence = notification.confidence,
            message = notification.sampleMessage,
            explanation = getAttackExplanation(notification.attackType),
            patternMatch = "", // Will be filled by IDS
            severity = severity,
            recommendedActions = recommendedActions
        )
    }

    private fun getDeviceName(deviceAddress: String): String {
        return state.value.pairedDevices.find { it.address == deviceAddress }?.name
            ?: state.value.scannedDevices.find { it.address == deviceAddress }?.name
            ?: deviceAddress
    }

    private fun formatAttackMessage(notification: IDSModel.AttackNotification): String {
        val timeWindow = formatTimeWindow(notification.timeWindow)

        return when (notification.attackType) {
            "INJECTION" -> "Detected ${notification.count} code injection attempts in $timeWindow"
            "SPOOFING" -> "Detected ${notification.count} spoofing/phishing attempts in $timeWindow"
            "FLOODING" -> "Device is flooding with ${notification.count} messages in $timeWindow"
            "EXPLOIT" -> "Detected ${notification.count} exploit attempts in $timeWindow"
            else -> "Detected ${notification.count} suspicious activities in $timeWindow"
        }
    }

    private fun formatTimeWindow(timeMs: Long): String {
        return when {
            timeMs < 60000 -> "${timeMs / 1000}s"
            timeMs < 3600000 -> "${timeMs / 60000}m"
            else -> "${timeMs / 3600000}h"
        }
    }

    private fun getRecommendedActions(attackType: String): List<String> {
        return when (attackType) {
            "INJECTION" -> listOf(
                "Block this device immediately",
                "Do not execute any commands",
                "Check for system compromise"
            )
            "SPOOFING" -> listOf(
                "Verify device identity",
                "Do not click any links",
                "Do not provide credentials"
            )
            "FLOODING" -> listOf(
                "Temporarily mute device",
                "Enable rate limiting",
                "Block if continues"
            )
            "EXPLOIT" -> listOf(
                "Disconnect immediately",
                "Check system security",
                "Update security patches"
            )
            else -> listOf("Monitor device", "Consider blocking")
        }
    }

    private fun getAttackExplanation(attackType: String): String {
        return when (attackType) {
            "INJECTION" -> "Attempting to execute malicious code or commands"
            "SPOOFING" -> "Trying to impersonate a trusted entity or phishing"
            "FLOODING" -> "Overwhelming the system with excessive messages"
            "EXPLOIT" -> "Attempting to exploit system vulnerabilities"
            else -> "Suspicious activity detected"
        }
    }

    fun clearSecurityAlert() {
        _securityAlert.value = null
        _detectionExplanation.value = null
    }

    fun blockDevice(deviceAddress: String) {
        viewModelScope.launch {
            Log.d("BluetoothViewModel", "Blocking device: $deviceAddress")

            // Clear IDS history for this device
            idsModel.clearDeviceHistory(deviceAddress)

            // Disconnect if connected
            if (connectedDeviceAddress == deviceAddress) {
                disconnectFromDevice()
            }

            // Mark notification as acted upon
            _attackNotifications.value = _attackNotifications.value.map { notif ->
                if (notif.deviceName.contains(deviceAddress)) {
                    notif.copy(actionTaken = true)
                } else notif
            }

            // TODO: Implement actual device blocking in BluetoothController
        }
    }

    // Test functions for development
    fun testIDSSystem() {
        viewModelScope.launch {
            Log.d("BluetoothViewModel", "Testing IDS system...")
            val testResults = idsModel.runTestCases()

            testResults.forEach { (message, result) ->
                Log.d("BluetoothViewModel", "Test: '${message.take(30)}...'")
                Log.d("BluetoothViewModel", "  Result: ${result.attackType} (${String.format("%.1f", result.confidence * 100)}%)")
            }
        }
    }

    fun simulateAttack(type: AttackType) {
        viewModelScope.launch {
            Log.d("BluetoothViewModel", "Simulating $type attack")

            val messages = when (type) {
                AttackType.SPOOFING -> listOf(
                    "URGENT: Your account will be suspended! Click http://malicious.com",
                    "Security Alert: Verify your password at www.fake-site.com"
                )
                AttackType.INJECTION -> listOf(
                    "{ \"command\": \"delete_files\", \"target\": \"*\" }",
                    "<script>alert('XSS')</script>",
                    "'; DROP TABLE users; --"
                )
                AttackType.FLOODING -> List(15) { i ->
                    "FLOOD_${System.currentTimeMillis()}_$i"
                }
                AttackType.NONE -> listOf("Normal test message")
            }

            messages.forEach { msg ->
                sendMessage(msg)
                delay(if (type == AttackType.FLOODING) 50 else 1000)
            }
        }
    }

    fun analyzeMessage(message: String) {
        viewModelScope.launch {
            val result = idsModel.analyzeMessage(message)
            Log.d("BluetoothViewModel", "Manual analysis of '$message':")
            Log.d("BluetoothViewModel", "Result: ${result.isAttack}, Type: ${result.attackType}, Confidence: ${result.confidence}")

            if (result.isAttack) {
                _detectionExplanation.value = """
                    🔍 Manual Analysis Result:
                    🚨 Attack Type: ${result.attackType}
                    📊 Confidence: ${String.format("%.1f", result.confidence * 100)}%
                    📝 Pattern: ${result.patternMatch}
                    ℹ️ ${result.explanation}
                """.trimIndent()
            }
        }
    }

    fun getAttackSummary(): Map<String, Int> {
        return idsModel.getAttackSummary()
    }

    fun resetModel() {
        viewModelScope.launch {
            idsModel.resetModel()
            _attackNotifications.value = emptyList()
            _detectionExplanation.value = null
            Log.d("BluetoothViewModel", "IDS model reset - history cleared")
        }
    }

    override fun onCleared() {
        super.onCleared()
        bluetoothController.release()
        idsModel.cleanup()
    }
}