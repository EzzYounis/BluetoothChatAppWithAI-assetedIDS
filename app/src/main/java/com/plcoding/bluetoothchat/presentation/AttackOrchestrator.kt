package com.plcoding.bluetoothchat.presentation

import com.plcoding.bluetoothchat.domain.chat.BluetoothController
import com.plcoding.bluetoothchat.presentation.BluetoothViewModel.AttackType.SPOOFING
import kotlinx.coroutines.delay
import java.util.UUID
import kotlin.random.Random

class AttackOrchestrator(
    private val viewModel: BluetoothViewModel,
    private val bluetoothController: BluetoothController
) {
    private val spoofingMessages = listOf(
        "FREE BTC: http://malicious.site",
        "Your device is infected! Click here to clean",
        "Urgent: Your account will be locked"
    )

    private val injectionMessages = listOf(
        "ADMIN COMMAND: FORMAT DRIVE",
        "{malicious: payload, exploit: true}",
        "SQL INJECTION: ' OR 1=1 --"
    )

    suspend fun executeAttack(type: BluetoothViewModel.AttackType) {
        when (type) {
            SPOOFING -> simulateSpoofing()
            BluetoothViewModel.AttackType.INJECTION -> simulateInjection()
            BluetoothViewModel.AttackType.FLOODING -> simulateFlooding()
            BluetoothViewModel.AttackType.NONE -> return
        }
    }

    private suspend fun simulateSpoofing() {
        val message = spoofingMessages.random()
        bluetoothController.trySendMessage(message)
        triggerAlert(
            type = "spoofing",
            message = message,
            detectionMethod = "Simulated Attack",
            explanation = "This is a simulated phishing attempt with malicious URL"
        )
    }

    private suspend fun simulateInjection() {
        val message = injectionMessages.random()
        bluetoothController.trySendMessage(message)
        triggerAlert(
            type = "injection",
            message = message,
            detectionMethod = "Simulated Attack",
            explanation = "This is a simulated code injection attempt"
        )
    }

    private suspend fun simulateFlooding() {
        repeat(50) {
            bluetoothController.trySendMessage("FLOOD_${UUID.randomUUID()}")
            delay(100)
        }
        triggerAlert(
            type = "flooding",
            message = "Mass message flood detected",
            detectionMethod = "Simulated Attack",
            explanation = "This is a simulated message flooding attack"
        )
    }

    private fun triggerAlert(
        type: String,
        message: String,
        detectionMethod: String,
        explanation: String
    ) {
        viewModel.onSecurityAlert(
            SecurityAlert(
                attackType = type,
                deviceName = "ATTACKER_${Random.nextInt(1000)}",
                deviceAddress = generateRandomMac(),
                message = message,
                detectionMethod = detectionMethod,
                explanation = explanation
            )
        )
    }

    private fun generateRandomMac(): String =
        (1..6).joinToString(":") { "%02x".format(Random.nextInt(256)) }
}