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
            BluetoothViewModel.AttackType.None -> return
        }
    }

    private suspend fun simulateSpoofing() {
        val message = spoofingMessages.random()
        bluetoothController.trySendMessage(message)
        triggerAlert("spoofing", message)
    }

    private suspend fun simulateInjection() {
        val message = injectionMessages.random()
        bluetoothController.trySendMessage(message)
        triggerAlert("injection", message)
    }

    private suspend fun simulateFlooding() {
        repeat(50) {  // Send 50 rapid messages
            bluetoothController.trySendMessage("FLOOD_${UUID.randomUUID()}")
            delay(100) // 100ms between messages
        }
        triggerAlert("flooding", "Mass message flood detected")
    }

    private fun triggerAlert(type: String, message: String) {
        viewModel.onSecurityAlert(
            SecurityAlert(
                attackType = type,
                deviceName = "ATTACKER_${Random.nextInt(1000)}",
                deviceAddress = generateRandomMac(),
                message = message
            )
        )
    }

    private fun generateRandomMac(): String =
        (1..6).joinToString(":") { "%02x".format(Random.nextInt(256)) }
}