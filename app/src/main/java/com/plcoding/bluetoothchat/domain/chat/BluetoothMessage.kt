package com.plcoding.bluetoothchat.domain.chat

data class BluetoothMessage(
    val message: String,
    val senderName: String,
    val isFromLocalUser: Boolean,
    val isAttack: Boolean = false,
    val attackType: String = "",
    val attackConfidence: Double = 0.0
)