package com.plcoding.bluetoothchat.presentation

data class SecurityAlert(
    val attackType: String,
    val message: String,
    val deviceAddress: String,
    val deviceName: String,
    val timestamp: Long = System.currentTimeMillis()
)
