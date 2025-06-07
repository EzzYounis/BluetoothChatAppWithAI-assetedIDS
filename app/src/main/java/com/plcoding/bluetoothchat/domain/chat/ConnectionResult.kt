package com.plcoding.bluetoothchat.domain.chat

sealed class ConnectionResult {
    object ConnectionEstablished : ConnectionResult()
    data class TransferSucceeded(val message: BluetoothMessage) : ConnectionResult()
    data class Error(val message: String) : ConnectionResult()
    object Disconnected : ConnectionResult()
}