package com.plcoding.bluetoothchat.presentation.components

import com.plcoding.bluetoothchat.presentation.SecurityAlert

interface SecurityAlertHandler {
    fun onSecurityAlert(alert: SecurityAlert)
}