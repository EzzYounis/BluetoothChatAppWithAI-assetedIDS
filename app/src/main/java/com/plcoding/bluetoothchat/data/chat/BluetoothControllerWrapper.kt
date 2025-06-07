package com.plcoding.bluetoothchat.data.chat

import com.plcoding.bluetoothchat.domain.chat.BluetoothController
import com.plcoding.bluetoothchat.presentation.SecurityAlert
import javax.inject.Inject

class BluetoothControllerWrapper @Inject constructor(
    private val controller: BluetoothController
) {
    private var securityAlertCallback: (SecurityAlert) -> Unit = { _ -> }

    fun setSecurityAlertCallback(callback: (SecurityAlert) -> Unit) {
        this.securityAlertCallback = callback
        (controller as? AndroidBluetoothController)?.setSecurityAlertCallback(callback)
    }

    fun getController(): BluetoothController = controller
}