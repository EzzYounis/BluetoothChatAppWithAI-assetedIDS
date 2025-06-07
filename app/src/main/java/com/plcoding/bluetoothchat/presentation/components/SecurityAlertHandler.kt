package com.plcoding.bluetoothchat.presentation.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import com.plcoding.bluetoothchat.presentation.BluetoothViewModel

@Composable
fun SecurityAlertHandler(
    viewModel: BluetoothViewModel,
    onBlockDevice: (String) -> Unit
) {
    val securityAlert by viewModel.securityAlert.collectAsState()

    securityAlert?.let { alert ->
        SecurityAlertDialog(
            alert = alert,
            onDismiss = { viewModel.clearSecurityAlert() },
            onBlockDevice = {
                onBlockDevice(alert.deviceAddress)
                viewModel.clearSecurityAlert()
            }
        )
    }
}