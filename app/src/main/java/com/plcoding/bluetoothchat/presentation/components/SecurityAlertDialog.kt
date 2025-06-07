package com.plcoding.bluetoothchat.presentation.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material.*
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.plcoding.bluetoothchat.presentation.SecurityAlert

@Composable
fun SecurityAlertDialog(
    alert: SecurityAlert,
    onDismiss: () -> Unit,
    onBlockDevice: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Security Alert - ${alert.attackType.replaceFirstChar { it.uppercase() }}",
                color = MaterialTheme.colorScheme.error
            )
        },
        text = {
            Column {
                Text(text = "Device: ${alert.deviceName} (${alert.deviceAddress})")
                Spacer(modifier = Modifier.height(8.dp))
                Text(text = "Message: ${alert.message.take(200)}")
            }
        },
        confirmButton = {
            TextButton(
                onClick = onDismiss
            ) {
                Text(text = "DISMISS")
            }
        },
        dismissButton = {
            TextButton(
                onClick = onBlockDevice,
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text(text = "BLOCK DEVICE")
            }
        }
    )
}