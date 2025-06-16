package com.plcoding.bluetoothchat.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.plcoding.bluetoothchat.presentation.BluetoothViewModel
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun IDSStatusDialog(
    viewModel: BluetoothViewModel,
    attackNotifications: List<BluetoothViewModel.AttackNotificationUI>,
    onDismiss: () -> Unit
) {
    val attackSummary = viewModel.getAttackSummary()
    val dateFormatter = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.8f),
            shape = RoundedCornerShape(16.dp),
            elevation = 8.dp
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
            ) {
                // Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,

                ) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = "Security",
                        tint = MaterialTheme.colors.primary,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "IDS Security Status",
                        style = MaterialTheme.typography.h6,
                        fontWeight = FontWeight.Bold
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Model Info
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    backgroundColor = Color(0xFFE8F5E9)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = "Active",
                            tint = Color(0xFF4CAF50),
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "Enhanced IDS v8.0",
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = "ONNX Model + Rule-based Detection",
                                fontSize = 12.sp,
                                color = Color.Gray
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Attack Summary
                if (attackSummary.isNotEmpty()) {
                    Text(
                        text = "Attack Summary",
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        attackSummary.forEach { (type, count) ->
                            AttackTypeCard(type = type, count = count)
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                }

                // Recent Attacks
                Text(
                    text = "Recent Attack Attempts",
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(bottom = 8.dp)
                )

                if (attackNotifications.isEmpty()) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        backgroundColor = Color(0xFFE8F5E9)
                    ) {
                        Text(
                            text = "No attacks detected",
                            modifier = Modifier.padding(16.dp),
                            color = Color(0xFF4CAF50)
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(attackNotifications.take(10)) { notification ->
                            AttackNotificationCard(
                                notification = notification,
                                dateFormatter = dateFormatter
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Actions
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = { viewModel.resetModel() }) {
                        Text("Clear History", color = Color.Red)
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(onClick = onDismiss) {
                        Text("Close")
                    }
                }
            }
        }
    }
}

@Composable
private fun AttackTypeCard(type: String, count: Int) {
    Card(
        modifier = Modifier.size(80.dp),
        backgroundColor = when (type) {
            "INJECTION" -> Color(0xFFFFE0B2)
            "SPOOFING" -> Color(0xFFFFCDD2)
            "FLOODING" -> Color(0xFFD7CCC8)
            "EXPLOIT" -> Color(0xFFE1BEE7)
            else -> Color.LightGray
        }
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                imageVector = when (type) {
                    "INJECTION" -> Icons.Default.Send
                    "SPOOFING" -> Icons.Default.AccountCircle
                    "FLOODING" -> Icons.Default.ArrowForward
                    "EXPLOIT" -> Icons.Default.AccountCircle
                    else -> Icons.Default.Warning
                },
                contentDescription = type,
                modifier = Modifier.size(24.dp)
            )
            Text(
                text = count.toString(),
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp
            )
            Text(
                text = type,
                fontSize = 10.sp
            )
        }
    }
}

@Composable
private fun AttackNotificationCard(
    notification: BluetoothViewModel.AttackNotificationUI,
    dateFormatter: SimpleDateFormat
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        backgroundColor = when (notification.severity) {
            BluetoothViewModel.AttackSeverity.CRITICAL -> Color(0xFFFFEBEE)
            BluetoothViewModel.AttackSeverity.HIGH -> Color(0xFFFFF3E0)
            BluetoothViewModel.AttackSeverity.MEDIUM -> Color(0xFFFFF8E1)
            BluetoothViewModel.AttackSeverity.LOW -> Color(0xFFF3E5F5)
        }
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = when (notification.attackType) {
                    "INJECTION" -> Icons.Default.Send
                    "SPOOFING" -> Icons.Default.Info
                    "FLOODING" -> Icons.Default.Close
                    "EXPLOIT" -> Icons.Default.Warning
                    else -> Icons.Default.Warning
                },
                contentDescription = notification.attackType,
                tint = when (notification.severity) {
                    BluetoothViewModel.AttackSeverity.CRITICAL -> Color.Red
                    BluetoothViewModel.AttackSeverity.HIGH -> Color(0xFFFF6F00)
                    BluetoothViewModel.AttackSeverity.MEDIUM -> Color(0xFFFFA000)
                    BluetoothViewModel.AttackSeverity.LOW -> Color(0xFF9C27B0)
                },
                modifier = Modifier.size(24.dp)
            )

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = notification.attackType,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
                Text(
                    text = notification.message,
                    fontSize = 12.sp,
                    color = Color.Gray
                )
                Text(
                    text = "From: ${notification.deviceName}",
                    fontSize = 11.sp,
                    color = Color.Gray
                )
            }

            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = dateFormatter.format(Date(notification.timestamp)),
                    fontSize = 10.sp,
                    color = Color.Gray
                )
                if (notification.actionTaken) {
                    Text(
                        text = "Blocked",
                        fontSize = 10.sp,
                        color = Color.Red,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}