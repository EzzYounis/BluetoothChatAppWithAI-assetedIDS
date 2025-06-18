@file:OptIn(ExperimentalComposeUiApi::class)

package com.plcoding.bluetoothchat.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.ThumbUp
import androidx.compose.material.icons.filled.Warning
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.plcoding.bluetoothchat.presentation.BluetoothUiState
import com.plcoding.bluetoothchat.presentation.BluetoothViewModel
import kotlinx.coroutines.launch

@Composable
fun ChatScreen(
    state: BluetoothUiState,
    onDisconnect: () -> Unit,
    onSendMessage: (String) -> Unit,
    viewModel: BluetoothViewModel
) {
    val message = rememberSaveable { mutableStateOf("") }
    val keyboardController = LocalSoftwareKeyboardController.current
    val coroutineScope = rememberCoroutineScope()
    val showAttackButtons = remember { mutableStateOf(false) }
    val showIDSDialog = remember { mutableStateOf(false) }

    // Collect attack notifications and statistics
    val attackNotifications by viewModel.attackNotifications.collectAsState()
    val detectionExplanation by viewModel.detectionExplanation.collectAsState()
    val idsStatistics by viewModel.idsStatistics.collectAsState()

    // Calculate security status
    val attackCount = state.messages.count { it.isAttack && !it.isFromLocalUser }
    val totalMessages = state.messages.count { !it.isFromLocalUser }
    val securityStatus = when {
        attackCount == 0 -> SecurityStatus.SAFE
        attackCount.toFloat() / totalMessages.toFloat() < 0.1f -> SecurityStatus.WARNING
        else -> SecurityStatus.DANGER
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Header with Security Status
        Surface(
            modifier = Modifier.fillMaxWidth(),
            elevation = 4.dp,
            color = when (securityStatus) {
                SecurityStatus.SAFE -> Color(0xFF4CAF50)
                SecurityStatus.WARNING -> Color(0xFFFF9800)
                SecurityStatus.DANGER -> Color(0xFFF44336)
            }
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = when (securityStatus) {
                        SecurityStatus.SAFE -> Icons.Default.CheckCircle
                        SecurityStatus.WARNING -> Icons.Default.Warning
                        SecurityStatus.DANGER -> Icons.Default.Info
                    },
                    contentDescription = "Security Status",
                    tint = Color.White,
                    modifier = Modifier.size(24.dp)
                )

                Spacer(modifier = Modifier.width(8.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Bluetooth Chat",
                        color = Color.White,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = when (securityStatus) {
                            SecurityStatus.SAFE -> "Connection Secure"
                            SecurityStatus.WARNING -> "$attackCount attacks detected"
                            SecurityStatus.DANGER -> "⚠️ High threat level!"
                        },
                        color = Color.White,
                        fontSize = 12.sp
                    )
                }

                // IDS Status Indicator (Clickable)
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .background(Color.White.copy(alpha = 0.2f))
                        .clickable { showIDSDialog.value = true }
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(RoundedCornerShape(4.dp))
                            .background(Color(0xFF00FF00))
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "IDS Active",
                        color = Color.White,
                        fontSize = 10.sp
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                // Attack Menu Button
                IconButton(onClick = { showAttackButtons.value = !showAttackButtons.value }) {
                    Icon(
                        imageVector = Icons.Default.MoreVert,
                        contentDescription = "Menu",
                        tint = Color.White
                    )
                }

                // Disconnect Button
                IconButton(onClick = onDisconnect) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Disconnect",
                        tint = Color.White
                    )
                }
            }
        }

        // IDS Statistics Bar
        Surface(
            modifier = Modifier.fillMaxWidth(),
            color = Color(0xFFE3F2FD),
            elevation = 2.dp
        ) {}

        // Attack Statistics Bar (if attacks detected)
        if (attackCount > 0) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = Color(0xFFFFF3CD),
                elevation = 2.dp
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.ThumbUp,
                        contentDescription = "Shield",
                        tint = Color(0xFF856404),
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text(
                            text = "IDS blocked $attackCount malicious messages",
                            color = Color(0xFF856404),
                            fontSize = 14.sp
                        )
                        // Show attack breakdown
                        val attackBreakdown = idsStatistics.attacksDetected.entries.joinToString(" • ") {
                            "${it.key}: ${it.value}"
                        }
                        if (attackBreakdown.isNotEmpty()) {
                            Text(
                                text = attackBreakdown,
                                color = Color(0xFF856404),
                                fontSize = 12.sp
                            )
                        }
                    }
                }
            }
        }

        // Detection Explanation (if available)
        detectionExplanation?.let { explanation ->
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                color = Color(0xFFE3F2FD),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text(
                    text = explanation,
                    modifier = Modifier.padding(12.dp),
                    fontSize = 12.sp,
                    color = Color(0xFF1565C0)
                )
            }
        }

        // Attack Test Buttons (toggleable)
        if (showAttackButtons.value) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = Color(0xFFFFEBEE),
                elevation = 2.dp
            ) {
                Column(modifier = Modifier.padding(8.dp)) {
                    Text(
                        text = "IDS Test Controls",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        Button(
                            onClick = { viewModel.simulateAttack(BluetoothViewModel.AttackType.SPOOFING) },
                            colors = ButtonDefaults.buttonColors(backgroundColor = Color(0xFFFF9800)),
                            modifier = Modifier.height(36.dp)
                        ) {
                            Text("Spoofing", fontSize = 12.sp)
                        }
                        Button(
                            onClick = { viewModel.simulateAttack(BluetoothViewModel.AttackType.INJECTION) },
                            colors = ButtonDefaults.buttonColors(backgroundColor = Color(0xFFF44336)),
                            modifier = Modifier.height(36.dp)
                        ) {
                            Text("Injection", fontSize = 12.sp)
                        }
                        Button(
                            onClick = { viewModel.simulateAttack(BluetoothViewModel.AttackType.FLOODING) },
                            colors = ButtonDefaults.buttonColors(backgroundColor = Color(0xFF9C27B0)),
                            modifier = Modifier.height(36.dp)
                        ) {
                            Text("Flooding", fontSize = 12.sp)
                        }
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        Button(
                            onClick = { viewModel.testIDSSystem() },
                            colors = ButtonDefaults.buttonColors(backgroundColor = Color(0xFF2196F3)),
                            modifier = Modifier.height(36.dp)
                        ) {
                            Text("Run Tests", fontSize = 12.sp)
                        }
                        Button(
                            onClick = { viewModel.resetModel() },
                            colors = ButtonDefaults.buttonColors(backgroundColor = Color(0xFF607D8B)),
                            modifier = Modifier.height(36.dp)
                        ) {
                            Text("Reset IDS", fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        // Messages List
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(state.messages) { message ->
                Column(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    // Show attack warning for malicious messages
                    if (message.isAttack && !message.isFromLocalUser) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 4.dp),
                            horizontalArrangement = if (message.isFromLocalUser) Arrangement.End else Arrangement.Start
                        ) {
                            Surface(
                                color = when (message.attackType) {
                                    "SPOOFING" -> Color(0xFFFF9800)
                                    "INJECTION" -> Color(0xFFF44336)
                                    "FLOODING" -> Color(0xFF9C27B0)
                                    "EXPLOIT" -> Color(0xFFE91E63)
                                    else -> Color(0xFF607D8B)
                                },
                                shape = RoundedCornerShape(12.dp),
                                elevation = 2.dp
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Warning,
                                        contentDescription = "Attack",
                                        tint = Color.White,
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = "${message.attackType} BLOCKED (${String.format("%.0f", message.attackConfidence * 100)}%)",
                                        color = Color.White,
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                        }
                    }

                    // Message bubble
                    ChatMessage(
                        message = message,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        // Message Input
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextField(
                value = message.value,
                onValueChange = { message.value = it },
                placeholder = { Text("Message") },
                modifier = Modifier.weight(1f),
                colors = TextFieldDefaults.textFieldColors(
                    backgroundColor = Color.LightGray.copy(alpha = 0.3f)
                )
            )
            Spacer(modifier = Modifier.width(8.dp))
            IconButton(
                onClick = {
                    if (message.value.isNotBlank()) {
                        onSendMessage(message.value)
                        message.value = ""
                        keyboardController?.hide()
                    }
                }
            ) {
                Icon(
                    imageVector = Icons.Default.Send,
                    contentDescription = "Send message",
                    tint = MaterialTheme.colors.primary
                )
            }
        }
    }

    // IDS Statistics Dialog
    if (showIDSDialog.value) {
        AlertDialog(
            onDismissRequest = { showIDSDialog.value = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = "IDS",
                        tint = Color(0xFF1976D2)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("IDS Statistics")
                }
            },
            text = {
                Column {
                    // Model Status
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("Model Status:", fontWeight = FontWeight.Bold)
                        Text(
                            text = idsStatistics.modelStatus,
                            color = Color(0xFF4CAF50),
                            fontWeight = FontWeight.Bold
                        )
                    }

                    Divider(modifier = Modifier.padding(vertical = 8.dp))

                    // Statistics
                    StatisticRow("Total Messages:", idsStatistics.totalMessages.toString())
                    StatisticRow("Message Rate:", "${String.format("%.1f", idsStatistics.messageRate)} msg/min")
                    StatisticRow("Attack Rate:", "${String.format("%.1f", idsStatistics.detectionRate)}%")
                    StatisticRow("Total Attacks:", idsStatistics.attacksDetected.values.sum().toString())

                    Divider(modifier = Modifier.padding(vertical = 8.dp))

                    // Attack Breakdown
                    Text("Attack Breakdown:", fontWeight = FontWeight.Bold)
                    idsStatistics.attacksDetected.forEach { (type, count) ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(start = 16.dp, top = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(type, fontSize = 14.sp)
                            Text(
                                count.toString(),
                                fontWeight = FontWeight.Bold,
                                color = when(type) {
                                    "INJECTION" -> Color(0xFFF44336)
                                    "SPOOFING" -> Color(0xFFFF9800)
                                    "FLOODING" -> Color(0xFF9C27B0)
                                    "EXPLOIT" -> Color(0xFFE91E63)
                                    else -> Color.Black
                                }
                            )
                        }
                    }

                    Divider(modifier = Modifier.padding(vertical = 8.dp))

                    // Recent Notifications
                    if (attackNotifications.isNotEmpty()) {
                        Text("Recent Alerts:", fontWeight = FontWeight.Bold)
                        attackNotifications.take(3).forEach { notification ->
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 4.dp),
                                backgroundColor = when(notification.severity) {
                                    BluetoothViewModel.AttackSeverity.CRITICAL -> Color(0xFFFFEBEE)
                                    BluetoothViewModel.AttackSeverity.HIGH -> Color(0xFFFFF3E0)
                                    BluetoothViewModel.AttackSeverity.MEDIUM -> Color(0xFFE3F2FD)
                                    BluetoothViewModel.AttackSeverity.LOW -> Color(0xFFE8F5E9)
                                }
                            ) {
                                Column(modifier = Modifier.padding(8.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            notification.attackType,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 12.sp
                                        )
                                        Text(
                                            formatTime(System.currentTimeMillis() - notification.timestamp),
                                            fontSize = 10.sp,
                                            color = Color.Gray
                                        )
                                    }
                                    Text(
                                        notification.message,
                                        fontSize = 11.sp,
                                        maxLines = 2
                                    )
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {
                Button(onClick = { showIDSDialog.value = false }) {
                    Text("Close")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    coroutineScope.launch {
                        viewModel.resetModel()
                        showIDSDialog.value = false
                    }
                }) {
                    Text("Reset Stats", color = Color.Red)
                }
            }
        )
    }
}

@Composable
private fun StatisticRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 14.sp)
        Text(value, fontWeight = FontWeight.Bold, fontSize = 14.sp)
    }
}

private fun formatTime(millisAgo: Long): String {
    return when {
        millisAgo < 60000 -> "${millisAgo / 1000}s ago"
        millisAgo < 3600000 -> "${millisAgo / 60000}m ago"
        else -> "${millisAgo / 3600000}h ago"
    }
}

private enum class SecurityStatus {
    SAFE, WARNING, DANGER
}