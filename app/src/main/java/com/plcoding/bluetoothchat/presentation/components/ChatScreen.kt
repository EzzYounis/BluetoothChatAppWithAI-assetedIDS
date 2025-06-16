@file:OptIn(ExperimentalComposeUiApi::class)

package com.plcoding.bluetoothchat.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
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

    // Collect attack notifications
    val attackNotifications by viewModel.attackNotifications.collectAsState()
    val detectionExplanation by viewModel.detectionExplanation.collectAsState()

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

                // IDS Status Indicator
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .background(Color.White.copy(alpha = 0.2f))
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
                    Text(
                        text = "IDS blocked $attackCount malicious messages",
                        color = Color(0xFF856404),
                        fontSize = 14.sp
                    )
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
                    color = Color(0xFF1976D2)
                )
            }
        }

        // Attack Buttons (conditionally shown)
        if (showAttackButtons.value) {
            AttackButtonRow(viewModel)
        }

        // Messages List
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            reverseLayout = true // Show newest messages at bottom
        ) {
            items(state.messages.reversed()) { message ->
                Column(modifier = Modifier.fillMaxWidth()) {
                    ChatMessage(
                        message = message,
                        modifier = Modifier.align(
                            if (message.isFromLocalUser) Alignment.End else Alignment.Start
                        )
                    )
                }
            }
        }

        // Message Input Row
        Surface(
            modifier = Modifier.fillMaxWidth(),
            elevation = 8.dp
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextField(
                    value = message.value,
                    onValueChange = { message.value = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("Type a message...") },
                    colors = TextFieldDefaults.textFieldColors(
                        backgroundColor = Color.Transparent
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
                    },
                    enabled = message.value.isNotBlank()
                ) {
                    Icon(
                        imageVector = Icons.Default.Send,
                        contentDescription = "Send message",
                        tint = if (message.value.isNotBlank())
                            MaterialTheme.colors.primary
                        else
                            Color.Gray
                    )
                }
            }
        }
    }
}

enum class SecurityStatus {
    SAFE, WARNING, DANGER
}

@Composable
private fun AttackButtonRow(viewModel: BluetoothViewModel) {
    val coroutineScope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFFF5F5F5))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                "Test Attacks:",
                style = MaterialTheme.typography.subtitle2,
                fontWeight = FontWeight.Bold
            )
            IconButton(
                onClick = { coroutineScope.launch { viewModel.testIDSSystem() } },
                modifier = Modifier.size(36.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Build,
                    contentDescription = "Test IDS",
                    tint = Color(0xFF4CAF50)
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Spoofing Attack Button
            OutlinedButton(
                onClick = {
                    coroutineScope.launch {
                        viewModel.simulateAttack(BluetoothViewModel.AttackType.SPOOFING)
                    }
                },
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color(0xFFFF6B6B)
                ),
                modifier = Modifier.weight(1f)
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.AccountBox,
                        contentDescription = "Spoofing",
                        modifier = Modifier.size(20.dp)
                    )
                    Text("Spoofing", fontSize = 10.sp)
                }
            }

            // Injection Attack Button
            OutlinedButton(
                onClick = {
                    coroutineScope.launch {
                        viewModel.simulateAttack(BluetoothViewModel.AttackType.INJECTION)
                    }
                },
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color(0xFFFFA500)
                ),
                modifier = Modifier.weight(1f)
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.Add,
                        contentDescription = "Injection",
                        modifier = Modifier.size(20.dp)
                    )
                    Text("Injection", fontSize = 10.sp)
                }
            }

            // Flooding Attack Button
            OutlinedButton(
                onClick = {
                    coroutineScope.launch {
                        viewModel.simulateAttack(BluetoothViewModel.AttackType.FLOODING)
                    }
                },
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color(0xFF6B8E23)
                ),
                modifier = Modifier.weight(1f)
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Flooding",
                        modifier = Modifier.size(20.dp)
                    )
                    Text("Flooding", fontSize = 10.sp)
                }
            }
        }
    }
}