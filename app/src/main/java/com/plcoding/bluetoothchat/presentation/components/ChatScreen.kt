@file:OptIn(ExperimentalComposeUiApi::class)

package com.plcoding.bluetoothchat.presentation.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Send
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.unit.dp
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

    Column(modifier = Modifier.fillMaxSize()) {
        // Header Row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(text = "Messages", modifier = Modifier.weight(1f))

            // Toggle Attack Menu Button
            IconButton(onClick = { showAttackButtons.value = !showAttackButtons.value }) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = "Attack Simulation",
                    tint = if (showAttackButtons.value) Color.Red else MaterialTheme.colors.onSurface
                )
            }

            IconButton(onClick = onDisconnect) {
                Icon(Icons.Default.Close, "Disconnect")
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
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            items(state.messages) { message ->
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
                placeholder = { Text("Message") }
            )
            IconButton(onClick = {
                onSendMessage(message.value)
                message.value = ""
                keyboardController?.hide()
            }) {
                Icon(Icons.Default.Send, "Send message")
            }
        }
    }
}

@Composable
private fun AttackButtonRow(viewModel: BluetoothViewModel) {
    val coroutineScope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text("Simulate Attacks:", style = MaterialTheme.typography.caption)

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Spoofing Attack Button
            Button(
                onClick = {
                    coroutineScope.launch {
                        viewModel.simulateAttack(BluetoothViewModel.AttackType.SPOOFING)
                    }
                },
                colors = ButtonDefaults.buttonColors(
                    backgroundColor = Color(0xFFFF6B6B),
                    contentColor = Color.White
                ),
                modifier = Modifier.weight(1f)
            ) {
                Text("Spoofing")
            }

            // Injection Attack Button
            Button(
                onClick = {
                    coroutineScope.launch {
                        viewModel.simulateAttack(BluetoothViewModel.AttackType.INJECTION)
                    }
                },
                colors = ButtonDefaults.buttonColors(
                    backgroundColor = Color(0xFFFFA500),
                    contentColor = Color.White
                ),
                modifier = Modifier.weight(1f)
            ) {
                Text("Injection")
            }

            // Flooding Attack Button
            Button(
                onClick = {
                    coroutineScope.launch {
                        viewModel.simulateAttack(BluetoothViewModel.AttackType.FLOODING)
                    }
                },
                colors = ButtonDefaults.buttonColors(
                    backgroundColor = Color(0xFF6B8E23),
                    contentColor = Color.White
                ),
                modifier = Modifier.weight(1f)
            ) {
                Text("Flooding")
            }
        }
    }
}