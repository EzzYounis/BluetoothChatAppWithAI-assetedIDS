package com.plcoding.bluetoothchat.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Icon
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.plcoding.bluetoothchat.domain.chat.BluetoothMessage
import com.plcoding.bluetoothchat.ui.theme.BluetoothChatTheme
import com.plcoding.bluetoothchat.ui.theme.OldRose
import com.plcoding.bluetoothchat.ui.theme.Vanilla

@Composable
fun ChatMessage(
    message: BluetoothMessage,
    modifier: Modifier = Modifier
) {
    val isAttack = message.isAttack && !message.isFromLocalUser // Only show warning for incoming attacks

    Column(
        modifier = modifier
            .clip(
                RoundedCornerShape(
                    topStart = if (message.isFromLocalUser) 15.dp else 0.dp,
                    topEnd = 15.dp,
                    bottomStart = 15.dp,
                    bottomEnd = if (message.isFromLocalUser) 0.dp else 15.dp
                )
            )
            .then(
                if (isAttack) {
                    Modifier.border(
                        width = 2.dp,
                        color = Color.Red,
                        shape = RoundedCornerShape(
                            topStart = if (message.isFromLocalUser) 15.dp else 0.dp,
                            topEnd = 15.dp,
                            bottomStart = 15.dp,
                            bottomEnd = if (message.isFromLocalUser) 0.dp else 15.dp
                        )
                    )
                } else {
                    Modifier
                }
            )
            .background(
                when {
                    isAttack -> Color(0xFFFFE6E6) // Light red for attack messages
                    message.isFromLocalUser -> OldRose
                    else -> Vanilla
                }
            )
            .padding(16.dp)
    ) {
        // Attack warning header
        if (isAttack) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(bottom = 8.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = "Security Warning",
                    tint = Color.Red,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    text = "⚠️ SECURITY THREAT DETECTED",
                    fontSize = 12.sp,
                    color = Color.Red,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        // Sender name
        Text(
            text = message.senderName,
            fontSize = 10.sp,
            color = if (isAttack) Color.Red else Color.Black,
            fontWeight = if (isAttack) FontWeight.Bold else FontWeight.Normal
        )

        // Message content
        Text(
            text = message.message,
            color = if (isAttack) Color.Red.copy(alpha = 0.8f) else Color.Black,
            modifier = Modifier.widthIn(max = 250.dp)
        )

        // Attack type indicator
        if (isAttack) {
            Text(
                text = "🚨 Blocked for your safety",
                fontSize = 10.sp,
                color = Color.Red,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
    }
}

@Preview
@Composable
fun ChatMessagePreview() {
    BluetoothChatTheme {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            ChatMessage(
                message = BluetoothMessage(
                    message = "Hello World!",
                    senderName = "Pixel 6",
                    isFromLocalUser = false,
                    isAttack = false
                )
            )
            ChatMessage(
                message = BluetoothMessage(
                    message = "URGENT: Click this link http://malicious.com",
                    senderName = "Unknown Device",
                    isFromLocalUser = false,
                    isAttack = true
                )
            )
        }
    }
}