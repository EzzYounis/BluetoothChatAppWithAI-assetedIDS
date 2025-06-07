package com.plcoding.bluetoothchat.domain.chat

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "message_logs")
data class MessageLog(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val fromDevice: String,
    val toDevice: String,
    val message: String,
    val timestamp: Long
)
