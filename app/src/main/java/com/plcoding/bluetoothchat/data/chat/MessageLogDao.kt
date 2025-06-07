package com.plcoding.bluetoothchat.data.chat

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.plcoding.bluetoothchat.domain.chat.MessageLog

@Dao
interface MessageLogDao {

    @Insert
    suspend fun insertMessage(messageLog: MessageLog)

    @Query("SELECT * FROM message_logs ORDER BY timestamp DESC")
    suspend fun getAllLogs(): List<MessageLog>
}
