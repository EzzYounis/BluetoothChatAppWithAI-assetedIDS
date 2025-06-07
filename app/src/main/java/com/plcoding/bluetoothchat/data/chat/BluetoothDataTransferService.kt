package com.plcoding.bluetoothchat.data.chat

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.os.Environment
import android.util.Log
import androidx.core.content.ContextCompat
import com.plcoding.bluetoothchat.domain.chat.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean

class BluetoothDataTransferService(
    private val context: Context,
    private val socket: BluetoothSocket,
    private val messageLogDao: MessageLogDao? = null // Optional Room integration
) {
    // File logging configuration - now using txt extension and simplified path
    private val logDirectory by lazy {
        File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS), "BluetoothChatLogs").apply {
            if (!exists()) mkdirs()
        }
    }
    private val logFile by lazy {
        File(logDirectory, "bluetooth_messages_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.txt")
    }
    private val isLoggingEnabled = AtomicBoolean(true)

    @SuppressLint("MissingPermission")
    fun listenForIncomingMessages(): Flow<BluetoothMessage> = flow {
        val buffer = ByteArray(1024)
        while (true) {
            val byteCount = try {
                socket.inputStream.read(buffer)
            } catch (e: IOException) {
                if (socket.isConnected) throw TransferFailedException()
                else break
            }

            val messageText = buffer.decodeToString(endIndex = byteCount)
            val message = BluetoothMessage(
                message = messageText,
                senderName = socket.remoteDevice.name ?: "Unknown",
                isFromLocalUser = false
            )

            logMessage(
                fromDevice = socket.remoteDevice.name ?: "Unknown",
                toDevice = BluetoothAdapter.getDefaultAdapter()?.name ?: "Local",
                message = messageText,
                direction = "INCOMING"
            )

            emit(message)
        }
    }.flowOn(Dispatchers.IO)

    @SuppressLint("MissingPermission")
    suspend fun sendMessage(bytes: ByteArray): Boolean = withContext(Dispatchers.IO) {
        try {
            socket.outputStream.write(bytes)
            val message =     bytes.decodeToString()

            logMessage(
                fromDevice = BluetoothAdapter.getDefaultAdapter()?.name ?: "Local",
                toDevice = socket.remoteDevice.name ?: "Unknown",
                message = message,
                direction = "OUTGOING"
            )

            true
        } catch (e: IOException) {
            Log.e("BluetoothTransfer", "Message send failed", e)
            false
        }
    }

    private suspend fun logMessage(
        fromDevice: String,
        toDevice: String,
        message: String,
        direction: String
    ) {
        if (!isLoggingEnabled.get()) return

        try {
            val timestamp = System.currentTimeMillis()
            val dateTime = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
                .format(Date(timestamp))

            // Format the log entry with simplified structure
            val logEntry = """
                [$dateTime] $direction
                From: $fromDevice
                To: $toDevice
                Message: ${message.replace("\n", "\\n")}
                
                """.trimIndent()

            // Write to txt file
            logFile.appendText(logEntry)

            // Optional: Save to Room database
            messageLogDao?.insertMessage(
                MessageLog(
                    fromDevice = fromDevice,
                    toDevice = toDevice,
                    message = if (message.length > 500)
                        message.take(500) + "..." else message,
                    timestamp = timestamp
                )
            )
        } catch (e: Exception) {
            Log.e("BluetoothTransfer", "Logging failed", e)
        }
    }

    // File management utilities
    fun getLogFiles(): List<File> = logDirectory.listFiles()
        ?.filter { it.name.startsWith("bluetooth_messages_") && it.name.endsWith(".txt") }
        ?.sortedByDescending { it.lastModified() }
        ?: emptyList()

    fun exportLogs(targetDir: File): File? {
        return try {
            val exportFile = File(targetDir, "bluetooth_export_${System.currentTimeMillis()}.txt")
            logFile.copyTo(exportFile, overwrite = true)
            exportFile
        } catch (e: Exception) {
            Log.e("BluetoothTransfer", "Export failed", e)
            null
        }
    }

    fun clearLogs(olderThanDays: Int = 7) {
        val cutoff = System.currentTimeMillis() - (olderThanDays * 24 * 60 * 60 * 1000L)
        logDirectory.listFiles()?.forEach { file ->
            if (file.lastModified() < cutoff) {
                file.delete()
            }
        }
    }

    fun enableLogging(enable: Boolean) {
        isLoggingEnabled.set(enable)
    }

    companion object {
        fun getLogsDirectory(context: Context): File {
            return File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
                "BluetoothChatLogs").apply {
                if (!exists()) mkdirs()
            }
        }
    }
}