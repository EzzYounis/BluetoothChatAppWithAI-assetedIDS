package com.plcoding.bluetoothchat.data.chat

import IDS.BluetoothFeatureExtractor
import IDS.IDSModelHelper
import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.Intent
import android.os.Environment
import android.util.Log
import androidx.core.content.ContextCompat
import com.plcoding.bluetoothchat.domain.chat.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean

class BluetoothDataTransferService(
    private val context: Context,
    private val socket: BluetoothSocket,
    private val messageLogDao: MessageLogDao? = null, // Optional Room integration
    private val idsModel: IDSModelHelper = IDSModelHelper(context),
    private val featureExtractor: BluetoothFeatureExtractor = BluetoothFeatureExtractor(),
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.Default + SupervisorJob())



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
            val remoteDevice = socket.remoteDevice
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
            scope.launch {
                detectIntrusion(
                    message = messageText,
                    device = remoteDevice.address,
                    deviceName = remoteDevice.name ?: "Unknown",
                    direction = "INCOMING"
                )
            }

            emit(message)
        }
    }.flowOn(Dispatchers.IO)

    @SuppressLint("MissingPermission")
    suspend fun sendMessage(bytes: ByteArray): Boolean = withContext(Dispatchers.IO) {
        try {
            socket.outputStream.write(bytes)
            val message =     bytes.decodeToString()
            val remoteDevice = socket.remoteDevice


            logMessage(
                fromDevice = BluetoothAdapter.getDefaultAdapter()?.name ?: "Local",
                toDevice = socket.remoteDevice.name ?: "Unknown",
                message = message,
                direction = "OUTGOING"
            )
            scope.launch {
                detectIntrusion(
                    message = message,
                    device = remoteDevice.address,
                    deviceName = remoteDevice.name ?: "Unknown",
                    direction = "OUTGOING"
                )
            }

            true
        } catch (e: IOException) {
            Log.e("BluetoothTransfer", "Message send failed", e)
            false
        }
    }
    private suspend fun detectIntrusion(
        message: String,
        device: String,
        deviceName: String,
        direction: String
    ) {
        try {
            val features = featureExtractor.extractFeatures(
                message = message,
                timestamp = System.currentTimeMillis(),
                device = device,
                direction = direction
            )

            idsModel.predict(features)?.let { (prediction, _) ->
                if (prediction != "normal") {
                    notifySecurityAlert(prediction, message, device, deviceName)
                }
            }
        } catch (e: Exception) {
            Log.e("BluetoothIDS", "Intrusion detection failed", e)
        }
    }
    private fun notifySecurityAlert(
        attackType: String,
        message: String,
        deviceAddress: String,
        deviceName: String
    ) {
        val intent = Intent("SECURITY_ALERT").apply {
            putExtra("ATTACK_TYPE", attackType)
            putExtra("MESSAGE", message)
            putExtra("DEVICE_ADDRESS", deviceAddress)
            putExtra("DEVICE_NAME", deviceName)
        }
        context.sendBroadcast(intent) // Regular broadcast instead of local
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
    fun close() {
        scope.cancel()
        idsModel.shutdown()
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