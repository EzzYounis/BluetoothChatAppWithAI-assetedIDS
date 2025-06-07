package com.plcoding.bluetoothchat.data.chat

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Environment
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.plcoding.bluetoothchat.domain.chat.*
import com.plcoding.bluetoothchat.presentation.IDS.BluetoothFeatureExtractor
import com.plcoding.bluetoothchat.presentation.IDS.IDSModel
import com.plcoding.bluetoothchat.presentation.SecurityAlert
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean

class BluetoothDataTransferService(
    private val context: Context,
    private val socket: BluetoothSocket,
    private val messageLogDao: MessageLogDao? = null,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
    private val onSecurityAlert: (SecurityAlert) -> Unit,
    private val isSocketConnected: AtomicBoolean = AtomicBoolean(true)
) {
    // File logging configuration
    private val logDirectory by lazy {
        File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            "BluetoothChatLogs").apply {
            if (!exists()) mkdirs()
        }
    }
    private val logFile by lazy {
        File(logDirectory, "bluetooth_messages_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.txt")
    }
    private val isLoggingEnabled = AtomicBoolean(true)

    // IDS Components
    private val featureExtractor = BluetoothFeatureExtractor()
    private lateinit var idsModel: IDSModel
    private val modelInitialized = AtomicBoolean(false)

    // Message channel for proper flow handling
    private val messageChannel = Channel<BluetoothMessage>(Channel.UNLIMITED)

    init {
        initIDSModel()
    }

    private fun initIDSModel() {
        scope.launch(Dispatchers.IO) {
            try {
                idsModel = IDSModel(context)
                modelInitialized.set(true)
                Log.d("IDS", "Intrusion Detection Model loaded successfully")
            } catch (e: Exception) {
                Log.e("IDS", "Failed to initialize IDS model", e)
            }
        }
    }

    @SuppressLint("MissingPermission")
    fun listenForIncomingMessages(): Flow<BluetoothMessage> = flow {
        val buffer = ByteArray(1024)
        val inputStream = socket.inputStream

        try {
            while (isSocketConnected.get() && socket.isConnected) {
                try {
                    val byteCount = inputStream.read(buffer)

                    if (byteCount <= 0) {
                        Log.d("BluetoothService", "Connection closed by remote device")
                        break
                    }

                    val messageText = String(buffer, 0, byteCount, Charsets.UTF_8).trim()
                    if (messageText.isEmpty()) continue

                    val remoteDevice = socket.remoteDevice
                    Log.d("BluetoothService", "Received message: $messageText from ${remoteDevice?.name}")

                    // Log incoming message
                    logMessage(
                        fromDevice = remoteDevice?.name ?: "Unknown",
                        toDevice = BluetoothAdapter.getDefaultAdapter()?.name ?: "Local",
                        message = messageText,
                        direction = "INCOMING"
                    )

                    var detectionResult: IDSModel.AnalysisResult? = null

                    // IDS Analysis
                    if (modelInitialized.get()) {
                        detectionResult = idsModel.analyzeMessage(messageText)

                        if (detectionResult.isAttack) {
                            handleSecurityAlert(detectionResult, messageText)

                            // Send alert back to sender
                            try {
                                val alertMsg = """
                                    [SECURITY ALERT]
                                    Your message was blocked
                                    Reason: ${detectionResult.attackType}
                                    Detected by: ${if (detectionResult.aiDetected) "AI" else "rules"}
                                """.trimIndent()

                                socket.outputStream.write(alertMsg.toByteArray(Charsets.UTF_8))
                                socket.outputStream.flush()
                            } catch (e: Exception) {
                                Log.e("BluetoothService", "Failed to send security alert", e)
                            }
                        }
                    }

                    val message = BluetoothMessage(
                        message = messageText,
                        senderName = remoteDevice?.name ?: "Unknown",
                        isFromLocalUser = false,
                        isAttack = detectionResult?.isAttack ?: false
                    )

                    emit(message)

                } catch (e: IOException) {
                    if (e.message?.contains("bt socket closed") == true ||
                        e.message?.contains("Connection reset") == true) {
                        Log.i("BluetoothService", "Socket closed during read operation")
                    } else {
                        Log.e("BluetoothService", "Read error: ${e.message}")
                    }
                    break
                } catch (e: Exception) {
                    Log.e("BluetoothService", "Unexpected error reading message", e)
                    continue
                }
            }
        } catch (e: Exception) {
            Log.e("BluetoothService", "Error in message listening loop", e)
        } finally {
            Log.d("BluetoothService", "Message listening stopped")
        }
    }.flowOn(Dispatchers.IO)

    private fun handleSecurityAlert(result: IDSModel.AnalysisResult, message: String) {
        val device = socket.remoteDevice
        if (ActivityCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_CONNECT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        onSecurityAlert(
            SecurityAlert(
                attackType = result.attackType,
                deviceName = device?.name ?: "Unknown",
                deviceAddress = device?.address ?: "Unknown",
                message = message,
                detectionMethod = if (result.aiDetected) "AI Model" else "Rule-based",
                explanation = result.explanation
            )
        )
    }

    @SuppressLint("MissingPermission")
    suspend fun sendMessage(bytes: ByteArray): Boolean = withContext(Dispatchers.IO) {
        if (!isSocketConnected.get() || !socket.isConnected) {
            Log.w("BluetoothTransfer", "Cannot send message - socket not connected")
            return@withContext false
        }

        try {
            val messageText = String(bytes, Charsets.UTF_8)
            val remoteDevice = socket.remoteDevice

            Log.d("BluetoothTransfer", "Sending message: $messageText to ${remoteDevice?.name}")

            // Log the outgoing message
            logMessage(
                fromDevice = BluetoothAdapter.getDefaultAdapter()?.name ?: "Local",
                toDevice = remoteDevice?.name ?: "Unknown",
                message = messageText,
                direction = "OUTGOING"
            )

            // Perform IDS analysis before sending
            if (modelInitialized.get()) {
                val detectionResult = idsModel.analyzeMessage(messageText)
                if (detectionResult.isAttack) {
                    handleSecurityAlert(detectionResult, messageText)
                    if (shouldBlockMessage(detectionResult)) {
                        Log.w("BluetoothTransfer", "Message blocked by IDS: ${detectionResult.attackType}")
                        return@withContext false
                    }
                }
            }

            // Send the message with proper encoding
            socket.outputStream.write(bytes)
            socket.outputStream.flush()

            Log.d("BluetoothTransfer", "Message sent successfully")
            return@withContext true

        } catch (e: IOException) {
            Log.e("BluetoothTransfer", "Message send failed: ${e.message}", e)
            // Close connection on IO error
            closeConnection()
            return@withContext false
        } catch (e: Exception) {
            Log.e("BluetoothTransfer", "Unexpected error sending message", e)
            return@withContext false
        }
    }

    private fun shouldBlockMessage(result: IDSModel.AnalysisResult): Boolean {
        return when (result.attackType) {
            "SPOOFING", "INJECTION", "FLOODING" -> true
            else -> false
        }
    }

    fun closeConnection() {
        if (isSocketConnected.compareAndSet(true, false)) {
            try {
                messageChannel.close()
                socket.inputStream?.close()
                socket.outputStream?.close()
                socket.close()
                Log.i("BluetoothService", "Socket closed gracefully")
            } catch (e: IOException) {
                if (e.message?.contains("closed") == true) {
                    Log.i("BluetoothService", "Socket already closed")
                } else {
                    Log.e("BluetoothService", "Error closing socket", e)
                }
            } finally {
                scope.cancel("Connection closed")
            }
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

            val logEntry = """
                [$dateTime] $direction
                From: $fromDevice
                To: $toDevice
                Message: ${message.replace("\n", "\\n")}
                
                """.trimIndent()

            logFile.appendText(logEntry)

            messageLogDao?.insertMessage(
                MessageLog(
                    fromDevice = fromDevice,
                    toDevice = toDevice,
                    message = if (message.length > 500) message.take(500) + "..." else message,
                    timestamp = timestamp
                )
            )
        } catch (e: Exception) {
            Log.e("BluetoothTransfer", "Logging failed", e)
        }
    }

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
        closeConnection()
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