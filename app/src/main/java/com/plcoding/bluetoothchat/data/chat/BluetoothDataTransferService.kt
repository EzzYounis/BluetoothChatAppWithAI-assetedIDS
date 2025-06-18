package com.plcoding.bluetoothchat.data.chat

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.pm.PackageManager
import android.os.Environment
import android.util.Log
import androidx.core.app.ActivityCompat
import com.plcoding.bluetoothchat.domain.chat.*
import com.plcoding.bluetoothchat.presentation.IDS.IDSModel
import com.plcoding.bluetoothchat.presentation.SecurityAlert
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import java.io.File
import java.io.IOException
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
    private val idsModel: IDSModel = IDSModel(context)

    init {
        Log.d("BluetoothDataTransfer", "=== IDS SYSTEM INITIALIZED ===")
        Log.d("BluetoothDataTransfer", "Model: ${idsModel.modelName}")
        Log.d("BluetoothDataTransfer", "Monitoring: ACTIVE")
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
                        Log.d("BluetoothDataTransfer", "Connection closed by remote device")
                        break
                    }

                    val messageText = String(buffer, 0, byteCount, Charsets.UTF_8).trim()
                    if (messageText.isEmpty()) continue

                    val remoteDevice = socket.remoteDevice
                    val deviceName = remoteDevice?.name ?: "Unknown"
                    val deviceAddress = remoteDevice?.address ?: "Unknown"

                    Log.d("BluetoothDataTransfer", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                    Log.d("BluetoothDataTransfer", "📥 INCOMING MESSAGE")
                    Log.d("BluetoothDataTransfer", "From: $deviceName ($deviceAddress)")
                    Log.d("BluetoothDataTransfer", "Message: \"$messageText\"")
                    Log.d("BluetoothDataTransfer", "Length: ${messageText.length} chars")

                    // Log incoming message to file
                    logMessage(
                        fromDevice = deviceName,
                        toDevice = BluetoothAdapter.getDefaultAdapter()?.name ?: "Local",
                        message = messageText,
                        direction = "INCOMING"
                    )

                    // IDS Analysis
                    val analysisStartTime = System.currentTimeMillis()
                    val detectionResult = withContext(Dispatchers.Default) {
                        idsModel.analyzeMessage(
                            message = messageText,
                            fromDevice = deviceAddress,
                            toDevice = "local",
                            direction = "INCOMING"
                        )
                    }
                    val analysisTime = System.currentTimeMillis() - analysisStartTime

                    // Enhanced logging of IDS results
                    Log.d("BluetoothDataTransfer", "┌─── IDS ANALYSIS RESULTS ───")
                    Log.d("BluetoothDataTransfer", "│ Status: ${if (detectionResult.isAttack) "🚨 ATTACK DETECTED" else "✅ SAFE"}")
                    Log.d("BluetoothDataTransfer", "│ Attack Type: ${detectionResult.attackType}")
                    Log.d("BluetoothDataTransfer", "│ Confidence: ${String.format("%.1f", detectionResult.confidence * 100)}%")
                    Log.d("BluetoothDataTransfer", "│ Pattern Match: ${detectionResult.patternMatch}")
                    Log.d("BluetoothDataTransfer", "│ Explanation: ${detectionResult.explanation}")
                    Log.d("BluetoothDataTransfer", "│ Analysis Time: ${analysisTime}ms")
                    Log.d("BluetoothDataTransfer", "│ Should Notify: ${detectionResult.shouldNotify}")
                    Log.d("BluetoothDataTransfer", "└────────────────────────────")

                    if (detectionResult.isAttack) {
                        Log.w("BluetoothDataTransfer", "⚠️ SECURITY THREAT DETECTED ⚠️")
                        Log.w("BluetoothDataTransfer", "Attack Type: ${detectionResult.attackType}")
                        Log.w("BluetoothDataTransfer", "From Device: $deviceName ($deviceAddress)")

                        if (detectionResult.shouldNotify) {
                            // Send security alert to UI
                            onSecurityAlert(
                                SecurityAlert(
                                    attackType = detectionResult.attackType,
                                    deviceName = deviceName,
                                    deviceAddress = deviceAddress,
                                    message = messageText,
                                    detectionMethod = "Enhanced IDS v8.0",
                                    explanation = detectionResult.explanation
                                )
                            )

                            // DO NOT send alert back to attacker - this causes confusion
                            // The victim should see the alert in their UI, not the attacker
                            Log.d("BluetoothDataTransfer", "Security alert sent to UI")
                        } else {
                            Log.d("BluetoothDataTransfer", "Attack detected but notification suppressed (rate limiting)")
                        }
                    }

                    // Create message with attack info
                    val message = BluetoothMessage(
                        message = messageText,
                        senderName = deviceName,
                        isFromLocalUser = false,
                        isAttack = detectionResult.isAttack,
                        attackType = if (detectionResult.isAttack) detectionResult.attackType else "",
                        attackConfidence = if (detectionResult.isAttack) detectionResult.confidence else 0.0
                    )


                    emit(message)
                    Log.d("BluetoothDataTransfer", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

                } catch (e: IOException) {
                    if (e.message?.contains("bt socket closed") == true ||
                        e.message?.contains("Connection reset") == true) {
                        Log.i("BluetoothDataTransfer", "Socket closed during read operation")
                    } else {
                        Log.e("BluetoothDataTransfer", "Read error: ${e.message}")
                    }
                    break
                } catch (e: Exception) {
                    Log.e("BluetoothDataTransfer", "Unexpected error reading message", e)
                    continue
                }
            }
        } catch (e: Exception) {
            Log.e("BluetoothDataTransfer", "Error in message listening loop", e)
        } finally {
            Log.d("BluetoothDataTransfer", "Message listening stopped")
        }
    }.flowOn(Dispatchers.IO)

    @SuppressLint("MissingPermission")
    suspend fun sendMessage(bytes: ByteArray): Boolean = withContext(Dispatchers.IO) {
        if (!isSocketConnected.get() || !socket.isConnected) {
            Log.w("BluetoothDataTransfer", "Cannot send message - socket not connected")
            return@withContext false
        }

        try {
            val messageText = String(bytes, Charsets.UTF_8)
            val remoteDevice = socket.remoteDevice
            val deviceName = remoteDevice?.name ?: "Unknown"
            val deviceAddress = remoteDevice?.address ?: "Unknown"

            Log.d("BluetoothDataTransfer", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            Log.d("BluetoothDataTransfer", "📤 OUTGOING MESSAGE")
            Log.d("BluetoothDataTransfer", "To: $deviceName ($deviceAddress)")
            Log.d("BluetoothDataTransfer", "Message: \"$messageText\"")
            Log.d("BluetoothDataTransfer", "Length: ${messageText.length} chars")

            // Log the outgoing message
            logMessage(
                fromDevice = BluetoothAdapter.getDefaultAdapter()?.name ?: "Local",
                toDevice = deviceName,
                message = messageText,
                direction = "OUTGOING"
            )

            // Perform IDS analysis on outgoing message
            val analysisStartTime = System.currentTimeMillis()
            val detectionResult = idsModel.analyzeMessage(
                message = messageText,
                fromDevice = "local",
                toDevice = deviceAddress,
                direction = "OUTGOING"
            )
            val analysisTime = System.currentTimeMillis() - analysisStartTime

            // Log outgoing analysis results
            Log.d("BluetoothDataTransfer", "┌─── OUTGOING IDS ANALYSIS ───")
            Log.d("BluetoothDataTransfer", "│ Status: ${if (detectionResult.isAttack) "⚠️ SUSPICIOUS" else "✅ SAFE"}")
            Log.d("BluetoothDataTransfer", "│ Type: ${detectionResult.attackType}")
            Log.d("BluetoothDataTransfer", "│ Confidence: ${String.format("%.1f", detectionResult.confidence * 100)}%")
            Log.d("BluetoothDataTransfer", "│ Analysis Time: ${analysisTime}ms")
            Log.d("BluetoothDataTransfer", "└────────────────────────────")

            if (detectionResult.isAttack) {
                Log.w("BluetoothDataTransfer", "⚠️ WARNING: Outgoing message contains attack patterns!")
                Log.w("BluetoothDataTransfer", "Type: ${detectionResult.attackType}")
                // Note: We don't block outgoing messages, just log the warning
            }

            // Send the message
            socket.outputStream.write(bytes)
            socket.outputStream.flush()

            Log.d("BluetoothDataTransfer", "✓ Message sent successfully")
            Log.d("BluetoothDataTransfer", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

            return@withContext true

        } catch (e: IOException) {
            Log.e("BluetoothDataTransfer", "Message send failed: ${e.message}", e)
            // Close connection on IO error
            closeConnection()
            return@withContext false
        } catch (e: Exception) {
            Log.e("BluetoothDataTransfer", "Unexpected error sending message", e)
            return@withContext false
        }
    }

    fun closeConnection() {
        if (isSocketConnected.compareAndSet(true, false)) {
            try {
                socket.inputStream?.close()
                socket.outputStream?.close()
                socket.close()
                Log.i("BluetoothDataTransfer", "Socket closed gracefully")
            } catch (e: IOException) {
                if (e.message?.contains("closed") == true) {
                    Log.i("BluetoothDataTransfer", "Socket already closed")
                } else {
                    Log.e("BluetoothDataTransfer", "Error closing socket", e)
                }
            } finally {
                scope.cancel("Connection closed")
                Log.d("BluetoothDataTransfer", "=== IDS MONITORING STOPPED ===")
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

            // Enhanced log entry with IDS results
            val idsResult = withContext(Dispatchers.Default) {
                idsModel.analyzeMessage(message)
            }

            val logEntry = """
                [$dateTime] $direction
                From: $fromDevice
                To: $toDevice
                Message: ${message.replace("\n", "\\n")}
                IDS Result: ${if (idsResult.isAttack) "ATTACK DETECTED - ${idsResult.attackType}" else "SAFE"}
                Confidence: ${String.format("%.1f", idsResult.confidence * 100)}%
                
                """.trimIndent()

            withContext(Dispatchers.IO) {
                logFile.appendText(logEntry)
            }

            messageLogDao?.insertMessage(
                MessageLog(
                    fromDevice = fromDevice,
                    toDevice = toDevice,
                    message = if (message.length > 500) message.take(500) + "..." else message,
                    timestamp = timestamp
                )
            )
        } catch (e: Exception) {
            Log.e("BluetoothDataTransfer", "Logging failed", e)
        }
    }

    fun getLogFiles(): List<File> = logDirectory.listFiles()
        ?.filter { it.name.startsWith("bluetooth_messages_") && it.name.endsWith(".txt") }
        ?.sortedByDescending { it.lastModified() }
        ?: emptyList()

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
}