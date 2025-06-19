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
    private val detailedLogFile by lazy {
        File(logDirectory, "ids_detailed_analysis_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.txt")
    }
    private val isLoggingEnabled = AtomicBoolean(true)

    // IDS Components
    private val idsModel: IDSModel = IDSModel(context)

    init {
        Log.d("BluetoothDataTransfer", "=== IDS SYSTEM INITIALIZED ===")
        Log.d("BluetoothDataTransfer", "Model: ${idsModel.modelName}")
        Log.d("BluetoothDataTransfer", "Monitoring: ACTIVE")

        // Initialize log files with headers
        initializeLogFiles()
    }

    private fun initializeLogFiles() {
        try {
            // Main log file header
            logFile.appendText("""
                =====================================
                BLUETOOTH IDS MONITORING LOG
                Started: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}
                Model: ${idsModel.modelName}
                Device: ${android.os.Build.MODEL}
                =====================================
                
            """.trimIndent())

            // Detailed analysis log header
            detailedLogFile.appendText("""
                =====================================
                IDS DETAILED ANALYSIS LOG
                Started: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}
                =====================================
                
            """.trimIndent())
        } catch (e: Exception) {
            Log.e("BluetoothDataTransfer", "Failed to initialize log files", e)
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
                        Log.d("BluetoothDataTransfer", "Connection closed by remote device")
                        break
                    }

                    val messageText = String(buffer, 0, byteCount, Charsets.UTF_8).trim()
                    if (messageText.isEmpty()) continue

                    val remoteDevice = socket.remoteDevice
                    val deviceName = remoteDevice?.name ?: "Unknown"
                    val deviceAddress = remoteDevice?.address ?: "Unknown"

                    // Enhanced logging with box drawing characters
                    val timestamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())

                    Log.d("BluetoothDataTransfer", "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                    Log.d("BluetoothDataTransfer", "┃ 📥 INCOMING MESSAGE ANALYSIS")
                    Log.d("BluetoothDataTransfer", "┃ Time: $timestamp")
                    Log.d("BluetoothDataTransfer", "┃ From: $deviceName ($deviceAddress)")
                    Log.d("BluetoothDataTransfer", "┃ Message: \"$messageText\"")
                    Log.d("BluetoothDataTransfer", "┃ Length: ${messageText.length} chars | Bytes: $byteCount")
                    Log.d("BluetoothDataTransfer", "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

                    // Log incoming message to file
                    logMessage(
                        fromDevice = deviceName,
                        toDevice = BluetoothAdapter.getDefaultAdapter()?.name ?: "Local",
                        message = messageText,
                        direction = "INCOMING"
                    )

                    // IDS Analysis with detailed timing
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

                    // Enhanced logging of IDS results with visual indicators
                    val statusIcon = if (detectionResult.isAttack) "🚨" else "✅"
                    val statusColor = if (detectionResult.isAttack) "ATTACK DETECTED" else "SAFE"

                    Log.d("BluetoothDataTransfer", "┏━━━ IDS ANALYSIS RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                    Log.d("BluetoothDataTransfer", "┃ $statusIcon Status: $statusColor")
                    Log.d("BluetoothDataTransfer", "┃ 🎯 Attack Type: ${detectionResult.attackType}")
                    Log.d("BluetoothDataTransfer", "┃ 📊 Confidence: ${String.format("%.1f", detectionResult.confidence * 100)}%")
                    Log.d("BluetoothDataTransfer", "┃ 🔍 Pattern Match: ${detectionResult.patternMatch}")
                    Log.d("BluetoothDataTransfer", "┃ 💡 Explanation: ${detectionResult.explanation}")
                    Log.d("BluetoothDataTransfer", "┃ ⏱️ Analysis Time: ${analysisTime}ms")
                    Log.d("BluetoothDataTransfer", "┃ 🔔 Should Notify: ${detectionResult.shouldNotify}")
                    Log.d("BluetoothDataTransfer", "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

                    // Log detailed analysis to file
                    logDetailedAnalysis(
                        timestamp = timestamp,
                        deviceName = deviceName,
                        deviceAddress = deviceAddress,
                        message = messageText,
                        detectionResult = detectionResult,
                        analysisTime = analysisTime
                    )

                    if (detectionResult.isAttack) {
                        Log.w("BluetoothDataTransfer", "┏━━━ ⚠️ SECURITY THREAT DETECTED ⚠️ ━━━━━━━━━━━━━━━━━━━━━━━━━")
                        Log.w("BluetoothDataTransfer", "┃ Attack Type: ${detectionResult.attackType}")
                        Log.w("BluetoothDataTransfer", "┃ From Device: $deviceName ($deviceAddress)")
                        Log.w("BluetoothDataTransfer", "┃ Threat Level: ${getThreatLevel(detectionResult.confidence)}")
                        Log.w("BluetoothDataTransfer", "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

                        if (detectionResult.shouldNotify) {
                            // Send security alert to UI
                            onSecurityAlert(
                                SecurityAlert(
                                    attackType = detectionResult.attackType,
                                    deviceName = deviceName,
                                    deviceAddress = deviceAddress,
                                    message = messageText,
                                    detectionMethod = "Enhanced IDS v9.0",
                                    explanation = detectionResult.explanation
                                )
                            )

                            Log.d("BluetoothDataTransfer", "📢 Security alert sent to UI")
                        } else {
                            Log.d("BluetoothDataTransfer", "🔇 Attack detected but notification suppressed (rate limiting)")
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

                    // Log performance metrics periodically
                    logPerformanceMetrics()

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
            logFinalStatistics()
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
            val timestamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())

            Log.d("BluetoothDataTransfer", "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            Log.d("BluetoothDataTransfer", "┃ 📤 OUTGOING MESSAGE ANALYSIS")
            Log.d("BluetoothDataTransfer", "┃ Time: $timestamp")
            Log.d("BluetoothDataTransfer", "┃ To: $deviceName ($deviceAddress)")
            Log.d("BluetoothDataTransfer", "┃ Message: \"$messageText\"")
            Log.d("BluetoothDataTransfer", "┃ Length: ${messageText.length} chars")
            Log.d("BluetoothDataTransfer", "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

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
            Log.d("BluetoothDataTransfer", "┏━━━ OUTGOING IDS ANALYSIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            Log.d("BluetoothDataTransfer", "┃ Status: ${if (detectionResult.isAttack) "⚠️ SUSPICIOUS" else "✅ SAFE"}")
            Log.d("BluetoothDataTransfer", "┃ Type: ${detectionResult.attackType}")
            Log.d("BluetoothDataTransfer", "┃ Confidence: ${String.format("%.1f", detectionResult.confidence * 100)}%")
            Log.d("BluetoothDataTransfer", "┃ Analysis Time: ${analysisTime}ms")
            Log.d("BluetoothDataTransfer", "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

            if (detectionResult.isAttack) {
                Log.w("BluetoothDataTransfer", "⚠️ WARNING: Outgoing message contains attack patterns!")
                Log.w("BluetoothDataTransfer", "Type: ${detectionResult.attackType}")
                // Note: We don't block outgoing messages, just log the warning
            }

            // Send the message
            socket.outputStream.write(bytes)
            socket.outputStream.flush()

            Log.d("BluetoothDataTransfer", "✓ Message sent successfully")

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

    private fun getThreatLevel(confidence: Double): String {
        return when {
            confidence >= 0.9 -> "CRITICAL"
            confidence >= 0.7 -> "HIGH"
            confidence >= 0.5 -> "MEDIUM"
            else -> "LOW"
        }
    }

    private suspend fun logDetailedAnalysis(
        timestamp: String,
        deviceName: String,
        deviceAddress: String,
        message: String,
        detectionResult: IDSModel.AnalysisResult,
        analysisTime: Long
    ) {
        if (!isLoggingEnabled.get()) return

        try {
            val logEntry = buildString {
                appendLine("=====================================")
                appendLine("TIMESTAMP: $timestamp")
                appendLine("DEVICE: $deviceName ($deviceAddress)")
                appendLine("MESSAGE: $message")
                appendLine("-------------------------------------")
                appendLine("ANALYSIS RESULTS:")
                appendLine("  Status: ${if (detectionResult.isAttack) "ATTACK DETECTED" else "SAFE"}")
                appendLine("  Attack Type: ${detectionResult.attackType}")
                appendLine("  Confidence: ${String.format("%.1f", detectionResult.confidence * 100)}%")
                appendLine("  Pattern Match: ${detectionResult.patternMatch}")
                appendLine("  Explanation: ${detectionResult.explanation}")
                appendLine("  Analysis Time: ${analysisTime}ms")
                appendLine("=====================================")
                appendLine()
            }

            withContext(Dispatchers.IO) {
                detailedLogFile.appendText(logEntry)
            }
        } catch (e: Exception) {
            Log.e("BluetoothDataTransfer", "Failed to log detailed analysis", e)
        }
    }

    private fun logPerformanceMetrics() {
        // Log performance metrics every 50 messages
        val stats = idsModel.getStatistics()
        if (stats.contains("Total Messages") && stats.contains("50")) {
            Log.i("BluetoothDataTransfer", "┏━━━ PERFORMANCE METRICS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            stats.lines().forEach { line ->
                if (line.isNotBlank()) {
                    Log.i("BluetoothDataTransfer", "┃ $line")
                }
            }
            Log.i("BluetoothDataTransfer", "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        }
    }

    private fun logFinalStatistics() {
        Log.i("BluetoothDataTransfer", "┏━━━ FINAL IDS STATISTICS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        val stats = idsModel.getStatistics()
        stats.lines().forEach { line ->
            if (line.isNotBlank()) {
                Log.i("BluetoothDataTransfer", "┃ $line")
            }
        }
        Log.i("BluetoothDataTransfer", "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        // Write final statistics to file
        try {
            val statsFile = File(logDirectory, "ids_final_statistics_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.txt")
            statsFile.writeText(stats)
        } catch (e: Exception) {
            Log.e("BluetoothDataTransfer", "Failed to write final statistics", e)
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
                logFinalStatistics()
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