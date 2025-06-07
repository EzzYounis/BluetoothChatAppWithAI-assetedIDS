package IDS

import IDS.IDSModelHelper.Companion.EXPECTED_FEATURE_COUNT
import kotlin.math.log2

class BluetoothFeatureExtractor {

    companion object {
        private const val MSG_LENGTH_WEIGHT = 0.1f
        private const val TIME_WINDOW_SECONDS = 10f
    }

    // Feature extraction history tracking
    private val messageHistory = mutableListOf<MessageRecord>()
    private val deviceStats = mutableMapOf<String, DeviceStats>()

    data class MessageRecord(
        val timestamp: Long,
        val device: String,
        val direction: String,
        val length: Int,
        val wordCount: Int
    )

    data class DeviceStats(
        var msgCount: Int = 0,
        var lastTimestamp: Long = 0,
        var lastMessage: String? = null
    )

    fun extractFeatures(
        message: String,
        timestamp: Long,
        device: String,
        direction: String
    ): FloatArray {
        // Clean message
        val cleanMessage = message.trim()
        val currentTime = timestamp

        // 1. Basic message features
        val msgLength = cleanMessage.length.toFloat()
        val wordCount = cleanMessage.split("\\s+".toRegex()).size.toFloat()
        val hasNumbers = if (cleanMessage.any { it.isDigit() }) 1f else 0f
        val hasSpecialChars = if (cleanMessage.any { !it.isLetterOrDigit() }) 1f else 0f
        val isUpperCase = if (cleanMessage == cleanMessage.uppercase()) 1f else 0f
        val entropy = calculateShannonEntropy(cleanMessage)

        // 2. Temporal features
        val deviceStat = deviceStats.getOrPut(device) { DeviceStats() }
        val timeSinceLast = if (deviceStat.lastTimestamp > 0) {
            (currentTime - deviceStat.lastTimestamp) / 1000f // Convert to seconds
        } else {
            0f
        }

        // 3. Behavioral features
        val isRepeat = if (deviceStat.lastMessage == cleanMessage) 1f else 0f
        val msgRate = if (timeSinceLast > 0) 1f / timeSinceLast else 0f

        // 4. Contextual features (sliding window)
        messageHistory.add(MessageRecord(currentTime, device, direction, cleanMessage.length, wordCount.toInt()))

        // Remove old records (10-second window)
        messageHistory.removeAll {
            currentTime - it.timestamp > TIME_WINDOW_SECONDS * 1000
        }

        val windowMsgCount = messageHistory.count {
            it.device == device &&
                    currentTime - it.timestamp <= TIME_WINDOW_SECONDS * 1000
        }.toFloat()

        val avgMsgLength = messageHistory
            .filter { it.device == device }
            .map { it.length }
            .average()
            .toFloat()

        // 5. Protocol features (placeholder for Bluetooth-specific features)
        val protocolAnomalyScore = 0f // Could analyze packet headers if available

        // Update device stats
        deviceStat.apply {
            msgCount++
            lastTimestamp = currentTime
            lastMessage = cleanMessage
        }

        // Create feature array (must match EXPECTED_FEATURE_COUNT = 22)
        return floatArrayOf(
            // Basic features (0-6)
            msgLength * MSG_LENGTH_WEIGHT,
            wordCount,
            hasNumbers,
            hasSpecialChars,
            isUpperCase,
            entropy,
            cleanMessage.map { it.code.toFloat() }.average().toFloat(),

            // Temporal features (7-10)
            timeSinceLast,
            msgRate,
            windowMsgCount,
            avgMsgLength,

            // Behavioral features (11-15)
            isRepeat,
            deviceStat.msgCount.toFloat(),
            if (direction == "INCOMING") 1f else 0f,
            calculateMessageComplexity(cleanMessage),
            protocolAnomalyScore,

            // Derived features (16-21)
            msgLength / (wordCount + 1f), // Avg word length
            windowMsgCount / TIME_WINDOW_SECONDS, // Msg rate per second
            if (windowMsgCount > 10f) 1f else 0f, // Flooding flag
            if (isRepeat == 1f && timeSinceLast < 1f) 1f else 0f, // Injection flag
            if (deviceStat.msgCount < 3) 1f else 0f, // New device flag
            calculatePatternScore(cleanMessage) // Regex pattern matching
        ).also {
            // Ensure we have exactly 22 features
            require(it.size == IDSModelHelper.EXPECTED_FEATURE_COUNT) {
                "Feature count mismatch: Expected ${IDSModelHelper.EXPECTED_FEATURE_COUNT}, got ${it.size}"
            }
        }
    }

    private fun calculateShannonEntropy(message: String): Float {
        if (message.isEmpty()) return 0f
        val charCounts = mutableMapOf<Char, Int>()
        message.forEach { char -> charCounts[char] = charCounts.getOrDefault(char, 0) + 1 }

        return charCounts.values.sumOf { count ->
            val probability = count.toDouble() / message.length
            -probability * log2(probability)
        }.toFloat()
    }

    private fun calculateMessageComplexity(message: String): Float {
        val uniqueChars = message.toSet().size.toFloat()
        val length = message.length.toFloat()
        return if (length > 0) uniqueChars / length else 0f
    }

    private fun calculatePatternScore(message: String): Float {
        val patterns = listOf(
            Regex("\\b(free|win|prize|claim|urgent)\\b", RegexOption.IGNORE_CASE),
            Regex("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"), // MAC address pattern
            Regex("\\b(admin|root|password)\\b", RegexOption.IGNORE_CASE)
        )

        return patterns.count { it.containsMatchIn(message) }.toFloat()
    }

    fun resetSession() {
        messageHistory.clear()
        deviceStats.clear()
    }
}