package com.plcoding.bluetoothchat.presentation.IDS
import java.util.*
import kotlin.math.pow
import kotlin.math.sqrt

class BluetoothFeatureExtractor {
    private val messageHistory = LinkedList<BluetoothMessage>()
    private val deviceMessageCounts = mutableMapOf<String, Int>()
    private val lastMessageTimestamps = mutableMapOf<String, Long>()
    private val lastMessageContent = mutableMapOf<String, String>()

    data class BluetoothMessage(
        val timestamp: Long,
        val fromDevice: String,
        val toDevice: String,
        val message: String,
        val direction: Direction
    ) {
        enum class Direction { INCOMING, OUTGOING }
    }

    fun extractFeatures(newMessage: BluetoothMessage): FloatArray {
        updateMessageHistory(newMessage)

        return floatArrayOf(
            // 1. Message Content Features (7)
            newMessage.message.length.toFloat(),               // msg_char_len
            newMessage.message.split("\\s+".toRegex()).size.toFloat(), // msg_word_len
            if (newMessage.message.any { it.isDigit() }) 1f else 0f,  // has_number
            if (newMessage.message.any { !it.isLetterOrDigit() }) 1f else 0f, // has_special
            if (newMessage.message.equals(newMessage.message.uppercase())) 1f else 0f, // is_upper
            if (newMessage.message.equals(newMessage.message.lowercase())) 1f else 0f, // is_lower
            if (newMessage.message == newMessage.message.replaceFirstChar { it.uppercase() }) 1f else 0f,
            // 2. Entropy (1)
            calculateRollingLenStd(device = toString()).toFloat(),    // msg_entropy

            // 3. Temporal Features (4)
            Calendar.getInstance().apply { timeInMillis = newMessage.timestamp }.get(Calendar.HOUR_OF_DAY).toFloat(), // hour_of_day
            Calendar.getInstance().apply { timeInMillis = newMessage.timestamp }.get(Calendar.DAY_OF_WEEK).toFloat(), // day_of_week
            calculateTimeSinceLast(newMessage),                // time_since_last
            calculateTimeSinceLastSameMsg(newMessage),         // time_since_last_same_msg

            // 4. Behavioral Features (7)
            calculateMsgCountWindow(newMessage.fromDevice),    // msg_count_window
            calculateRollingAvgLen(newMessage.fromDevice),     // rolling_avg_len
            calculateRollingLenStd(newMessage.fromDevice),    // rolling_len_std
            calculateMsgRepeatCount(newMessage),               // msg_repeat_count
            if (lastMessageContent[newMessage.fromDevice] == newMessage.message) 1f else 0f, // is_repeated
            if (newMessage.direction == BluetoothMessage.Direction.INCOMING) 0f else 1f, // direction_encoded
            newMessage.fromDevice.hashCode().toFloat(),        // from_device_encoded
            newMessage.toDevice.hashCode().toFloat(),          // to_device_encoded

            // 5. Security Features (2)
            if ((deviceMessageCounts[newMessage.fromDevice] ?: 0) >= SPOOFING_DEVICE_COUNT_THRESHOLD) 0f else 1f, // is_spoofed
            (newMessage.message.length.toFloat() / 500f).coerceIn(0f, 1f) // msg_len_bin (normalized)
        )
    }

    // Helper methods (same as previous implementation)
    private fun updateMessageHistory(msg: BluetoothMessage) {
        messageHistory.add(msg)
        deviceMessageCounts[msg.fromDevice] = (deviceMessageCounts[msg.fromDevice] ?: 0) + 1
        lastMessageTimestamps[msg.fromDevice] = msg.timestamp
        lastMessageContent[msg.fromDevice] = msg.message
        if (messageHistory.size > WINDOW_SIZE) messageHistory.removeFirst()
    }

    private fun calculateTimeSinceLast(msg: BluetoothMessage): Float {
        val lastTimestamp = lastMessageTimestamps[msg.fromDevice] ?: return 0f
        return ((msg.timestamp - lastTimestamp) / 1000f).coerceAtLeast(0f)
    }

    private fun calculateTimeSinceLastSameMsg(msg: BluetoothMessage): Float {
        return if (lastMessageContent[msg.fromDevice] == msg.message) {
            calculateTimeSinceLast(msg)
        } else 0f
    }

    private fun calculateMsgCountWindow(device: String): Float {
        return messageHistory.count { it.fromDevice == device }.toFloat()
    }

    private fun calculateRollingAvgLen(device: String): Float {
        val recent = messageHistory.filter { it.fromDevice == device }
        return if (recent.isEmpty()) 0f else recent.map { it.message.length }.average().toFloat()
    }

    private fun calculateRollingLenStd(device: String): Float {
        val recent = messageHistory.filter { it.fromDevice == device }
        return if (recent.size < 2) 0f else {
            val lengths = recent.map { it.message.length.toDouble() }
            val avg = lengths.average()
            val variance = lengths.map { (it - avg).pow(2) }.average()
            sqrt(variance).toFloat()
        }
    }

    private fun calculateMsgRepeatCount(msg: BluetoothMessage): Float {
        return messageHistory.count {
            it.fromDevice == msg.fromDevice && it.message == msg.message
        }.toFloat()
    }

    companion object {
        const val WINDOW_SIZE = 10
        const val SPOOFING_DEVICE_COUNT_THRESHOLD = 2
        private fun calculateRollingLenStd(
            bluetoothFeatureExtractor: BluetoothFeatureExtractor,
            device: String): Float {
            val recent = bluetoothFeatureExtractor.messageHistory.filter { it.fromDevice == device }
            return if (recent.size < 2) 0f else {
                val avg = recent.map { it.message.length }.average()
                sqrt(recent.map { (it.message.length - avg).pow(2) }.average()).toFloat()
            }
        }
    }
}