package com.plcoding.bluetoothchat.presentation.IDS

import android.content.Context
import android.util.Log
import java.util.regex.Pattern

class IDSModel(private val context: Context) {
    val modelName = "Bluetooth Security IDS v1.0"

    // Rule-based detection patterns
    private val attackPatterns = mapOf(
        "SPOOFING" to listOf(
            Pattern.compile("(?i)(urgent|click|link|account|suspended|verify|login)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(http://|https://|www\\.|ftp://)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(password|username|credit card|ssn|social security)", Pattern.CASE_INSENSITIVE)
        ),
        "INJECTION" to listOf(
            Pattern.compile("\\{.*[\"'].*:.*[\"'].*\\}", Pattern.CASE_INSENSITIVE), // JSON-like structures
            Pattern.compile("(?i)(admin|root|system|command|execute|payload)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("[<>\"'%;()&+]", Pattern.CASE_INSENSITIVE), // Special characters
            Pattern.compile("(?i)(script|eval|exec|shell|cmd)", Pattern.CASE_INSENSITIVE)
        ),
        "FLOODING" to listOf(
            Pattern.compile("^FLOOD_\\d+$", Pattern.CASE_INSENSITIVE),
            Pattern.compile("^(.{1,10})\\1{5,}$", Pattern.CASE_INSENSITIVE), // Repeated patterns
            Pattern.compile("^[A-Z0-9_]{20,}$", Pattern.CASE_INSENSITIVE) // Long uppercase/number strings
        )
    )

    // Message frequency tracking for flood detection
    private val messageHistory = mutableListOf<Long>()
    private val maxMessagesPerSecond = 5
    private val historyWindowMs = 1000L

    data class AnalysisResult(
        val isAttack: Boolean,
        val attackType: String,
        val confidence: Double,
        val aiDetected: Boolean = false,
        val explanation: String,
        val matchedPattern: String = ""
    )

    fun analyzeMessage(message: String): AnalysisResult {
        Log.d("IDS", "Analyzing message: '$message'")

        // Clean up message history (remove old entries)
        val currentTime = System.currentTimeMillis()
        messageHistory.removeAll { currentTime - it > historyWindowMs }

        // Add current message timestamp
        messageHistory.add(currentTime)

        // Check for flooding first
        if (messageHistory.size > maxMessagesPerSecond) {
            Log.w("IDS", "FLOODING detected - ${messageHistory.size} messages in ${historyWindowMs}ms")
            return AnalysisResult(
                isAttack = true,
                attackType = "FLOODING",
                confidence = 0.95,
                aiDetected = false,
                explanation = "Message flooding detected: ${messageHistory.size} messages in ${historyWindowMs/1000} second(s)",
                matchedPattern = "Message frequency > $maxMessagesPerSecond/sec"
            )
        }

        // Check rule-based patterns
        for ((attackType, patterns) in attackPatterns) {
            for ((index, pattern) in patterns.withIndex()) {
                val matcher = pattern.matcher(message)
                if (matcher.find()) {
                    val matchedText = matcher.group()
                    Log.w("IDS", "$attackType attack detected - Pattern: ${pattern.pattern()}, Match: '$matchedText'")

                    return AnalysisResult(
                        isAttack = true,
                        attackType = attackType,
                        confidence = calculateConfidence(attackType, message, matchedText),
                        aiDetected = false,
                        explanation = getExplanation(attackType, matchedText),
                        matchedPattern = "Pattern ${index + 1}: ${pattern.pattern()}"
                    )
                }
            }
        }

        // Additional heuristic checks
        val heuristicResult = performHeuristicAnalysis(message)
        if (heuristicResult.isAttack) {
            Log.w("IDS", "Heuristic detection: ${heuristicResult.attackType}")
            return heuristicResult
        }

        Log.d("IDS", "Message appears safe")
        return AnalysisResult(
            isAttack = false,
            attackType = "NONE",
            confidence = 0.0,
            aiDetected = false,
            explanation = "Message passed all security checks",
            matchedPattern = ""
        )
    }

    private fun performHeuristicAnalysis(message: String): AnalysisResult {
        val suspiciousScore = calculateSuspiciousScore(message)

        if (suspiciousScore > 0.7) {
            val attackType = when {
                message.contains("http", ignoreCase = true) ||
                        message.contains("click", ignoreCase = true) -> "SPOOFING"
                message.contains("{") && message.contains("}") -> "INJECTION"
                message.length > 100 && message.count { it.isUpperCase() } > message.length / 2 -> "FLOODING"
                else -> "SUSPICIOUS"
            }

            return AnalysisResult(
                isAttack = true,
                attackType = attackType,
                confidence = suspiciousScore,
                aiDetected = true,
                explanation = "Heuristic analysis detected suspicious content (score: ${String.format("%.2f", suspiciousScore)})",
                matchedPattern = "Heuristic analysis"
            )
        }

        return AnalysisResult(
            isAttack = false,
            attackType = "NONE",
            confidence = 0.0,
            aiDetected = false,
            explanation = "Heuristic analysis passed",
            matchedPattern = ""
        )
    }

    private fun calculateSuspiciousScore(message: String): Double {
        var score = 0.0

        // Check for suspicious keywords
        val suspiciousKeywords = listOf(
            "urgent", "click", "verify", "suspended", "account", "login",
            "password", "admin", "root", "command", "payload", "exploit"
        )

        suspiciousKeywords.forEach { keyword ->
            if (message.contains(keyword, ignoreCase = true)) {
                score += 0.1
            }
        }

        // Check for URLs
        if (message.contains("http", ignoreCase = true) ||
            message.contains("www.", ignoreCase = true)) {
            score += 0.3
        }

        // Check for special characters (potential injection)
        val specialChars = "<>\"'%;()&+{}[]"
        val specialCharCount = message.count { it in specialChars }
        if (specialCharCount > 3) {
            score += 0.2
        }

        // Check message length and repetition
        if (message.length > 200) {
            score += 0.1
        }

        return minOf(score, 1.0)
    }

    private fun calculateConfidence(attackType: String, message: String, matchedText: String): Double {
        return when (attackType) {
            "SPOOFING" -> when {
                message.contains("http", ignoreCase = true) -> 0.9
                message.contains("urgent", ignoreCase = true) -> 0.8
                else -> 0.7
            }
            "INJECTION" -> when {
                matchedText.contains("{") && matchedText.contains("}") -> 0.95
                message.contains("admin", ignoreCase = true) -> 0.85
                else -> 0.75
            }
            "FLOODING" -> when {
                message.startsWith("FLOOD_") -> 0.99
                else -> 0.8
            }
            else -> 0.6
        }
    }

    private fun getExplanation(attackType: String, matchedText: String): String {
        return when (attackType) {
            "SPOOFING" -> "Potential phishing or social engineering attempt detected. Suspicious content: '$matchedText'"
            "INJECTION" -> "Potential code injection or malicious payload detected. Suspicious pattern: '$matchedText'"
            "FLOODING" -> "Message flooding attack detected. Pattern indicates automated spam: '$matchedText'"
            else -> "Suspicious content detected: '$matchedText'"
        }
    }

    // Method to test the IDS with known attack patterns
    fun testDetection(): List<Pair<String, AnalysisResult>> {
        val testMessages = listOf(
            "URGENT: Your account will be suspended! Click http://malicious.link to verify",
            "Hello, how are you today?",
            "ADMIN COMMAND: {execute: true, payload: 'rm -rf /', escalate: admin}",
            "FLOOD_1234567890",
            "Normal message with some text",
            "Please enter your password and username here",
            "<script>alert('xss')</script>",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        return testMessages.map { message ->
            message to analyzeMessage(message)
        }
    }
}