package com.plcoding.bluetoothchat.presentation.IDS

import android.content.Context
import android.util.Log
import ai.onnxruntime.*
import kotlinx.coroutines.*
import java.nio.FloatBuffer
import java.util.*
import kotlin.math.*

class IDSModel(private val context: Context) {
    val modelName = "Bluetooth Security IDS - Final v7.1"

    // ONNX Runtime components
    private var ortSession: OrtSession? = null
    private var ortEnvironment: OrtEnvironment? = null
    private val modelFileName = "bluetooth_ids_model.onnx"

    // Feature extraction parameters
    private val featureCount = 22
    private val maxMessageLength = 1024

    // Device tracking
    private val deviceMessageHistory = mutableMapOf<String, MutableList<MessageRecord>>()
    private val deviceStats = mutableMapOf<String, DeviceStats>()

    // Thresholds - LOWERED for better detection
    private val confidenceThreshold = 0.5  // Lowered from 0.75
    private val ruleBasedThreshold = 0.6   // Added separate threshold for rule-based

    private val historyWindowMs = 60000L

    // Attack patterns and signatures - IMPROVED PATTERNS
    private val injectionPatterns = listOf(
        Regex("""\{.*:.*\}"""),  // JSON
        Regex("""<\w+>.*<\/\w+>"""),  // HTML
        Regex("""(cmd|exec|run|system|delete|rm|drop|sudo|sh|bash)""", RegexOption.IGNORE_CASE),
        Regex("""(['"]).*\1"""),  // Quoted strings
        Regex("""(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)""", RegexOption.IGNORE_CASE), // SQL
        Regex("""/\*.*\*/"""), // SQL comments
        Regex("""--.*$""", RegexOption.MULTILINE), // SQL line comments
        Regex("""(script|javascript|vbscript|onload|onerror|onclick)""", RegexOption.IGNORE_CASE)
    )

    private val spoofingPatterns = listOf(
        Regex("""(urgent|immediate|action required|admin|security|verify)""", RegexOption.IGNORE_CASE),
        Regex("""(click|link|update|pair|connect|verify)""", RegexOption.IGNORE_CASE),
        Regex("""(prevent|lockout|expire|suspend|disabled)""", RegexOption.IGNORE_CASE),
        Regex("""http[s]?://""", RegexOption.IGNORE_CASE),
        Regex("""www\.""", RegexOption.IGNORE_CASE),
        Regex("""(account|password|credential|username|login)""", RegexOption.IGNORE_CASE)
    )

    private val floodingPatterns = listOf(
        Regex("""FLOOD_\d+"""),
        Regex("""PING""", RegexOption.IGNORE_CASE),
        Regex("""(\w+)\s+\1\s+\1"""),  // Repeated words
        Regex("""(.)\1{10,}"""), // Character repeated 10+ times
        Regex("""(TEST|SPAM|FLOOD)""", RegexOption.IGNORE_CASE)
    )

    private val exploitPatterns = listOf(
        Regex("""\\x[0-9a-fA-F]{2}"""),  // Hex encoding
        Regex("""AT\+\w+"""),  // AT commands
        Regex("""(override|root|access|bypass|privilege|escalate)""", RegexOption.IGNORE_CASE),
        Regex("""[\x00-\x1F\x7F-\xFF]"""),  // Binary data
        Regex("""%[0-9a-fA-F]{2}"""), // URL encoding
        Regex("""\\u[0-9a-fA-F]{4}""") // Unicode escapes
    )

    data class MessageRecord(
        val timestamp: Long,
        val fromDevice: String,
        val toDevice: String,
        val message: String,
        val direction: String
    )

    data class DeviceStats(
        var messageCount: Int = 0,
        var lastSeen: Long = 0,
        var avgMessageLength: Float = 0f,
        var entropySum: Float = 0f,
        var commandCount: Int = 0,
        var attackScore: Double = 0.0
    )

    data class AnalysisResult(
        val isAttack: Boolean,
        val attackType: String,
        val confidence: Double,
        val explanation: String,
        val features: FloatArray? = null,
        val patternMatch: String = ""
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AnalysisResult

            if (isAttack != other.isAttack) return false
            if (attackType != other.attackType) return false
            if (confidence != other.confidence) return false
            if (explanation != other.explanation) return false
            if (patternMatch != other.patternMatch) return false
            if (features != null) {
                if (other.features == null) return false
                if (!features.contentEquals(other.features)) return false
            } else if (other.features != null) return false

            return true
        }

        override fun hashCode(): Int {
            var result = isAttack.hashCode()
            result = 31 * result + attackType.hashCode()
            result = 31 * result + confidence.hashCode()
            result = 31 * result + explanation.hashCode()
            result = 31 * result + patternMatch.hashCode()
            result = 31 * result + (features?.contentHashCode() ?: 0)
            return result
        }
    }

    companion object {
        val testCases = listOf(
            "{ \"command\": \"delete_files\", \"target\": \"*\" }" to "INJECTION",
            "admin: {execute: 'rm -rf /'}" to "INJECTION",
            "<script>alert('xss')</script>" to "INJECTION",
            "URGENT: Pair with ADMIN-1234 to prevent lockout" to "SPOOFING",
            "Your device needs update! Click HERE" to "SPOOFING",
            "FLOOD_${System.currentTimeMillis()}" to "FLOODING",
            "PING ".repeat(50) to "FLOODING",
            "\\x01\\x02\\x03\\x04\\x05" to "EXPLOIT",
            "AT+OVERRIDE=ROOT_ACCESS" to "EXPLOIT",
            "Hello, how are you?" to "NORMAL",
            "Please send the documents" to "NORMAL",
            "Meeting at 3pm tomorrow" to "NORMAL",
            // Add more challenging test cases
            "GET /wp-admin/install.php HTTP/1.1" to "INJECTION",
            "rm -rf / --no-preserve-root" to "INJECTION",
            "IMPORTANT: Your account will be suspended unless you verify NOW!" to "SPOOFING",
            "FLOOD_1234567890" to "FLOODING",
            "A".repeat(500) to "FLOODING",
            "\\x90".repeat(100) to "EXPLOIT"
        )
    }

    init {
        initializeONNXModel()
    }

    private fun initializeONNXModel() {
        try {
            ortEnvironment = OrtEnvironment.getEnvironment()

            // Check if model file exists
            val modelExists = try {
                context.assets.open(modelFileName).close()
                true
            } catch (e: Exception) {
                false
            }

            if (!modelExists) {
                Log.w("IDS", "ONNX model file not found: $modelFileName")
                Log.w("IDS", "Falling back to rule-based detection only")
                return
            }

            val inputStream = context.assets.open(modelFileName)
            val modelBytes = inputStream.readBytes()
            inputStream.close()

            val sessionOptions = OrtSession.SessionOptions().apply {
                setIntraOpNumThreads(1)
                setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT)
            }

            ortSession = ortEnvironment?.createSession(modelBytes, sessionOptions)
            Log.i("IDS", "ONNX model loaded successfully")

            // Log model info for debugging
            ortSession?.let { session ->
                Log.d("IDS", "Model input names: ${session.inputNames}")
                Log.d("IDS", "Model output names: ${session.outputNames}")
            }
        } catch (e: Exception) {
            Log.e("IDS", "Failed to load ONNX model", e)
            ortSession = null
        }
    }

    suspend fun analyzeMessage(
        message: String,
        fromDevice: String = "unknown",
        toDevice: String = "unknown",
        direction: String = "INCOMING"
    ): AnalysisResult = withContext(Dispatchers.Default) {
        val currentTime = System.currentTimeMillis()
        val messageRecord = MessageRecord(currentTime, fromDevice, toDevice, message, direction)

        updateDeviceStats(messageRecord)

        // ALWAYS try rule-based detection first
        val ruleBasedResult = enhancedRuleBasedDetection(messageRecord)

        // If rule-based detected an attack with high confidence, return it
        if (ruleBasedResult.isAttack && ruleBasedResult.confidence >= 0.8) {
            Log.d("IDS", "High confidence rule-based detection: ${ruleBasedResult.attackType}")
            return@withContext ruleBasedResult
        }

        // Try model detection if available
        val modelResult = if (ortSession != null) {
            detectAttack(messageRecord)
        } else {
            null
        }

        // Combine results intelligently
        return@withContext when {
            // Both detected attack - use the one with higher confidence
            modelResult?.isAttack == true && ruleBasedResult.isAttack -> {
                if (modelResult.confidence > ruleBasedResult.confidence) modelResult else ruleBasedResult
            }
            // Only model detected
            modelResult?.isAttack == true -> modelResult
            // Only rule-based detected
            ruleBasedResult.isAttack -> ruleBasedResult
            // Neither detected but model has result
            modelResult != null -> modelResult
            // Default to rule-based normal result
            else -> ruleBasedResult
        }
    }

    private fun updateDeviceStats(record: MessageRecord) {
        // Clean old messages
        val now = System.currentTimeMillis()
        deviceMessageHistory.values.forEach { messages ->
            messages.removeAll { now - it.timestamp > historyWindowMs }
        }

        // Update sender history
        val senderHistory = deviceMessageHistory.getOrPut(record.fromDevice) { mutableListOf() }
        senderHistory.add(record)

        // Update device statistics
        val stats = deviceStats.getOrPut(record.fromDevice) { DeviceStats() }
        stats.messageCount++
        stats.lastSeen = record.timestamp

        // Update rolling averages
        val messageLength = record.message.length.toFloat()
        stats.avgMessageLength = (stats.avgMessageLength * (stats.messageCount - 1) + messageLength) / stats.messageCount
        stats.entropySum += calculateEntropy(record.message)

        // Update command count if message contains commands
        if (containsCommandPattern(record.message)) {
            stats.commandCount++
        }

        // Decay attack score over time
        stats.attackScore *= 0.95
    }

    private fun containsCommandPattern(message: String): Boolean {
        return injectionPatterns.any { it.containsMatchIn(message) } ||
                exploitPatterns.any { it.containsMatchIn(message) }
    }

    @Suppress("UNCHECKED_CAST")
    private suspend fun detectAttack(record: MessageRecord): AnalysisResult {
        if (ortSession == null) {
            return AnalysisResult(
                isAttack = false,
                attackType = "MODEL_UNAVAILABLE",
                confidence = 0.0,
                explanation = "AI model not loaded",
                patternMatch = ""
            )
        }

        try {
            val features = extractEnhancedFeatures(record)
            val inputName = ortSession!!.inputNames.iterator().next()

            // Create input tensor
            val shape = longArrayOf(1, featureCount.toLong())
            val floatBuffer = FloatBuffer.wrap(features)
            val inputTensor = OnnxTensor.createTensor(ortEnvironment, floatBuffer, shape)

            // Run inference
            val results = ortSession!!.run(mapOf(inputName to inputTensor))

            // Process results - handle different output formats
            val output = results[0].value
            val predictions = when (output) {
                is Array<*> -> {
                    when {
                        output.isArrayOf<FloatArray>() -> (output as Array<FloatArray>)[0]
                        output.isArrayOf<String>() -> {
                            // Handle string array output - convert to float array
                            Log.w("IDS", "Model returned String array, converting to float")
                            (output as Array<String>).map { it.toFloatOrNull() ?: 0f }.toFloatArray()
                        }
                        else -> {
                            Log.e("IDS", "Unexpected array type: ${output[0]?.javaClass}")
                            throw IllegalStateException("Unexpected model output array type")
                        }
                    }
                }
                is FloatArray -> output
                is String -> {
                    // Handle single string output
                    Log.w("IDS", "Model returned String, parsing as float array")
                    floatArrayOf(output.toFloatOrNull() ?: 0f)
                }
                else -> {
                    Log.e("IDS", "Unexpected output format: ${output.javaClass}")
                    throw IllegalStateException("Unexpected model output format: ${output.javaClass}")
                }
            }

            // Class indices (must match your model's output)
            val classIndices = listOf("NORMAL", "FLOODING", "INJECTION", "SPOOFING", "EXPLOIT")

            // Get top prediction
            val maxIndex = predictions.indices.maxByOrNull { predictions[it] } ?: 0
            val confidence = predictions[maxIndex].toDouble()
            val predictedType = classIndices.getOrElse(maxIndex) { "UNKNOWN" }
            val isAttack = predictedType != "NORMAL"

            // Get pattern match details
            val patternMatch = if (isAttack) {
                detectPatternMatch(record.message, predictedType)
            } else ""

            // Clean up resources
            inputTensor.close()
            results.close()

            Log.d("IDS", "Model prediction: $predictedType (${"%.2f".format(confidence)})")

            return if (isAttack && confidence >= confidenceThreshold) {
                // Update device attack score
                deviceStats[record.fromDevice]?.attackScore =
                    (deviceStats[record.fromDevice]?.attackScore ?: 0.0) + confidence * 0.1

                AnalysisResult(
                    isAttack = true,
                    attackType = predictedType,
                    confidence = confidence,
                    explanation = "AI detected $predictedType with ${"%.1f".format(confidence * 100)}% confidence",
                    features = features,
                    patternMatch = patternMatch
                )
            } else {
                AnalysisResult(
                    isAttack = false,
                    attackType = "NORMAL",
                    confidence = if (predictedType == "NORMAL") confidence else 1.0 - confidence,
                    explanation = "Normal traffic (${"%.1f".format((1.0 - confidence) * 100)}% confidence)",
                    features = features,
                    patternMatch = ""
                )
            }

        } catch (e: Exception) {
            Log.e("IDS", "Detection failed: ${e.message}", e)
            return enhancedRuleBasedDetection(record)
        }
    }

    private fun enhancedRuleBasedDetection(record: MessageRecord): AnalysisResult {
        val message = record.message
        val features = extractEnhancedFeatures(record)
        val stats = deviceStats[record.fromDevice] ?: DeviceStats()

        // Calculate scores for each attack type
        val injectionScore = calculateAttackScore(message, features, "INJECTION")
        val spoofingScore = calculateAttackScore(message, features, "SPOOFING")
        val floodingScore = calculateAttackScore(message, features, "FLOODING")
        val exploitScore = calculateAttackScore(message, features, "EXPLOIT")

        // Get the highest scoring attack
        val scores = mapOf(
            "INJECTION" to injectionScore,
            "SPOOFING" to spoofingScore,
            "FLOODING" to floodingScore,
            "EXPLOIT" to exploitScore
        )

        val maxEntry = scores.maxByOrNull { it.value }
        val detectedType = maxEntry?.key ?: "NORMAL"
        val confidence = maxEntry?.value ?: 0.0

        // Apply LOWER thresholds for better detection
        val isAttack = when {
            // High confidence detection
            confidence > 0.8 -> true
            // Medium confidence
            confidence > ruleBasedThreshold -> true
            // Context-aware detection with lower threshold
            confidence > 0.5 && (
                    detectedType == "INJECTION" && stats.commandCount > 2 ||
                            detectedType == "FLOODING" && stats.messageCount > 10 ||
                            detectedType == "SPOOFING" && message.contains(Regex("""(urgent|click|verify)""", RegexOption.IGNORE_CASE))
                    ) -> true
            // Device has recent attack history
            stats.attackScore > 0.3 && confidence > 0.4 -> true
            // Otherwise not an attack
            else -> false
        }

        val patternMatch = if (isAttack || confidence > 0.4) {
            detectPatternMatch(message, detectedType)
        } else ""

        Log.d("IDS", "Rule-based detection: $detectedType (${"%.2f".format(confidence)}) - Attack: $isAttack")

        if (isAttack) {
            // Update device attack score
            stats.attackScore = minOf(stats.attackScore + confidence * 0.2, 1.0)
        }

        return AnalysisResult(
            isAttack = isAttack,
            attackType = if (isAttack) detectedType else "NORMAL",
            confidence = if (isAttack) confidence else 1.0 - confidence,
            explanation = if (isAttack) {
                "Rule-based detected $detectedType with ${"%.1f".format(confidence * 100)}% confidence"
            } else {
                "Normal traffic (highest risk: $detectedType at ${"%.1f".format(confidence * 100)}%)"
            },
            features = features,
            patternMatch = patternMatch
        )
    }

    private fun calculateAttackScore(message: String, features: FloatArray, attackType: String): Double {
        var score = 0.0
        var patternMatches = 0

        when (attackType) {
            "INJECTION" -> {
                // Pattern matches with higher weights
                injectionPatterns.forEach { pattern ->
                    if (pattern.containsMatchIn(message)) {
                        score += 0.35  // Increased from 0.25
                        patternMatches++
                    }
                }
                // Feature-based with adjusted thresholds
                if (features[9] > 0.3) score += 0.25  // JSON - lowered threshold
                if (features[10] > 0.3) score += 0.25  // HTML - lowered threshold
                if (features[12] > 0.3) score += 0.35  // Commands - lowered threshold
                if (features[3] > 0.5) score += 0.2   // Special chars - lowered threshold

                // Bonus for multiple patterns
                if (patternMatches > 1) score += 0.2
            }
            "SPOOFING" -> {
                spoofingPatterns.forEach { pattern ->
                    if (pattern.containsMatchIn(message)) {
                        score += 0.35  // Increased
                        patternMatches++
                    }
                }
                if (features[13] > 0.3) score += 0.35  // URLs - lowered threshold
                if (features[14] > 0.3) score += 0.25  // Credentials - lowered threshold
                if (features[1] > 0.6) score += 0.2    // High entropy - lowered threshold

                // Check for multiple urgency words
                val urgencyCount = spoofingPatterns.take(3).count { it.containsMatchIn(message) }
                if (urgencyCount > 1) score += 0.3
            }
            "FLOODING" -> {
                floodingPatterns.forEach { pattern ->
                    if (pattern.containsMatchIn(message)) {
                        score += 0.4  // Increased significantly
                        patternMatches++
                    }
                }
                if (features[0] > 0.6) score += 0.35   // Length - lowered threshold
                if (features[17] > 0.5) score += 0.25  // Repeats - lowered threshold
                if (features[8] > 0.3) score += 0.25   // Frequency - lowered threshold

                // Check message length directly
                if (message.length > 200) score += 0.3
                if (message.length > 500) score += 0.2
            }
            "EXPLOIT" -> {
                exploitPatterns.forEach { pattern ->
                    if (pattern.containsMatchIn(message)) {
                        score += 0.4  // Increased
                        patternMatches++
                    }
                }
                if (features[4] > 0.3) score += 0.35   // Binary - lowered threshold
                if (features[11] > 0.3) score += 0.25  // Hex - lowered threshold
                if (features[12] > 0.3) score += 0.25  // Commands - lowered threshold

                // Check for AT commands specifically
                if (message.contains(Regex("""AT\+""", RegexOption.IGNORE_CASE))) score += 0.4
            }
        }

        // Cap the score but allow it to go higher
        return minOf(score, 1.5) / 1.5  // Normalize to 0-1 range
    }

    private fun detectPatternMatch(message: String, attackType: String): String {
        val matches = mutableListOf<String>()

        when (attackType) {
            "INJECTION" -> {
                if (message.contains(Regex("""\{.*:.*\}"""))) matches.add("JSON structure")
                if (message.contains(Regex("""<\w+>.*<\/\w+>"""))) matches.add("HTML tags")
                if (message.contains(Regex("""(cmd|exec|run|system|rm|delete)""", RegexOption.IGNORE_CASE))) matches.add("Command pattern")
                if (message.contains(Regex("""(SELECT|INSERT|UPDATE|DELETE)""", RegexOption.IGNORE_CASE))) matches.add("SQL injection")
                if (message.contains("'") && message.contains("\"")) matches.add("Mixed quotes")
            }
            "SPOOFING" -> {
                if (message.contains(Regex("""(urgent|immediate|action required)""", RegexOption.IGNORE_CASE))) matches.add("Urgency language")
                if (message.contains(Regex("""(click|link|http|www)""", RegexOption.IGNORE_CASE))) matches.add("Link pattern")
                if (message.contains(Regex("""(admin|security|update|verify)""", RegexOption.IGNORE_CASE))) matches.add("Authority reference")
                if (message.contains(Regex("""(account|password|credential)""", RegexOption.IGNORE_CASE))) matches.add("Credential request")
            }
            "FLOODING" -> {
                if (message.contains(Regex("""FLOOD_\d+"""))) matches.add("Flood pattern")
                if (message.length > 200) matches.add("Oversized message (${message.length} chars)")
                if (message.split(" ").groupBy { it }.values.any { it.size > 5 }) matches.add("Repeated content")
                if (message.contains(Regex("""(.)\1{10,}"""))) matches.add("Character flooding")
            }
            "EXPLOIT" -> {
                if (message.contains(Regex("""\\x[0-9a-fA-F]{2}"""))) matches.add("Hex encoding")
                if (message.contains(Regex("""AT\+"""))) matches.add("AT command")
                if (message.contains(Regex("""[\x00-\x1F\x7F-\xFF]"""))) matches.add("Binary data")
                if (message.contains(Regex("""(root|privilege|override|bypass)""", RegexOption.IGNORE_CASE))) matches.add("Privilege escalation")
                if (message.contains(Regex("""%[0-9a-fA-F]{2}"""))) matches.add("URL encoding")
            }
        }

        return if (matches.isNotEmpty()) {
            matches.joinToString(", ")
        } else {
            when (attackType) {
                "INJECTION" -> "Suspicious syntax"
                "SPOOFING" -> "Social engineering"
                "FLOODING" -> "High frequency/volume"
                "EXPLOIT" -> "Exploit signature"
                else -> ""
            }
        }
    }

    private fun extractEnhancedFeatures(record: MessageRecord): FloatArray {
        val features = FloatArray(featureCount)
        val message = record.message
        val currentTime = System.currentTimeMillis()
        val stats = deviceStats[record.fromDevice] ?: DeviceStats()
        val history = deviceMessageHistory[record.fromDevice] ?: emptyList()

        // 1. Basic Message Features (0-4)
        features[0] = minOf(message.length.toFloat(), maxMessageLength.toFloat()) / maxMessageLength
        features[1] = calculateEntropy(message)
        features[2] = message.count { it.isDigit() }.toFloat() / message.length.coerceAtLeast(1).toFloat()
        features[3] = message.count { !it.isLetterOrDigit() }.toFloat() / message.length.coerceAtLeast(1).toFloat()
        features[4] = if (message.contains(Regex("""[\x00-\x1F\x7F-\xFF]"""))) 1f else 0f

        // 2. Temporal Features (5-8)
        features[5] = (currentTime - (if (stats.lastSeen > 0) stats.lastSeen else currentTime)).toFloat() / 60000f
        features[6] = (Calendar.getInstance().get(Calendar.HOUR_OF_DAY).toFloat() / 24f)
        features[7] = (Calendar.getInstance().get(Calendar.DAY_OF_WEEK).toFloat() / 7f)
        features[8] = minOf(stats.messageCount.toFloat() / 100f, 1f)

        // 3. Content Patterns (9-14) - MORE SENSITIVE DETECTION
        features[9] = if (message.contains(Regex("""[\{\[].*[:=].*[\}\]]"""))) 1f else 0f  // Broader JSON detection
        features[10] = if (message.contains(Regex("""<[^>]+>"""))) 1f else 0f  // Any HTML-like tags
        features[11] = if (message.contains(Regex("""(\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2})"""))) 1f else 0f  // Hex or URL encoding
        features[12] = if (message.contains(Regex("""(admin|root|system|cmd|exec|sudo|rm|delete)""", RegexOption.IGNORE_CASE))) 1f else 0f
        features[13] = if (message.contains(Regex("""(http|ftp|www\.|\.com|\.org)""", RegexOption.IGNORE_CASE))) 1f else 0f
        features[14] = if (message.contains(Regex("""(password|login|credential|username|auth|token)""", RegexOption.IGNORE_CASE))) 1f else 0f

        // 4. Behavioral Features (15-19)
        features[15] = stats.avgMessageLength / maxMessageLength
        features[16] = (stats.entropySum / stats.messageCount.coerceAtLeast(1))
        features[17] = calculateMessageRepeatScore(record, history)
        features[18] = minOf(stats.commandCount.toFloat() / 10f, 1f)
        features[19] = calculateDirectionChangeScore(record, history)

        // 5. Device Context (20-21)
        features[20] = if (stats.messageCount > 10) 1f else 0f
        features[21] = if (history.size > 5) {
            minOf(history.takeLast(5).count { it.message.length > 100 }.toFloat() / 5f, 1f)
        } else 0f

        return features
    }

    private fun calculateEntropy(message: String): Float {
        if (message.isEmpty()) return 0f
        val freq = mutableMapOf<Char, Int>()
        message.forEach { char -> freq[char] = freq.getOrDefault(char, 0) + 1 }

        var entropy = 0.0
        val length = message.length.toDouble()
        freq.values.forEach { count ->
            val p = count / length
            if (p > 0) entropy -= p * log2(p)
        }

        return (entropy / 8f).toFloat()  // Normalize to 0-1 range
    }

    private fun calculateMessageRepeatScore(record: MessageRecord, history: List<MessageRecord>): Float {
        if (history.isEmpty()) return 0f
        val similarCount = history.count {
            it.message == record.message ||
                    it.message.contains(record.message) ||
                    record.message.contains(it.message)
        }
        return minOf(similarCount.toFloat() / 5f, 1f)
    }

    private fun calculateDirectionChangeScore(record: MessageRecord, history: List<MessageRecord>): Float {
        if (history.isEmpty()) return 0f
        val lastDirection = history.last().direction
        return if (lastDirection != record.direction) 1f else 0f
    }

    suspend fun runTestCases(): List<Pair<String, AnalysisResult>> = withContext(Dispatchers.Default) {
        Log.d("IDS", "Running test cases...")
        testCases.map { (message, expectedType) ->
            val result = analyzeMessage(message, "TestDevice", "TargetDevice")
            val passed = if (expectedType == "NORMAL") !result.isAttack else result.isAttack
            Log.d("IDS", "Test: $message")
            Log.d("IDS", "Expected: $expectedType, Got: ${result.attackType}, Passed: $passed")
            Log.d("IDS", "Confidence: ${result.confidence}, Pattern: ${result.patternMatch}")
            message to result
        }
    }

    fun cleanup() {
        try {
            ortSession?.close()
            ortEnvironment?.close()
        } catch (e: Exception) {
            Log.e("IDS", "Cleanup error", e)
        }
    }
}