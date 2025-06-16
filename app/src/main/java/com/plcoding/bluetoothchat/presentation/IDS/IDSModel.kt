package com.plcoding.bluetoothchat.presentation.IDS

import android.content.Context
import android.util.Log
import ai.onnxruntime.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.*
import java.nio.FloatBuffer
import java.util.*
import kotlin.math.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class IDSModel(private val context: Context) {
    val modelName = "Bluetooth Security IDS - Enhanced v8.0"

    // ONNX Runtime components
    private var ortSession: OrtSession? = null
    private var ortEnvironment: OrtEnvironment? = null
    private val modelFileName = "bluetooth_ids_model.onnx"

    // Feature extraction parameters
    private val featureCount = 22
    private val maxMessageLength = 1024

    // Device tracking
    private val deviceMessageHistory = ConcurrentHashMap<String, MutableList<MessageRecord>>()
    private val deviceStats = ConcurrentHashMap<String, DeviceStats>()

    // Attack detection state management
    private val activeAttacks = ConcurrentHashMap<String, AttackState>()
    private val attackNotificationFlow = MutableSharedFlow<AttackNotification>(
        replay = 0,
        extraBufferCapacity = 10,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    // Thresholds - INCREASED for better accuracy
    private val confidenceThreshold = 0.75  // Increased from 0.6
    private val ruleBasedThreshold = 0.7   // Increased from 0.5
    private val attackCooldownMs = 30000L // 30 seconds cooldown between same attack notifications
    private val attackGroupingWindowMs = 5000L // Group attacks within 5 seconds

    private val historyWindowMs = 60000L

    // Rate limiting
    private val rateLimiter = RateLimiter()

    // Attack patterns
    private val injectionPatterns = listOf(
        Regex("""\{.*:.*\}"""),  // JSON
        Regex("""<\w+>.*<\/\w+>"""),  // HTML
        Regex("""(cmd|exec|run|system|delete|rm|drop|sudo|sh|bash)""", RegexOption.IGNORE_CASE),
        Regex("""(['"]).*\1"""),  // Quoted strings
        Regex("""(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)""", RegexOption.IGNORE_CASE),
        Regex("""/\*.*\*/"""), // SQL comments
        Regex("""--.*$""", RegexOption.MULTILINE),
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

    // Safe message patterns - common phrases that should not trigger alerts
    private val safeMessagePatterns = listOf(
        Regex("^(hello|hi|hey|good morning|good evening|good night)[!.,]?$", RegexOption.IGNORE_CASE),
        Regex("^(yes|no|ok|okay|sure|maybe|thanks|thank you)[!.,]?$", RegexOption.IGNORE_CASE),
        Regex("^(how are you|what's up|how's it going|nice to meet you)[?!.,]?$", RegexOption.IGNORE_CASE),
        Regex("^(see you|bye|goodbye|talk to you later|ttyl)[!.,]?$", RegexOption.IGNORE_CASE),
        Regex("^(please|sorry|excuse me|pardon)[!.,]?$", RegexOption.IGNORE_CASE),
        Regex("^(i'm fine|doing well|not bad|pretty good)[!.,]?$", RegexOption.IGNORE_CASE)
    )

    // Data classes
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
        var attackScore: Double = 0.0,
        var lastAttackTime: Long = 0
    )

    data class AttackState(
        val deviceId: String,
        val attackType: String,
        var count: Int = 1,
        var firstDetected: Long = System.currentTimeMillis(),
        var lastDetected: Long = System.currentTimeMillis(),
        var messages: MutableList<String> = mutableListOf(),
        var maxConfidence: Double = 0.0
    )

    data class AttackNotification(
        val deviceId: String,
        val attackType: String,
        val count: Int,
        val confidence: Double,
        val timeWindow: Long,
        val sampleMessage: String,
        val timestamp: Long = System.currentTimeMillis()
    )

    data class AnalysisResult(
        val isAttack: Boolean,
        val attackType: String,
        val confidence: Double,
        val explanation: String,
        val features: FloatArray? = null,
        val patternMatch: String = "",
        val shouldNotify: Boolean = true
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
            if (shouldNotify != other.shouldNotify) return false
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
            result = 31 * result + shouldNotify.hashCode()
            result = 31 * result + (features?.contentHashCode() ?: 0)
            return result
        }
    }

    // Rate limiter for preventing spam
    private class RateLimiter {
        val lastNotificationTime = ConcurrentHashMap<String, AtomicLong>()
        val notificationCounts = ConcurrentHashMap<String, AtomicLong>()

        fun shouldAllow(key: String, cooldownMs: Long): Boolean {
            val now = System.currentTimeMillis()
            val lastTime = lastNotificationTime.computeIfAbsent(key) { AtomicLong(0) }

            if (now - lastTime.get() < cooldownMs) {
                return false
            }

            lastTime.set(now)
            return true
        }

        fun incrementCount(key: String): Long {
            return notificationCounts.computeIfAbsent(key) { AtomicLong(0) }.incrementAndGet()
        }

        fun resetCount(key: String) {
            notificationCounts[key]?.set(0)
        }
    }

    init {
        initializeONNXModel()

        // Start attack state cleanup coroutine
        GlobalScope.launch {
            while (true) {
                delay(60000) // Clean up every minute
                cleanupOldAttackStates()
            }
        }
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
                setIntraOpNumThreads(2)
                setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT)
            }

            ortSession = ortEnvironment?.createSession(modelBytes, sessionOptions)
            Log.i("IDS", "ONNX model loaded successfully")

            // Log model info
            ortSession?.let { session ->
                Log.d("IDS", "Model input count: ${session.numInputs}")
                Log.d("IDS", "Model output count: ${session.numOutputs}")
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

        // Quick check for safe messages
        if (isSafeMessage(message)) {
            Log.d("IDS", "Message identified as safe common phrase")
            return@withContext AnalysisResult(
                isAttack = false,
                attackType = "NORMAL",
                confidence = 0.99,
                explanation = "Common safe communication",
                patternMatch = "Safe phrase detected"
            )
        }

        // Try model detection first if available
        val modelResult = if (ortSession != null) {
            detectAttackWithONNX(messageRecord)
        } else {
            null
        }

        // Always run rule-based detection as backup
        val ruleBasedResult = enhancedRuleBasedDetection(messageRecord)

        // Combine results intelligently
        val finalResult = when {
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

        // Handle attack notification logic
        if (finalResult.isAttack) {
            val shouldNotify = handleAttackDetection(fromDevice, finalResult.attackType,
                finalResult.confidence, message)
            return@withContext finalResult.copy(shouldNotify = shouldNotify)
        }

        finalResult
    }

    private fun isSafeMessage(message: String): Boolean {
        // Check message length - very short messages are usually safe
        if (message.length < 3) return true

        // Check against safe patterns
        val trimmedMessage = message.trim()
        if (safeMessagePatterns.any { it.matches(trimmedMessage) }) {
            return true
        }

        // Check for normal conversational messages
        val lowerMessage = message.lowercase().trim()
        val safeWords = setOf(
            "hello", "hi", "hey", "thanks", "thank you", "please", "yes", "no",
            "okay", "ok", "sure", "sorry", "bye", "goodbye", "good morning",
            "good evening", "good night", "how are you", "fine", "great"
        )

        // If message is short and contains mostly safe words, it's probably safe
        if (message.length < 50) {
            val words = lowerMessage.split(Regex("\\s+"))
            val safeWordCount = words.count { it in safeWords }
            if (safeWordCount.toFloat() / words.size > 0.5) {
                return true
            }
        }

        return false
    }

    private fun handleAttackDetection(
        deviceId: String,
        attackType: String,
        confidence: Double,
        message: String
    ): Boolean {
        val now = System.currentTimeMillis()
        val attackKey = "$deviceId:$attackType"

        // Check rate limiting
        if (!rateLimiter.shouldAllow(attackKey, attackCooldownMs)) {
            // Update existing attack state
            activeAttacks[attackKey]?.let { state ->
                state.count++
                state.lastDetected = now
                state.messages.add(message.take(100)) // Store first 100 chars
                if (state.messages.size > 5) {
                    state.messages.removeAt(0) // Keep only last 5 messages
                }
                state.maxConfidence = maxOf(state.maxConfidence, confidence)
            }
            return false // Don't notify, we're in cooldown
        }

        // Create or update attack state
        val attackState = activeAttacks.computeIfAbsent(attackKey) {
            AttackState(deviceId, attackType)
        }.apply {
            count++
            lastDetected = now
            messages.add(message.take(100))
            if (messages.size > 5) messages.removeAt(0)
            maxConfidence = maxOf(maxConfidence, confidence)
        }

        // Send grouped notification
        GlobalScope.launch {
            attackNotificationFlow.emit(
                AttackNotification(
                    deviceId = deviceId,
                    attackType = attackType,
                    count = attackState.count,
                    confidence = attackState.maxConfidence,
                    timeWindow = now - attackState.firstDetected,
                    sampleMessage = attackState.messages.firstOrNull() ?: message
                )
            )
        }

        return true
    }

    private fun cleanupOldAttackStates() {
        val now = System.currentTimeMillis()
        val iterator = activeAttacks.iterator()

        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.lastDetected > attackCooldownMs * 2) {
                iterator.remove()
            }
        }
    }

    fun getAttackNotificationFlow(): SharedFlow<AttackNotification> = attackNotificationFlow

    fun getActiveAttacksCount(): Int = activeAttacks.size

    fun getDeviceAttackHistory(deviceId: String): List<AttackState> {
        return activeAttacks.values.filter { it.deviceId == deviceId }
    }

    private suspend fun detectAttackWithONNX(record: MessageRecord): AnalysisResult? {
        if (ortSession == null) return null

        try {
            val features = extractEnhancedFeatures(record)
            val inputName = ortSession!!.inputNames.iterator().next()

            // Create input tensor
            val shape = longArrayOf(1, featureCount.toLong())
            val floatBuffer = FloatBuffer.wrap(features)
            val inputTensor = OnnxTensor.createTensor(ortEnvironment, floatBuffer, shape)

            // Run inference
            val results = ortSession!!.run(mapOf(inputName to inputTensor))

            // Process Random Forest output
            val output = results[0]?.value
            val outputInfo = results[1]?.value // Probabilities

            // Handle class predictions
            val predictedClass = when (output) {
                is LongArray -> output[0].toInt()
                is IntArray -> output[0]
                is FloatArray -> output[0].toInt()
                else -> {
                    Log.e("IDS", "Unexpected prediction format: ${output?.javaClass}")
                    0
                }
            }

            // Handle probabilities
            val probabilities = when (outputInfo) {
                is Array<*> -> {
                    when {
                        outputInfo.isArrayOf<FloatArray>() -> (outputInfo as Array<FloatArray>)[0]
                        else -> floatArrayOf()
                    }
                }
                is FloatArray -> outputInfo
                else -> floatArrayOf()
            }

            // Class mapping (must match Python model)
            val classNames = listOf("EXPLOIT", "FLOODING", "INJECTION", "NORMAL", "SPOOFING")
            val predictedType = classNames.getOrElse(predictedClass) { "UNKNOWN" }
            val confidence = if (probabilities.isNotEmpty()) {
                probabilities[predictedClass].toDouble()
            } else {
                0.8 // Default confidence if probabilities not available
            }

            // Clean up
            inputTensor.close()
            results.close()

            val isAttack = predictedType != "NORMAL" && predictedType != "UNKNOWN"

            Log.d("IDS", "ONNX prediction: $predictedType (${String.format("%.2f", confidence)})")

            // Apply stricter confidence threshold for ONNX
            return if (isAttack && confidence >= confidenceThreshold) {
                // Update device attack score
                deviceStats[record.fromDevice]?.let {
                    it.attackScore = minOf(it.attackScore + confidence * 0.1, 1.0)
                    it.lastAttackTime = System.currentTimeMillis()
                }

                AnalysisResult(
                    isAttack = true,
                    attackType = predictedType,
                    confidence = confidence,
                    explanation = "AI model detected $predictedType attack pattern",
                    features = features,
                    patternMatch = detectPatternMatch(record.message, predictedType)
                )
            } else {
                AnalysisResult(
                    isAttack = false,
                    attackType = "NORMAL",
                    confidence = if (predictedType == "NORMAL") confidence else 1.0 - confidence,
                    explanation = "Normal communication pattern",
                    features = features
                )
            }

        } catch (e: Exception) {
            Log.e("IDS", "ONNX detection error: ${e.message}", e)
            return null
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

        // Consider device history - only boost if there's significant attack history
        val historyMultiplier = if (stats.attackScore > 0.7) 1.1 else 1.0

        val scores = mapOf(
            "INJECTION" to injectionScore * historyMultiplier,
            "SPOOFING" to spoofingScore * historyMultiplier,
            "FLOODING" to floodingScore * historyMultiplier,
            "EXPLOIT" to exploitScore * historyMultiplier
        )

        val maxEntry = scores.maxByOrNull { it.value }
        val detectedType = maxEntry?.key ?: "NORMAL"
        val confidence = minOf(maxEntry?.value ?: 0.0, 1.0)

        // More strict detection criteria
        val isAttack = confidence > ruleBasedThreshold && detectedType != "NORMAL"

        if (isAttack) {
            stats.attackScore = minOf(stats.attackScore + confidence * 0.1, 1.0)
            stats.lastAttackTime = System.currentTimeMillis()
        }

        return AnalysisResult(
            isAttack = isAttack,
            attackType = if (isAttack) detectedType else "NORMAL",
            confidence = if (isAttack) confidence else 1.0 - confidence,
            explanation = if (isAttack) {
                "Rule-based detection: $detectedType pattern"
            } else {
                "Normal communication"
            },
            features = features,
            patternMatch = if (isAttack) detectPatternMatch(message, detectedType) else ""
        )
    }

    private fun calculateAttackScore(message: String, features: FloatArray, attackType: String): Double {
        var score = 0.0
        var patternMatches = 0
        val messageLength = message.length

        when (attackType) {
            "INJECTION" -> {
                // Look for specific injection patterns
                injectionPatterns.forEach { pattern ->
                    if (pattern.containsMatchIn(message)) {
                        score += 0.25  // Reduced from 0.3
                        patternMatches++
                    }
                }
                // Feature-based scoring with stricter thresholds
                if (features[9] > 0.7 && message.contains("{") && message.contains("}")) score += 0.3  // JSON with brackets
                if (features[10] > 0.7 && message.contains("<") && message.contains(">")) score += 0.3  // HTML with tags
                if (features[12] > 0.7 && message.contains(Regex("(exec|system|rm|delete)", RegexOption.IGNORE_CASE))) score += 0.3

                // Require multiple indicators for injection
                if (patternMatches < 2 && score < 0.5) score *= 0.5
            }
            "SPOOFING" -> {
                spoofingPatterns.forEach { pattern ->
                    if (pattern.containsMatchIn(message)) {
                        score += 0.2  // Reduced from 0.3
                        patternMatches++
                    }
                }
                // Require both URL and urgency for spoofing
                val hasUrl = features[13] > 0.5 || message.contains(Regex("http|www\\.", RegexOption.IGNORE_CASE))
                val hasUrgency = message.contains(Regex("urgent|immediate|click|verify", RegexOption.IGNORE_CASE))

                if (hasUrl && hasUrgency) {
                    score += 0.4
                } else if (hasUrl || hasUrgency) {
                    score += 0.2
                }

                // Check for credential requests
                if (features[14] > 0.5 && message.contains(Regex("password|login", RegexOption.IGNORE_CASE))) {
                    score += 0.3
                }

                // Reduce score if no URL present
                if (!hasUrl) score *= 0.6
            }
            "FLOODING" -> {
                // More specific flooding detection
                floodingPatterns.forEach { pattern ->
                    if (pattern.containsMatchIn(message)) {
                        score += 0.5  // Higher score for exact flood patterns
                        patternMatches++
                    }
                }

                // Check for specific flood characteristics
                if (message.startsWith("FLOOD_") && message.matches(Regex("FLOOD_\\d+"))) {
                    score = 1.0  // Definite flood pattern
                } else if (messageLength > 500 && features[17] > 0.7) {
                    score += 0.4  // Long repetitive message
                } else if (message.matches(Regex("^[A-Z0-9_]+$")) && messageLength > 20) {
                    score += 0.3  // All caps pattern
                }

                // Reduce false positives for normal long messages
                if (message.contains(" ") && message.split(" ").size > 5) {
                    score *= 0.5  // Normal sentence structure
                }
            }
            "EXPLOIT" -> {
                exploitPatterns.forEach { pattern ->
                    if (pattern.containsMatchIn(message)) {
                        score += 0.35
                        patternMatches++
                    }
                }
                // Specific exploit indicators
                if (message.contains(Regex("AT\\+", RegexOption.IGNORE_CASE))) score += 0.5  // AT commands
                if (features[4] > 0.7 && features[11] > 0.5) score += 0.4  // Binary + hex
                if (message.contains(Regex("\\\\x[0-9a-fA-F]{2}"))) score += 0.4  // Hex encoding

                // Require strong indicators for exploit
                if (patternMatches == 0 && score < 0.5) score = 0.0
            }
        }

        // Apply penalties for normal message characteristics
        if (message.matches(Regex("^[a-zA-Z0-9\\s.,!?'-]+$")) && messageLength < 200) {
            // Normal alphanumeric message with punctuation
            score *= 0.3
        }

        // Common greetings and phrases should not be attacks
        val normalPhrases = listOf(
            "hello", "hi", "hey", "good morning", "good evening", "thank you",
            "thanks", "please", "yes", "no", "okay", "ok", "bye", "goodbye",
            "how are you", "what's up", "see you", "talk to you later"
        )

        if (normalPhrases.any { message.lowercase().contains(it) } && patternMatches == 0) {
            score *= 0.1
        }

        return minOf(score, 1.0)
    }

    private fun updateDeviceStats(record: MessageRecord) {
        // Clean old messages
        val now = System.currentTimeMillis()
        deviceMessageHistory.values.forEach { messages ->
            messages.removeAll { now - it.timestamp > historyWindowMs }
        }

        // Update history
        val history = deviceMessageHistory.computeIfAbsent(record.fromDevice) {
            Collections.synchronizedList(mutableListOf())
        }
        history.add(record)

        // Update stats
        val stats = deviceStats.computeIfAbsent(record.fromDevice) { DeviceStats() }
        stats.messageCount++
        stats.lastSeen = record.timestamp

        // Update averages
        val messageLength = record.message.length.toFloat()
        stats.avgMessageLength = (stats.avgMessageLength * (stats.messageCount - 1) + messageLength) / stats.messageCount
        stats.entropySum += calculateEntropy(record.message)

        // Count commands
        if (containsCommandPattern(record.message)) {
            stats.commandCount++
        }

        // Decay attack score
        val timeSinceLastAttack = now - stats.lastAttackTime
        if (timeSinceLastAttack > 300000) { // 5 minutes
            stats.attackScore *= 0.9
        }
    }

    private fun containsCommandPattern(message: String): Boolean {
        return injectionPatterns.any { it.containsMatchIn(message) } ||
                exploitPatterns.any { it.containsMatchIn(message) }
    }


    private fun detectPatternMatch(message: String, attackType: String): String {
        val matches = mutableListOf<String>()

        when (attackType) {
            "INJECTION" -> {
                if (message.contains(Regex("""\{.*:.*\}"""))) matches.add("JSON structure")
                if (message.contains(Regex("""<\w+>.*<\/\w+>"""))) matches.add("HTML tags")
                if (message.contains(Regex("""(cmd|exec|run|system|rm|delete)""", RegexOption.IGNORE_CASE))) {
                    matches.add("Command execution")
                }
                if (message.contains(Regex("""(SELECT|INSERT|UPDATE|DELETE)""", RegexOption.IGNORE_CASE))) {
                    matches.add("SQL injection")
                }
            }
            "SPOOFING" -> {
                if (message.contains(Regex("""(urgent|immediate)""", RegexOption.IGNORE_CASE))) {
                    matches.add("Urgency tactics")
                }
                if (message.contains(Regex("""(http|www\.)""", RegexOption.IGNORE_CASE))) {
                    matches.add("Suspicious URL")
                }
                if (message.contains(Regex("""(password|credential)""", RegexOption.IGNORE_CASE))) {
                    matches.add("Credential phishing")
                }
            }
            "FLOODING" -> {
                if (message.contains(Regex("""FLOOD_\d+"""))) matches.add("Flood signature")
                if (message.length > 500) matches.add("Oversized message")
                if (message.contains(Regex("""(.)\1{10,}"""))) matches.add("Character flooding")
            }
            "EXPLOIT" -> {
                if (message.contains(Regex("""\\x[0-9a-fA-F]{2}"""))) matches.add("Hex encoding")
                if (message.contains(Regex("""AT\+"""))) matches.add("AT command")
                if (message.contains(Regex("""[\x00-\x1F\x7F-\xFF]"""))) matches.add("Binary payload")
            }
        }

        return matches.joinToString(", ").ifEmpty { "Suspicious pattern" }
    }

    private fun extractEnhancedFeatures(record: MessageRecord): FloatArray {
        val features = FloatArray(featureCount)
        val message = record.message
        val currentTime = System.currentTimeMillis()
        val stats = deviceStats[record.fromDevice] ?: DeviceStats()
        val history = deviceMessageHistory[record.fromDevice] ?: emptyList()

        // Basic Message Features (0-4)
        features[0] = minOf(message.length.toFloat(), maxMessageLength.toFloat()) / maxMessageLength
        features[1] = calculateEntropy(message)
        features[2] = message.count { it.isDigit() }.toFloat() / message.length.coerceAtLeast(1).toFloat()
        features[3] = message.count { !it.isLetterOrDigit() }.toFloat() / message.length.coerceAtLeast(1).toFloat()
        features[4] = if (message.any { it.code < 32 || it.code > 126 }) 1f else 0f

        // Temporal Features (5-8)
        features[5] = if (stats.lastSeen > 0) {
            minOf((currentTime - stats.lastSeen).toFloat() / 60000f, 1f)
        } else 0.5f
        features[6] = Calendar.getInstance().get(Calendar.HOUR_OF_DAY).toFloat() / 24f
        features[7] = Calendar.getInstance().get(Calendar.DAY_OF_WEEK).toFloat() / 7f
        features[8] = minOf(stats.messageCount.toFloat() / 100f, 1f)

        // Content Patterns (9-14)
        features[9] = if (message.contains(Regex("""[\{\[].*[:=].*[\}\]]"""))) 1f else 0f
        features[10] = if (message.contains(Regex("""<[^>]+>"""))) 1f else 0f
        features[11] = if (message.contains(Regex("""(\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2})"""))) 1f else 0f
        features[12] = if (message.contains(Regex("""(admin|root|system|cmd|exec|sudo|rm|delete)""", RegexOption.IGNORE_CASE))) 1f else 0f
        features[13] = if (message.contains(Regex("""(http|ftp|www\.|\.com|\.org)""", RegexOption.IGNORE_CASE))) 1f else 0f
        features[14] = if (message.contains(Regex("""(password|login|credential|username|auth|token)""", RegexOption.IGNORE_CASE))) 1f else 0f

        // Behavioral Features (15-19)
        features[15] = stats.avgMessageLength / maxMessageLength
        features[16] = if (stats.messageCount > 0) stats.entropySum / stats.messageCount else 0.5f
        features[17] = calculateMessageRepeatScore(record, history)
        features[18] = minOf(stats.commandCount.toFloat() / 10f, 1f)
        features[19] = calculateDirectionChangeScore(record, history)

        // Device Context (20-21)
        features[20] = if (stats.messageCount > 10) 1f else stats.messageCount / 10f
        features[21] = if (history.size > 5) {
            history.takeLast(5).count { it.message.length > 100 }.toFloat() / 5f
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

        return (entropy / 8.0).toFloat().coerceIn(0f, 1f)
    }

    private fun calculateMessageRepeatScore(record: MessageRecord, history: List<MessageRecord>): Float {
        if (history.isEmpty()) return 0f

        val recentHistory = history.takeLast(10)
        val similarCount = recentHistory.count {
            it.message == record.message ||
                    (it.message.length > 10 && record.message.contains(it.message.substring(0, 10)))
        }

        return minOf(similarCount.toFloat() / 5f, 1f)
    }

    private fun calculateDirectionChangeScore(record: MessageRecord, history: List<MessageRecord>): Float {
        if (history.isEmpty()) return 0f

        val recentHistory = history.takeLast(5)
        val directionChanges = recentHistory.zipWithNext().count { (a, b) -> a.direction != b.direction }

        return directionChanges.toFloat() / recentHistory.size.coerceAtLeast(1)
    }

    suspend fun runTestCases(): List<Pair<String, AnalysisResult>> = withContext(Dispatchers.Default) {
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
            "Meeting at 3pm tomorrow" to "NORMAL"
        )

        Log.d("IDS", "Running ${testCases.size} test cases...")
        testCases.map { (message, expectedType) ->
            val result = analyzeMessage(message, "TestDevice", "TargetDevice")
            val passed = if (expectedType == "NORMAL") !result.isAttack else result.attackType == expectedType

            Log.d("IDS", "Test: ${message.take(50)}...")
            Log.d("IDS", "Expected: $expectedType, Got: ${result.attackType}, Passed: $passed")
            Log.d("IDS", "Confidence: ${String.format("%.2f", result.confidence)}, Pattern: ${result.patternMatch}")

            message to result
        }
    }

    fun getDeviceStats(deviceId: String): DeviceStats? = deviceStats[deviceId]

    fun getAllDeviceStats(): Map<String, DeviceStats> = deviceStats.toMap()

    fun clearDeviceHistory(deviceId: String) {
        deviceMessageHistory.remove(deviceId)
        deviceStats.remove(deviceId)
        activeAttacks.keys.removeIf { it.startsWith("$deviceId:") }
    }

    fun getAttackSummary(): Map<String, Int> {
        return activeAttacks.values.groupBy { it.attackType }
            .mapValues { it.value.sumOf { state -> state.count } }
    }

    fun resetModel() {
        deviceMessageHistory.clear()
        deviceStats.clear()
        activeAttacks.clear()
        rateLimiter.lastNotificationTime.clear()
        rateLimiter.notificationCounts.clear()
    }

    fun cleanup() {
        try {
            ortSession?.close()
            ortEnvironment?.close()
            resetModel()
        } catch (e: Exception) {
            Log.e("IDS", "Cleanup error", e)
        }
    }

    companion object {
        // Configuration constants
        const val DEFAULT_CONFIDENCE_THRESHOLD = 0.6
        const val DEFAULT_COOLDOWN_MS = 30000L
        const val DEFAULT_GROUPING_WINDOW_MS = 5000L

        // Feature indices for reference
        const val FEATURE_MESSAGE_LENGTH = 0
        const val FEATURE_ENTROPY = 1
        const val FEATURE_DIGIT_RATIO = 2
        const val FEATURE_SPECIAL_CHAR_RATIO = 3
        const val FEATURE_BINARY_DATA = 4
        const val FEATURE_TIME_SINCE_LAST = 5
        const val FEATURE_HOUR_OF_DAY = 6
        const val FEATURE_DAY_OF_WEEK = 7
        const val FEATURE_MESSAGE_FREQUENCY = 8
        const val FEATURE_JSON_PATTERN = 9
        const val FEATURE_HTML_PATTERN = 10
        const val FEATURE_HEX_ENCODING = 11
        const val FEATURE_COMMAND_PATTERN = 12
        const val FEATURE_URL_PATTERN = 13
        const val FEATURE_CREDENTIAL_PATTERN = 14
        const val FEATURE_AVG_MESSAGE_LENGTH = 15
        const val FEATURE_AVG_ENTROPY = 16
        const val FEATURE_MESSAGE_REPEAT = 17
        const val FEATURE_COMMAND_COUNT = 18
        const val FEATURE_DIRECTION_CHANGE = 19
        const val FEATURE_HIGH_MESSAGE_COUNT = 20
        const val FEATURE_RECENT_LARGE_MESSAGES = 21
    }
}