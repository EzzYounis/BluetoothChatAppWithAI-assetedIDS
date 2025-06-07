// presentation/IDS/IDSModel.kt
package com.plcoding.bluetoothchat.presentation.IDS

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import android.util.Log
import java.nio.FloatBuffer
import java.util.*
import java.util.Collections
import kotlin.math.max

class IDSModel(context: Context) {
    private val ortEnv = OrtEnvironment.getEnvironment()
    private val featureCount = 22 // Must match your model's input features
    val modelName = "BluetoothThreat-v3.1"
    private lateinit var ortSession: OrtSession

    data class AnalysisResult(
        val isAttack: Boolean,
        val attackType: String,
        val aiDetected: Boolean,
        val matchedPattern: String,
        val explanation: String
    )

    init {
        try {
            context.assets.open("bluetooth_ids_model.onnx").use { inputStream ->
                val modelBytes = inputStream.readBytes()
                ortSession = ortEnv.createSession(modelBytes)
            }
        } catch (e: Exception) {
            Log.e("IDSModel", "ONNX model loading failed", e)
            throw RuntimeException("Failed to load ONNX model: ${e.message}", e)

        }
    }

    fun analyzeMessage(message: String): AnalysisResult {
        // Rule-based detection first
        val ruleBasedResult = detectWithRules(message)
        if (ruleBasedResult != null) return ruleBasedResult

        // AI model detection
        return detectWithAI(message)
    }


    private fun detectWithRules(message: String): AnalysisResult? {
        return when {
            isSpoofing(message) -> AnalysisResult(
                isAttack = true,
                attackType = "spoofing",
                aiDetected = false,
                matchedPattern = "Malicious URL/Content",
                explanation = "Contains phishing attempt"
            )

            isInjection(message) -> AnalysisResult(
                isAttack = true,
                attackType = "injection",
                aiDetected = false,
                matchedPattern = "Malicious Syntax",
                explanation = "Contains code injection pattern"
            )

            isFlooding(message) -> AnalysisResult(
                isAttack = true,
                attackType = "flooding",
                aiDetected = false,
                matchedPattern = "Message Flood",
                explanation = "High frequency or large message size"
            )

            else -> null
        }
    }

    private fun isSpoofing(message: String): Boolean {
        return message.contains(Regex("http://|https://")) ||
                message.contains("click here", ignoreCase = true) ||
                message.contains("urgent", ignoreCase = true)
    }

    private fun isInjection(message: String): Boolean {
        return message.contains("' OR") ||
                message.contains("{malicious:") ||
                message.contains("ADMIN COMMAND")
    }

    private fun isFlooding(message: String): Boolean {
        return message.length > 500 ||
                message.split(" ").size > 100
    }

    private fun detectWithAI(message: String): AnalysisResult {
        val features = extractFeatures(message)
        val inputTensor = OnnxTensor.createTensor(
            ortEnv,
            FloatBuffer.wrap(features),
            longArrayOf(1, features.size.toLong())
        )

        val output = ortSession.run(Collections.singletonMap("float_input", inputTensor))
        val prediction = processOutput(output)
        val confidence = getConfidence(output)

        return AnalysisResult(
            isAttack = prediction != "normal",
            attackType = prediction,
            aiDetected = true,
            matchedPattern = "AI-detected anomaly",
            explanation = "Model confidence: ${"%.1f".format(confidence * 100)}%"
        )
    }

    private fun extractFeatures(message: String): FloatArray {
        // Implement your feature extraction logic
        return FloatArray(featureCount).apply {
            // Example features - replace with your actual feature extraction
            this[0] = message.length.toFloat()              // Message length
            this[1] = message.split(" ").size.toFloat()     // Word count
            this[2] = if (isSpoofing(message)) 1f else 0f   // Spoofing flag
            this[3] = if (isInjection(message)) 1f else 0f  // Injection flag
            // ... add all 22 features
        }
    }

    private fun processOutput(output: OrtSession.Result): String {
        return when (val rawOutput = output?.get(0)?.value) {
            is Array<*> -> CLASS_LABELS[(rawOutput.first() as FloatArray).indices.maxBy {
                (rawOutput.first() as FloatArray)[it]
            }]

            is Long -> CLASS_LABELS[rawOutput.toInt()]
            else -> "unknown"
        }
    }

    private fun getConfidence(output: OrtSession.Result): Float {
        return when (val rawOutput = output?.get(0)?.value) {
            is Array<*> -> (rawOutput.first() as FloatArray).maxOrNull() ?: 0f
            else -> 0f
        }
    }

    fun close() {
        ortSession.close()
    }

    companion object {
        private val CLASS_LABELS = arrayOf("normal", "flooding", "injection", "spoofing")
    }

    fun predict(features: FloatArray): String {
        require(features.size == featureCount) {
            "Expected $featureCount features, got ${features.size}"
        }

        return try {
            val inputBuffer = FloatBuffer.wrap(features)
            val inputTensor =
                OnnxTensor.createTensor(ortEnv, inputBuffer, longArrayOf(1, featureCount.toLong()))

            val output = ortSession.run(Collections.singletonMap("float_input", inputTensor))
            processOutput(output).also {
                output?.close()
                inputTensor.close()
            }
        } catch (e: Exception) {
            "prediction_error: ${e.message}"
        }
    }

}