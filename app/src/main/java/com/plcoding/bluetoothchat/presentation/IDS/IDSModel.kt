package com.plcoding.bluetoothchat.presentation.IDS
import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import java.nio.FloatBuffer
import java.util.Collections

class IDSModel(context: Context) {
    private val ortEnv = OrtEnvironment.getEnvironment()
    private lateinit var ortSession: OrtSession
    private val featureCount = 22 // Update this to match your model's input features

    companion object {
        // Class labels must match your Python model's output order
        private val CLASS_LABELS = arrayOf("normal", "flooding", "injection", "spoofing")
    }

    init {
        try {
            context.assets.open("bluetooth_ids_model.onnx").use { inputStream ->
                val modelBytes = inputStream.readBytes()
                val sessionOptions = OrtSession.SessionOptions()
                ortSession = ortEnv.createSession(modelBytes, sessionOptions)
            }
        } catch (e: Exception) {
            throw RuntimeException("Failed to load ONNX model", e)
        }
    }

    fun predict(features: FloatArray): String {
        require(features.size == featureCount) {
            "Expected $featureCount features, got ${features.size}"
        }

        return try {
            // 1. Create input tensor with shape [1, featureCount]
            val inputBuffer = FloatBuffer.wrap(features)
            val inputTensor = OnnxTensor.createTensor(ortEnv, inputBuffer, longArrayOf(1, featureCount.toLong()))

            // 2. Run inference
            val output = ortSession.run(Collections.singletonMap("float_input", inputTensor))

            // 3. Process output (adjust based on your model's output layer)
            val rawOutput = output?.get(0)?.value
            when (rawOutput) {
                is Array<*> -> decodeMultiClassOutput(rawOutput)
                is Long -> CLASS_LABELS[rawOutput.toInt()]
                else -> "unknown"
            }.also {
                output?.close()
                inputTensor.close()
            }
        } catch (e: Exception) {
            "prediction_error: ${e.message}"
        }
    }

    private fun decodeMultiClassOutput(output: Array<*>): String {
        return when {
            // Case 1: Output is array of probabilities
            output.first() is FloatArray -> {
                val probs = (output.first() as FloatArray)
                CLASS_LABELS[probs.indices.maxBy { probs[it] }]
            }
            // Case 2: Output is direct class index
            output.first() is Long -> {
                CLASS_LABELS[(output.first() as Long).toInt()]
            }
            else -> "unknown"
        }
    }

    fun close() {
        ortSession.close()
    }
}