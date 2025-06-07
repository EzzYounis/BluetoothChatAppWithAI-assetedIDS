package IDS

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import android.util.Log
import java.nio.FloatBuffer
import java.util.Collections

class IDSModelHelper(private val context: Context) {

    companion object {
        private const val TAG = "IDSModelHelper"
        val CLASS_NAMES = listOf("normal", "flooding", "injection", "spoofing")
        const val EXPECTED_FEATURE_COUNT = 22
    }

    private lateinit var env: OrtEnvironment
    private lateinit var session: OrtSession

    fun initializeModel() {
        try {
            env = OrtEnvironment.getEnvironment()
            val modelStream = context.assets.open("bluetooth_ids_model.onnx")
            val modelBytes = modelStream.readBytes()
            session = env.createSession(modelBytes)

            Log.d(TAG, "Model initialized successfully")
            Log.d(TAG, "Input names: ${session.inputNames}")
            Log.d(TAG, "Output names: ${session.outputNames}")
        } catch (e: Exception) {
            Log.e(TAG, "Model initialization failed", e)
            throw RuntimeException("Failed to initialize ONNX model", e)
        }
    }

    fun predict(features: FloatArray): Pair<String, FloatArray?>? {
        if (!::session.isInitialized) {
            initializeModel()
        }

        if (features.size != EXPECTED_FEATURE_COUNT) {
            Log.e(TAG, "Invalid feature count: ${features.size} (expected $EXPECTED_FEATURE_COUNT)")
            return null
        }

        var inputTensor: OnnxTensor? = null
        var output: OrtSession.Result? = null

        return try {
            // Prepare input tensor
            val inputName = session.inputNames.iterator().next()
            val inputShape = longArrayOf(1, EXPECTED_FEATURE_COUNT.toLong())
            inputTensor = OnnxTensor.createTensor(env, FloatBuffer.wrap(features), inputShape)

            // Run inference
            output = session.run(Collections.singletonMap(inputName, inputTensor))

            // Get output tensor
            val outputName = session.outputNames.iterator().next()
            val onnxValue = output?.get(outputName)

            if (onnxValue is OnnxTensor) {
                val outputArray = onnxValue.value as? Array<FloatArray> // Usually shape: [1][num_classes]

                if (outputArray != null && outputArray.isNotEmpty()) {
                    val probs = outputArray[0]
                    val predictedIndex = probs.indices.maxBy { probs[it] }
                    val predictedClass = CLASS_NAMES.getOrElse(predictedIndex) { "unknown" }
                    Pair(predictedClass, probs)
                } else {
                    Log.e(TAG, "Unexpected output tensor format or empty output.")
                    null
                }
            } else {
                Log.e(TAG, "Output is not an OnnxTensor.")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Prediction failed", e)
            null
        } finally {
            inputTensor?.close()
            output?.close()
        }
    }

    fun shutdown() {
        try {
            session.close()
            env.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing ONNX resources", e)
        }
    }
}
