package com.plcoding.bluetoothchat.presentation.IDS

import android.os.SystemClock
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.sqrt

/**
 * Performance tracking system for the IDS
 * Tracks accuracy, precision, recall, F1-scores, and resource consumption
 */
class IDSPerformanceTracker {

    // Performance metrics per attack type
    private val metrics = ConcurrentHashMap<String, AttackMetrics>()

    // Resource consumption tracking
    private val resourceMetrics = ResourceMetrics()

    // Detection timing
    private val detectionTimes = mutableListOf<Long>()
    private val detectionTimesLock = Any()

    // Ground truth for validation (in production, this would come from user feedback)
    private val groundTruth = ConcurrentHashMap<String, Boolean>()

    // Performance flow for UI updates
    private val _performanceFlow = MutableStateFlow(PerformanceReport())
    val performanceFlow: StateFlow<PerformanceReport> = _performanceFlow.asStateFlow()

    init {
        // Initialize metrics for each attack type
        listOf("FLOODING", "INJECTION", "SPOOFING", "EXPLOIT", "NORMAL").forEach { type ->
            metrics[type] = AttackMetrics(type)
        }

        // Start performance monitoring coroutine
        GlobalScope.launch {
            while (true) {
                delay(5000) // Update every 5 seconds
                updatePerformanceReport()
            }
        }
    }

    data class AttackMetrics(
        val attackType: String,
        var truePositives: AtomicInteger = AtomicInteger(0),
        var falsePositives: AtomicInteger = AtomicInteger(0),
        var trueNegatives: AtomicInteger = AtomicInteger(0),
        var falseNegatives: AtomicInteger = AtomicInteger(0),
        var totalDetections: AtomicInteger = AtomicInteger(0)
    ) {
        fun calculateAccuracy(): Double {
            val total = truePositives.get() + falsePositives.get() +
                    trueNegatives.get() + falseNegatives.get()
            if (total == 0) return 0.0
            return (truePositives.get() + trueNegatives.get()).toDouble() / total
        }

        fun calculatePrecision(): Double {
            val denominator = truePositives.get() + falsePositives.get()
            if (denominator == 0) return 0.0
            return truePositives.get().toDouble() / denominator
        }

        fun calculateRecall(): Double {
            val denominator = truePositives.get() + falseNegatives.get()
            if (denominator == 0) return 0.0
            return truePositives.get().toDouble() / denominator
        }

        fun calculateF1Score(): Double {
            val precision = calculatePrecision()
            val recall = calculateRecall()
            if ((precision + recall).toInt() == 0) return 0.0
            return 2 * (precision * recall) / (precision + recall)
        }
    }

    data class ResourceMetrics(
        var totalMemoryUsage: AtomicLong = AtomicLong(0),
        var peakMemoryUsage: AtomicLong = AtomicLong(0),
        var totalCpuTime: AtomicLong = AtomicLong(0),
        var detectionCount: AtomicInteger = AtomicInteger(0),
        var startTime: Long = System.currentTimeMillis()
    ) {
        fun getAverageMemoryUsage(): Long {
            val count = detectionCount.get()
            if (count == 0) return 0
            return totalMemoryUsage.get() / count
        }

        fun getAverageCpuUsage(): Double {
            val elapsed = System.currentTimeMillis() - startTime
            if (elapsed == 0L) return 0.0
            return (totalCpuTime.get().toDouble() / elapsed) * 100
        }
    }

    data class PerformanceReport(
        val attackMetrics: Map<String, AttackTypePerformance> = emptyMap(),
        val overallAccuracy: Double = 0.0,
        val overallPrecision: Double = 0.0,
        val overallRecall: Double = 0.0,
        val overallF1Score: Double = 0.0,
        val averageDetectionTime: Double = 0.0,
        val maxDetectionTime: Long = 0,
        val messagesPerSecond: Double = 0.0,
        val falsePositiveRate: Double = 0.0,
        val averageMemoryUsageMB: Double = 0.0,
        val peakMemoryUsageMB: Double = 0.0,
        val cpuUsagePercent: Double = 0.0,
        val totalMessagesProcessed: Int = 0,
        val totalAttacksDetected: Int = 0,
        val timestamp: Long = System.currentTimeMillis()
    )

    data class AttackTypePerformance(
        val attackType: String,
        val accuracy: Double,
        val precision: Double,
        val recall: Double,
        val f1Score: Double,
        val detectionCount: Int
    )

    /**
     * Record a detection result for performance tracking
     */
    fun recordDetection(
        predictedType: String,
        actualType: String,
        confidence: Double,
        detectionTimeMs: Long,
        memoryUsageBytes: Long,
        cpuTimeNanos: Long
    ) {
        // Update metrics based on prediction vs actual
        val metric = metrics[predictedType] ?: return

        when {
            predictedType == actualType && actualType != "NORMAL" -> {
                metric.truePositives.incrementAndGet()
            }
            predictedType == actualType && actualType == "NORMAL" -> {
                metric.trueNegatives.incrementAndGet()
            }
            predictedType != "NORMAL" && actualType == "NORMAL" -> {
                metric.falsePositives.incrementAndGet()
            }
            predictedType == "NORMAL" && actualType != "NORMAL" -> {
                metric.falseNegatives.incrementAndGet()
            }
        }

        metric.totalDetections.incrementAndGet()

        // Update resource metrics
        resourceMetrics.totalMemoryUsage.addAndGet(memoryUsageBytes)
        resourceMetrics.peakMemoryUsage.updateAndGet { current ->
            maxOf(current, memoryUsageBytes)
        }
        resourceMetrics.totalCpuTime.addAndGet(cpuTimeNanos / 1_000_000) // Convert to ms
        resourceMetrics.detectionCount.incrementAndGet()

        // Update detection times
        synchronized(detectionTimesLock) {
            detectionTimes.add(detectionTimeMs)
            if (detectionTimes.size > 1000) {
                detectionTimes.removeAt(0)
            }
        }
    }

    /**
     * Record a detection with automatic resource measurement
     */
    fun recordDetectionAuto(
        predictedType: String,
        actualType: String,
        confidence: Double,
        startTime: Long
    ) {
        val detectionTime = System.currentTimeMillis() - startTime
        val runtime = Runtime.getRuntime()
        val memoryUsage = runtime.totalMemory() - runtime.freeMemory()
        val cpuTime = SystemClock.currentThreadTimeMillis()

        recordDetection(
            predictedType = predictedType,
            actualType = actualType,
            confidence = confidence,
            detectionTimeMs = detectionTime,
            memoryUsageBytes = memoryUsage,
            cpuTimeNanos = cpuTime * 1_000_000
        )
    }

    /**
     * Update the performance report with current metrics
     */
    private fun updatePerformanceReport() {
        val attackMetricsMap = mutableMapOf<String, AttackTypePerformance>()
        var totalTP = 0
        var totalFP = 0
        var totalTN = 0
        var totalFN = 0
        var totalDetections = 0

        // Calculate per-attack-type metrics
        metrics.forEach { (type, metric) ->
            if (metric.totalDetections.get() > 0) {
                attackMetricsMap[type] = AttackTypePerformance(
                    attackType = type,
                    accuracy = metric.calculateAccuracy(),
                    precision = metric.calculatePrecision(),
                    recall = metric.calculateRecall(),
                    f1Score = metric.calculateF1Score(),
                    detectionCount = metric.totalDetections.get()
                )

                totalTP += metric.truePositives.get()
                totalFP += metric.falsePositives.get()
                totalTN += metric.trueNegatives.get()
                totalFN += metric.falseNegatives.get()
                totalDetections += metric.totalDetections.get()
            }
        }

        // Calculate overall metrics
        val overallAccuracy = if (totalDetections > 0) {
            (totalTP + totalTN).toDouble() / totalDetections
        } else 0.0

        val overallPrecision = if (totalTP + totalFP > 0) {
            totalTP.toDouble() / (totalTP + totalFP)
        } else 0.0

        val overallRecall = if (totalTP + totalFN > 0) {
            totalTP.toDouble() / (totalTP + totalFN)
        } else 0.0

        val overallF1 = if (overallPrecision + overallRecall > 0) {
            2 * (overallPrecision * overallRecall) / (overallPrecision + overallRecall)
        } else 0.0

        val falsePositiveRate = if (totalFP + totalTN > 0) {
            totalFP.toDouble() / (totalFP + totalTN)
        } else 0.0

        // Calculate timing metrics
        val (avgDetectionTime, maxDetectionTime) = synchronized(detectionTimesLock) {
            if (detectionTimes.isEmpty()) {
                0.0 to 0L
            } else {
                detectionTimes.average() to detectionTimes.maxOrNull()!!
            }
        }

        // Calculate throughput
        val elapsedSeconds = (System.currentTimeMillis() - resourceMetrics.startTime) / 1000.0
        val messagesPerSecond = if (elapsedSeconds > 0) {
            totalDetections / elapsedSeconds
        } else 0.0

        // Update the performance report
        _performanceFlow.value = PerformanceReport(
            attackMetrics = attackMetricsMap,
            overallAccuracy = overallAccuracy,
            overallPrecision = overallPrecision,
            overallRecall = overallRecall,
            overallF1Score = overallF1,
            averageDetectionTime = avgDetectionTime,
            maxDetectionTime = maxDetectionTime,
            messagesPerSecond = messagesPerSecond,
            falsePositiveRate = falsePositiveRate,
            averageMemoryUsageMB = resourceMetrics.getAverageMemoryUsage() / (1024.0 * 1024.0),
            peakMemoryUsageMB = resourceMetrics.peakMemoryUsage.get() / (1024.0 * 1024.0),
            cpuUsagePercent = resourceMetrics.getAverageCpuUsage(),
            totalMessagesProcessed = totalDetections,
            totalAttacksDetected = totalTP,
            timestamp = System.currentTimeMillis()
        )
    }

    /**
     * Generate a formatted performance report string
     */
    fun generatePerformanceReportString(): String {
        val report = _performanceFlow.value
        val sb = StringBuilder()

        sb.appendLine("=== IDS PERFORMANCE REPORT ===")
        sb.appendLine("Generated: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(report.timestamp))}")
        sb.appendLine()

        // Attack type performance table
        sb.appendLine("7.1 Detection Performance")
        sb.appendLine("Attack Type | Accuracy | Precision | Recall | F1-Score")
        sb.appendLine("------------|----------|-----------|--------|----------")

        report.attackMetrics.values
            .filter { it.attackType != "NORMAL" }
            .sortedByDescending { it.accuracy }
            .forEach { metric ->
                sb.appendLine(String.format("%-11s | %6.1f%% | %7.1f%% | %6.1f%% | %6.1f%%",
                    metric.attackType,
                    metric.accuracy * 100,
                    metric.precision * 100,
                    metric.recall * 100,
                    metric.f1Score * 100
                ))
            }

        sb.appendLine("------------|----------|-----------|--------|----------")
        sb.appendLine(String.format("%-11s | %6.1f%% | %7.1f%% | %6.1f%% | %6.1f%%",
            "Overall",
            report.overallAccuracy * 100,
            report.overallPrecision * 100,
            report.overallRecall * 100,
            report.overallF1Score * 100
        ))

        sb.appendLine()
        sb.appendLine("7.2 Performance Comparison")
        sb.appendLine("Method | Accuracy | False Positive Rate | Avg. Detection Time")
        sb.appendLine("-------|----------|---------------------|--------------------")
        sb.appendLine(String.format("Hybrid | %6.1f%% | %17.1f%% | %15.0fms",
            report.overallAccuracy * 100,
            report.falsePositiveRate * 100,
            report.averageDetectionTime
        ))

        sb.appendLine()
        sb.appendLine("7.3 Resource Consumption")
        sb.appendLine("* Memory Usage: ${String.format("%.1f", report.averageMemoryUsageMB)}MB average (${String.format("%.1f", report.peakMemoryUsageMB)}MB peak)")
        sb.appendLine("* CPU Usage: ${String.format("%.1f", report.cpuUsagePercent)}%")

        sb.appendLine()
        sb.appendLine("7.4 Real-time Performance")
        sb.appendLine("* Average detection latency: ${String.format("%.0f", report.averageDetectionTime)}ms")
        sb.appendLine("* Maximum observed latency: ${report.maxDetectionTime}ms")
        sb.appendLine("* Messages processed per second: ${String.format("%.1f", report.messagesPerSecond)}")
        sb.appendLine("* Total messages processed: ${report.totalMessagesProcessed}")
        sb.appendLine("* Total attacks detected: ${report.totalAttacksDetected}")

        return sb.toString()
    }

    /**
     * Reset all performance metrics
     */
    fun reset() {
        metrics.values.forEach { metric ->
            metric.truePositives.set(0)
            metric.falsePositives.set(0)
            metric.trueNegatives.set(0)
            metric.falseNegatives.set(0)
            metric.totalDetections.set(0)
        }

        resourceMetrics.totalMemoryUsage.set(0)
        resourceMetrics.peakMemoryUsage.set(0)
        resourceMetrics.totalCpuTime.set(0)
        resourceMetrics.detectionCount.set(0)
        resourceMetrics.startTime = System.currentTimeMillis()

        synchronized(detectionTimesLock) {
            detectionTimes.clear()
        }

        groundTruth.clear()
        updatePerformanceReport()
    }

    /**
     * Set ground truth for a message (for validation purposes)
     */
    fun setGroundTruth(messageId: String, isAttack: Boolean, attackType: String?) {
        groundTruth[messageId] = isAttack
    }
}

// Extension to format the performance report for logging
fun IDSPerformanceTracker.PerformanceReport.toLogString(): String {
    return buildString {
        appendLine("┌─── IDS PERFORMANCE METRICS ───")
        appendLine("│ Overall Accuracy: ${String.format("%.1f", overallAccuracy * 100)}%")
        appendLine("│ False Positive Rate: ${String.format("%.1f", falsePositiveRate * 100)}%")
        appendLine("│ Avg Detection Time: ${String.format("%.0f", averageDetectionTime)}ms")
        appendLine("│ Messages/Second: ${String.format("%.1f", messagesPerSecond)}")
        appendLine("│ CPU Usage: ${String.format("%.1f", cpuUsagePercent)}%")
        appendLine("│ Memory: ${String.format("%.1f", averageMemoryUsageMB)}MB")
        appendLine("└───────────────────────────────")
    }
}

private fun SimpleDateFormat(pattern: String, locale: Locale): SimpleDateFormat {
    return SimpleDateFormat(pattern, locale)
}