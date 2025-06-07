// com.plcoding.bluetoothchat.data.chat.AndroidBluetoothController.kt
package com.plcoding.bluetoothchat.data.chat

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.util.Log
import com.plcoding.bluetoothchat.domain.chat.BluetoothController
import com.plcoding.bluetoothchat.domain.chat.BluetoothDeviceDomain
import com.plcoding.bluetoothchat.domain.chat.BluetoothMessage
import com.plcoding.bluetoothchat.domain.chat.ConnectionResult
import com.plcoding.bluetoothchat.presentation.SecurityAlert
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.IOException
import java.util.*
import javax.inject.Inject
import java.util.concurrent.atomic.AtomicBoolean

@SuppressLint("MissingPermission")
class AndroidBluetoothController @Inject constructor(
    private val context: Context,
    private val messageLogDao: MessageLogDao?,
) : BluetoothController {
    private val activeConnections = mutableListOf<BluetoothDataTransferService>()
    private val connectionScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var onSecurityAlert: (SecurityAlert) -> Unit = { _ -> }
    fun setSecurityAlertCallback(callback: (SecurityAlert) -> Unit) {
        this.onSecurityAlert = callback
    }

    private val bluetoothManager by lazy {
        context.getSystemService(BluetoothManager::class.java)
    }
    private val bluetoothAdapter by lazy {
        bluetoothManager?.adapter
    }

    private var dataTransferService: BluetoothDataTransferService? = null
    private var currentServerSocket: BluetoothServerSocket? = null
    private var currentClientSocket: BluetoothSocket? = null

    private val _isConnected = MutableStateFlow(false)
    override val isConnected: StateFlow<Boolean>
        get() = _isConnected.asStateFlow()

    private val _scannedDevices = MutableStateFlow<List<BluetoothDeviceDomain>>(emptyList())
    override val scannedDevices: StateFlow<List<BluetoothDeviceDomain>>
        get() = _scannedDevices.asStateFlow()

    private val _pairedDevices = MutableStateFlow<List<BluetoothDeviceDomain>>(emptyList())
    override val pairedDevices: StateFlow<List<BluetoothDeviceDomain>>
        get() = _pairedDevices.asStateFlow()

    private val _errors = MutableSharedFlow<String>()
    override val errors: SharedFlow<String>
        get() = _errors.asSharedFlow()

    private val foundDeviceReceiver = FoundDeviceReceiver { device ->
        _scannedDevices.update { devices ->
            val newDevice = device.toBluetoothDeviceDomain()
            if(newDevice in devices) devices else devices + newDevice
        }
    }

    private val bluetoothStateReceiver = BluetoothStateReceiver { isConnected, _ ->
        if (!isConnected) {
            _isConnected.update { false }
            cleanupConnection()
        }
    }

    init {
        updatePairedDevices()
        context.registerReceiver(
            bluetoothStateReceiver,
            IntentFilter().apply {
                addAction(BluetoothAdapter.ACTION_CONNECTION_STATE_CHANGED)
                addAction(BluetoothDevice.ACTION_ACL_CONNECTED)
                addAction(BluetoothDevice.ACTION_ACL_DISCONNECTED)
            }
        )
    }

    override fun startDiscovery() {
        if(!hasPermission(Manifest.permission.BLUETOOTH_SCAN)) return

        context.registerReceiver(
            foundDeviceReceiver,
            IntentFilter(BluetoothDevice.ACTION_FOUND)
        )

        updatePairedDevices()
        bluetoothAdapter?.startDiscovery()
    }

    override fun stopDiscovery() {
        if(!hasPermission(Manifest.permission.BLUETOOTH_SCAN)) return
        bluetoothAdapter?.cancelDiscovery()
    }

    override fun startBluetoothServer(): Flow<ConnectionResult> = flow {
        if(!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            throw SecurityException("No BLUETOOTH_CONNECT permission")
        }

        try {
            currentServerSocket = bluetoothAdapter?.listenUsingRfcommWithServiceRecord(
                "chat_service",
                UUID.fromString(SERVICE_UUID)
            )

            Log.d("BluetoothController", "Server socket created, waiting for connections...")

            var shouldLoop = true
            while(shouldLoop) {
                currentClientSocket = try {
                    currentServerSocket?.accept()
                } catch(e: IOException) {
                    Log.e("BluetoothController", "Server socket accept failed", e)
                    shouldLoop = false
                    null
                }

                currentClientSocket?.let { socket ->
                    Log.d("BluetoothController", "Client connected: ${socket.remoteDevice?.name}")

                    currentServerSocket?.close()
                    _isConnected.value = true
                    emit(ConnectionResult.ConnectionEstablished)

                    val service = BluetoothDataTransferService(
                        context = context.applicationContext,
                        socket = socket,
                        messageLogDao = messageLogDao,
                        onSecurityAlert = onSecurityAlert,
                        scope = connectionScope
                    )
                    dataTransferService = service
                    activeConnections.add(service)

                    try {
                        emitAll(
                            service
                                .listenForIncomingMessages()
                                .map { message ->
                                    Log.d("BluetoothController", "Message received in flow: ${message.message}")
                                    ConnectionResult.TransferSucceeded(message)
                                }
                        )
                    } catch (e: Exception) {
                        Log.e("BluetoothController", "Error in message flow", e)
                        emit(ConnectionResult.Error("Message transfer failed: ${e.message}"))
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("BluetoothController", "Server error", e)
            emit(ConnectionResult.Error("Server error: ${e.message}"))
        }
    }.onCompletion { cause ->
        Log.d("BluetoothController", "Server flow completed: $cause")
        emit(ConnectionResult.Disconnected)
        cleanupConnection()
    }.flowOn(Dispatchers.IO)

    override fun connectToDevice(device: BluetoothDeviceDomain): Flow<ConnectionResult> = flow {
        if(!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            throw SecurityException("No BLUETOOTH_CONNECT permission")
        }

        Log.d("BluetoothController", "Connecting to device: ${device.name} (${device.address})")

        // Clean up any previous connection
        cleanupConnection()
        _isConnected.value = false

        currentClientSocket = bluetoothAdapter
            ?.getRemoteDevice(device.address)
            ?.createRfcommSocketToServiceRecord(
                UUID.fromString(SERVICE_UUID)
            )

        stopDiscovery()

        currentClientSocket?.let { socket ->
            try {
                withContext(Dispatchers.IO) {
                    socket.connect()
                }

                Log.d("BluetoothController", "Connected to ${device.name}")
                _isConnected.value = true
                emit(ConnectionResult.ConnectionEstablished)

                val service = BluetoothDataTransferService(
                    context = context.applicationContext,
                    socket = socket,
                    messageLogDao = messageLogDao,
                    onSecurityAlert = onSecurityAlert,
                    scope = connectionScope
                )
                dataTransferService = service
                activeConnections.add(service)

                try {
                    emitAll(
                        service
                            .listenForIncomingMessages()
                            .map { message ->
                                Log.d("BluetoothController", "Message received: ${message.message}")
                                ConnectionResult.TransferSucceeded(message)
                            }
                    )
                } catch (e: Exception) {
                    Log.e("BluetoothController", "Error in message flow", e)
                    emit(ConnectionResult.Error("Message transfer failed: ${e.message}"))
                }
            } catch(e: IOException) {
                Log.e("BluetoothController", "Connection failed", e)
                socket.close()
                currentClientSocket = null
                emit(ConnectionResult.Error("Connection failed: ${e.message}"))
            }
        } ?: emit(ConnectionResult.Error("Failed to create socket"))
    }.onCompletion { cause ->
        Log.d("BluetoothController", "Client flow completed: $cause")
        emit(ConnectionResult.Disconnected)
        cleanupConnection()
    }.flowOn(Dispatchers.IO)

    override suspend fun trySendMessage(message: String): BluetoothMessage? {
        if(!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            Log.w("BluetoothController", "No BLUETOOTH_CONNECT permission")
            return null
        }

        if(dataTransferService == null) {
            Log.w("BluetoothController", "No data transfer service available")
            return null
        }

        if (!_isConnected.value) {
            Log.w("BluetoothController", "Not connected to any device")
            return null
        }

        val bluetoothMessage = BluetoothMessage(
            message = message,
            senderName = bluetoothAdapter?.name ?: "Unknown name",
            isFromLocalUser = true
        )

        Log.d("BluetoothController", "Attempting to send message: $message")

        return try {
            val success = dataTransferService?.sendMessage(message.toByteArray(Charsets.UTF_8))
            if (success == true) {
                Log.d("BluetoothController", "Message sent successfully")
                bluetoothMessage
            } else {
                Log.w("BluetoothController", "Failed to send message")
                null
            }
        } catch (e: Exception) {
            Log.e("BluetoothController", "Error sending message", e)
            null
        }
    }

    private fun cleanupConnection() {
        Log.d("BluetoothController", "Cleaning up connections")

        activeConnections.forEach {
            try {
                it.closeConnection()
            } catch (e: Exception) {
                Log.e("BluetoothController", "Error closing connection", e)
            }
        }
        activeConnections.clear()

        try {
            currentClientSocket?.close()
        } catch (e: IOException) {
            Log.e("BluetoothController", "Error closing client socket", e)
        }

        try {
            currentServerSocket?.close()
        } catch (e: IOException) {
            Log.e("BluetoothController", "Error closing server socket", e)
        }

        currentClientSocket = null
        currentServerSocket = null
        dataTransferService = null
        _isConnected.value = false
    }

    override fun closeConnection() {
        cleanupConnection()
    }

    override fun release() {
        try {
            context.unregisterReceiver(foundDeviceReceiver)
        } catch (e: Exception) {
            Log.e("BluetoothController", "Error unregistering foundDeviceReceiver", e)
        }

        try {
            context.unregisterReceiver(bluetoothStateReceiver)
        } catch (e: Exception) {
            Log.e("BluetoothController", "Error unregistering bluetoothStateReceiver", e)
        }

        cleanupConnection()
        connectionScope.cancel()
    }

    private fun updatePairedDevices() {
        if(!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return
        bluetoothAdapter
            ?.bondedDevices
            ?.map { it.toBluetoothDeviceDomain() }
            ?.also { devices ->
                _pairedDevices.update { devices }
            }
    }

    private fun hasPermission(permission: String): Boolean {
        return context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
    }

    companion object {
        const val SERVICE_UUID = "27b7d1da-08c7-4505-a6d1-2459987e5e2d"
    }
}