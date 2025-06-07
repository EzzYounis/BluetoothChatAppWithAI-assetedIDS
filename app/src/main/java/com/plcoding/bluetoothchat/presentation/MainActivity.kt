package com.plcoding.bluetoothchat.presentation

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.material.*

import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.plcoding.bluetoothchat.presentation.components.ChatScreen
import com.plcoding.bluetoothchat.presentation.components.DeviceScreen
import com.plcoding.bluetoothchat.presentation.components.SecurityAlertHandler
import com.plcoding.bluetoothchat.ui.theme.BluetoothChatTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity(),SecurityAlertHandler {

    private val bluetoothManager by lazy {
        applicationContext.getSystemService(BluetoothManager::class.java)
    }
    private val bluetoothAdapter by lazy {
        bluetoothManager?.adapter
    }

    private val isBluetoothEnabled: Boolean
        get() = bluetoothAdapter?.isEnabled == true
    private val viewModel: BluetoothViewModel by viewModels()

    override fun onSecurityAlert(alert: SecurityAlert) {
        viewModel.onSecurityAlert(alert)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val enableBluetoothLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { /* No action needed */ }

        val permissionLauncher = registerForActivityResult(
            ActivityResultContracts.RequestMultiplePermissions()
        ) { perms ->
            val canEnableBluetooth = if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                perms[Manifest.permission.BLUETOOTH_CONNECT] == true
            } else true

            if(canEnableBluetooth && !isBluetoothEnabled) {
                enableBluetoothLauncher.launch(
                    Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
                )
            }
        }

        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissionLauncher.launch(
                arrayOf(
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                )
            )
        }

        setContent {
            BluetoothChatTheme {
                val viewModel = hiltViewModel<BluetoothViewModel>()
                val state by viewModel.state.collectAsState()
                val context = LocalContext.current
                val securityAlert by viewModel.securityAlert.collectAsState()

                // Handle security alerts
                DisposableEffect(Unit) {
                    val receiver = object : BroadcastReceiver() {
                        override fun onReceive(context: Context, intent: Intent) {
                            if (intent.action == "SECURITY_ALERT") {
                                val attackType = intent.getStringExtra("ATTACK_TYPE") ?: "unknown"
                                val deviceName = intent.getStringExtra("DEVICE_NAME") ?: "Unknown"
                                val deviceAddress = intent.getStringExtra("DEVICE_ADDRESS") ?: "00:00:00:00:00:00"
                                val message = intent.getStringExtra("MESSAGE") ?: ""

                                viewModel.onSecurityAlert(
                                    SecurityAlert(
                                        attackType = attackType,
                                        deviceName = deviceName,
                                        deviceAddress = deviceAddress,
                                        message = message,detectionMethod = "Manual Trigger",
                                        explanation = "This is a demonstration of the security alert system"
                                    )
                                )
                            }
                        }
                    }
                    context.registerReceiver(
                        receiver,
                        IntentFilter("SECURITY_ALERT"),
                        RECEIVER_NOT_EXPORTED
                    )

                    onDispose {
                        context.unregisterReceiver(receiver)
                    }
                }

                // Show error messages
                LaunchedEffect(key1 = state.errorMessage) {
                    state.errorMessage?.let { message ->
                        Toast.makeText(
                            context,
                            message,
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }

                // Show connection success
                LaunchedEffect(key1 = state.isConnected) {
                    if(state.isConnected) {
                        Toast.makeText(
                            context,
                            "You're connected!",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }

                Surface(color = MaterialTheme.colors.background) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        when {
                            state.isConnecting -> {
                                ConnectingScreen()
                            }
                            state.isConnected -> {
                                ChatScreen(
                                    state = state,
                                    onDisconnect = viewModel::disconnectFromDevice,
                                    onSendMessage = viewModel::sendMessage,
                                    viewModel = viewModel,
                                )
                            }
                            else -> {
                                DeviceScreen(
                                    state = state,
                                    onStartScan = viewModel::startScan,
                                    onStopScan = viewModel::stopScan,
                                    onDeviceClick = viewModel::connectToDevice,
                                    onStartServer = viewModel::waitForIncomingConnections
                                )
                            }
                        }

                        // Security Alert Dialog
                        securityAlert?.let { alert ->
                            SecurityAlertDialog(
                                alert = alert,
                                onDismiss = { viewModel.clearSecurityAlert() },
                                onBlockDevice = {
                                    viewModel.blockDevice(alert.deviceAddress)
                                    viewModel.clearSecurityAlert()
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ConnectingScreen() {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator()
        Spacer(modifier = Modifier.height(8.dp))
        Text(text = "Connecting...")
    }
}

@Composable
fun SecurityAlertDialog(
    alert: SecurityAlert,
    onDismiss: () -> Unit,
    onBlockDevice: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                "Security Alert - ${alert.attackType.replaceFirstChar { it.uppercase() }}",
                color = MaterialTheme.colors.error
            )
        },
        text = {
            Column {
                Text("Device: ${alert.deviceName} (${alert.deviceAddress})")
                Spacer(modifier = Modifier.height(8.dp))
                Text("Message: ${alert.message.take(200)}")
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("DISMISS")
            }
        },
        dismissButton = {
            TextButton(
                onClick = onBlockDevice,
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colors.error
                )
            ) {
                Text("BLOCK DEVICE")
            }
        }
    )
}