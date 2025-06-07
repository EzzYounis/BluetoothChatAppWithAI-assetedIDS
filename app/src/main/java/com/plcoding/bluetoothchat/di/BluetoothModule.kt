package com.plcoding.bluetoothchat.di

import androidx.activity.ComponentActivity
import com.plcoding.bluetoothchat.presentation.SecurityAlert
import com.plcoding.bluetoothchat.presentation.components.SecurityAlertHandler
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ActivityComponent

@Module
@InstallIn(ActivityComponent::class)
 object BluetoothModule {

    @Provides
    fun provideActivitySecurityAlertCallback(
        activity: ComponentActivity
    ): (SecurityAlert) -> Unit {
        return { alert ->
            if (activity is SecurityAlertHandler) {
                activity.onSecurityAlert(alert)
            }
        }
    }
}