package com.plcoding.bluetoothchat.presentation.components


import com.plcoding.bluetoothchat.presentation.SecurityAlert
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.flow.MutableStateFlow
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object SecurityModule {

    @Provides
    @Singleton
    fun provideSecurityAlertState(): MutableStateFlow<SecurityAlert?> {
        return MutableStateFlow(null)
    }
}