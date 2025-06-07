package com.plcoding.bluetoothchat.di

import android.app.Application
import androidx.room.Room
import com.plcoding.bluetoothchat.data.chat.*
import com.plcoding.bluetoothchat.domain.chat.BluetoothController
import com.plcoding.bluetoothchat.presentation.BluetoothViewModel
import com.plcoding.bluetoothchat.presentation.IDS.BluetoothFeatureExtractor
import com.plcoding.bluetoothchat.presentation.SecurityAlert
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ViewModelComponent
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideBluetoothController(app: Application): BluetoothController {
        return AndroidBluetoothController(app)
    }

    @Provides
    @Singleton
    fun provideAppDatabase(app: Application): AppDatabase {
        return Room.databaseBuilder(
            app,
            AppDatabase::class.java,
            "bluetooth_chat_db"
        ).build()
    }

    @Provides
    @Singleton
    fun provideMessageLogDao(database: AppDatabase): MessageLogDao {
        return database.messageLogDao()
    }

    @Provides
    @Singleton
    fun provideBluetoothFeatureExtractor(): BluetoothFeatureExtractor {
        return BluetoothFeatureExtractor()
    }
}

@Module
@InstallIn(ViewModelComponent::class)
object ViewModelModule {

    @Provides
    fun provideSecurityAlertState(): MutableStateFlow<SecurityAlert?> {
        return MutableStateFlow(null)
    }
}