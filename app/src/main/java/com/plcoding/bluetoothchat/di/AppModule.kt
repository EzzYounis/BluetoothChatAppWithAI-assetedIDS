package com.plcoding.bluetoothchat.di

import android.app.Application
import androidx.room.Room
import com.plcoding.bluetoothchat.data.chat.AndroidBluetoothController
import com.plcoding.bluetoothchat.data.chat.AppDatabase
import com.plcoding.bluetoothchat.data.chat.MessageLogDao
import com.plcoding.bluetoothchat.domain.chat.BluetoothController
import com.plcoding.bluetoothchat.presentation.BluetoothViewModel
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

    // ✅ Provide BluetoothController as before
    @Provides
    @Singleton
    fun provideBluetoothController(app: Application): BluetoothController {
        return AndroidBluetoothController(app)
    }

    // ✅ Provide Room Database
    @Provides
    @Singleton
    fun provideAppDatabase(app: Application): AppDatabase {
        return Room.databaseBuilder(
            app,
            AppDatabase::class.java,
            "bluetooth_chat_db"
        ).build()
    }

    // ✅ Provide DAO
    @Provides
    @Singleton
    fun provideMessageLogDao(database: AppDatabase): MessageLogDao {
        return database.messageLogDao()
    }
}
@Module
@InstallIn(ViewModelComponent::class)
object ViewModelModule {

    @Provides
    fun provideSecurityAlertMutableStateFlow(): MutableStateFlow<BluetoothViewModel.SecurityAlert?> {
        return MutableStateFlow(null)
    }

    @Provides
    fun provideSecurityAlertStateFlow(
        mutableFlow: MutableStateFlow<BluetoothViewModel.SecurityAlert?>
    ): StateFlow<BluetoothViewModel.SecurityAlert?> {
        return mutableFlow.asStateFlow()
    }
}