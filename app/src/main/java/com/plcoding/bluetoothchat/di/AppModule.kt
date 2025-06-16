package com.plcoding.bluetoothchat.di

import android.app.Application
import android.content.Context
import androidx.room.Room
import com.plcoding.bluetoothchat.data.chat.*
import com.plcoding.bluetoothchat.domain.chat.BluetoothController
import com.plcoding.bluetoothchat.presentation.IDS.IDSModel
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideBluetoothController(
        @ApplicationContext context: Context,
        messageLogDao: MessageLogDao
    ): BluetoothController {
        return AndroidBluetoothController(
            context = context,
            messageLogDao = messageLogDao
        )
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
    fun provideIDSModel(@ApplicationContext context: Context): IDSModel {
        return IDSModel(context)
    }
}