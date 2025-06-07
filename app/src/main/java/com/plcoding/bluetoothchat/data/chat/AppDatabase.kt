package com.plcoding.bluetoothchat.data.chat

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.plcoding.bluetoothchat.domain.chat.MessageLog

@Database(entities = [MessageLog::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun messageLogDao(): MessageLogDao

    companion object {
        @Volatile private var INSTANCE: AppDatabase? = null

        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "bluetooth_mesh_db"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
