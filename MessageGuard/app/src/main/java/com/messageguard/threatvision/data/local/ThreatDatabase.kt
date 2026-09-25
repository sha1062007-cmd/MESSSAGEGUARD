package com.messageguard.threatvision.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.messageguard.threatvision.data.local.entity.ThreatScanEntity

@Database(entities = [ThreatScanEntity::class], version = 1, exportSchema = false)
abstract class ThreatDatabase : RoomDatabase() {

    abstract fun threatDao(): ThreatDao

    companion object {
        @Volatile
        private var INSTANCE: ThreatDatabase? = null

        fun getDatabase(context: Context): ThreatDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    ThreatDatabase::class.java,
                    "threat_vision_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
