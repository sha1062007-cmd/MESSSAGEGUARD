package com.messageguard.threatvision.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.messageguard.threatvision.data.local.entity.ThreatScanEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ThreatDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScan(scan: ThreatScanEntity): Long

    @Query("SELECT * FROM threat_scans ORDER BY timestamp DESC")
    fun getAllScans(): Flow<List<ThreatScanEntity>>

    @Query("SELECT * FROM threat_scans ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecentScans(limit: Int): List<ThreatScanEntity>

    @Query("SELECT * FROM threat_scans WHERE id = :id LIMIT 1")
    suspend fun getScanById(id: Long): ThreatScanEntity?

    @Query("DELETE FROM threat_scans")
    suspend fun clearAllScans()
}
