package com.messageguard.threatvision.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "threat_scans")
data class ThreatScanEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val extractedText: String,
    val extractedUrls: String, // Comma separated or JSON array
    val riskScore: Int,
    val verdict: String,
    val threatCategory: String,
    val detectionReason: String,
    val recommendedActions: String, // Pipe or JSON delimited
    val timestamp: Long
)
