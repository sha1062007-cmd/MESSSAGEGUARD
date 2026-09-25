package com.messageguard

/**
 * Dashboard statistics data class for MVVM LiveData
 */
data class DashboardStats(
    val totalToday: Int = 0,
    val dangersFound: Int = 0,
    val safeCount: Int = 0,
    val warningCount: Int = 0,
    val totalOverall: Int = 0,
    val safeOverall: Int = 0
)
