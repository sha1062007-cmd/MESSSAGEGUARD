package com.messageguard.sandbox.scan

import android.content.Context
import android.content.pm.PackageManager
import java.io.File

data class ApkFeatureVector(
    val features: FloatArray,
    val requestedPermissions: List<String>,
    val dangerousPermissionCount: Int,
    val hasInstallPackagesFlag: Boolean,
    val hasSystemAlertWindowFlag: Boolean
)

object ApkStaticExtractor {

    private val CRITICAL_PERMISSIONS = listOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.GET_TASKS",
        "android.permission.REORDER_TASKS",
        "android.permission.KILL_BACKGROUND_PROCESSES",
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.NFC",
        "android.permission.USE_BIOMETRIC",
        "android.permission.USE_FINGERPRINT",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
        "android.permission.DISABLE_KEYGUARD",
        "android.permission.WRITE_SETTINGS",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.REQUEST_DELETE_PACKAGES",
        "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.ADD_VOICEMAIL"
    )

    const val FEATURE_VECTOR_SIZE = 64

    fun extractFeatures(context: Context, apkPath: String): ApkFeatureVector? {
        val file = File(apkPath)
        if (!file.exists() || file.length() == 0L) return null

        val pm = context.packageManager
        val pkgInfo = try {
            @Suppress("DEPRECATION")
            pm.getPackageArchiveInfo(apkPath, PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            null
        } ?: return null

        val requestedPermissions = pkgInfo.requestedPermissions?.toList() ?: emptyList()
        val vector = FloatArray(FEATURE_VECTOR_SIZE) { 0.0f }

        // 1. One-Hot Map Top 50 Critical Permissions (Index 0 to 49)
        var dangerousCount = 0
        CRITICAL_PERMISSIONS.forEachIndexed { index, perm ->
            if (requestedPermissions.contains(perm)) {
                vector[index] = 1.0f
                dangerousCount++
            }
        }

        // 2. Extra Structural & Risk Flags (Index 50 to 53)
        val hasInstallPackages = requestedPermissions.contains("android.permission.REQUEST_INSTALL_PACKAGES")
        val hasSystemAlertWindow = requestedPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasAccessibility = requestedPermissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val hasBootCompleted = requestedPermissions.contains("android.permission.RECEIVE_BOOT_COMPLETED")

        vector[50] = if (hasInstallPackages) 1.0f else 0.0f
        vector[51] = if (hasSystemAlertWindow) 1.0f else 0.0f
        vector[52] = if (hasAccessibility) 1.0f else 0.0f
        vector[53] = if (hasBootCompleted) 1.0f else 0.0f

        // 3. Normalized Dangerous Ratio & Metrics (Index 54 to 55)
        vector[54] = (dangerousCount.toFloat() / CRITICAL_PERMISSIONS.size.toFloat()).coerceIn(0.0f, 1.0f)
        vector[55] = (requestedPermissions.size.toFloat() / 100.0f).coerceIn(0.0f, 1.0f)

        return ApkFeatureVector(
            features = vector,
            requestedPermissions = requestedPermissions,
            dangerousPermissionCount = dangerousCount,
            hasInstallPackagesFlag = hasInstallPackages,
            hasSystemAlertWindowFlag = hasSystemAlertWindow
        )
    }
}
