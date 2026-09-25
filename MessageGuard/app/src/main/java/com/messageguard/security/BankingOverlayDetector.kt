package com.messageguard.security

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import com.messageguard.MainActivity
import com.messageguard.R

/**
 * Sub-step 3: Overlay-During-Banking-App Detection.
 *
 * Called from AccessibilityEngineService whenever the foreground package changes.
 * Logic:
 *  1. Is the new foreground app a banking/UPI app? (uses KNOWN_BANK_KEYWORDS from BankAppSecurityAnalyzer)
 *  2. If yes: enumerate all non-system apps that currently hold SYSTEM_ALERT_WINDOW AND
 *     have it GRANTED (Settings.canDrawOverlays), excluding MessageGuard's own package.
 *  3. If any third-party overlay is active → fire a HIGH-priority notification immediately.
 *  4. Self-suppress: MessageGuard's FloatingBubbleService and OverlaySelectionService are
 *     excluded by filtering on `com.messageguard` package prefix.
 */
class BankingOverlayDetector(private val context: Context) {

    companion object {
        private const val TAG = "BankingOverlayDetector"
        private const val CHANNEL_ID = "banking_overlay_alert_channel"
        private const val NOTIFICATION_ID = 9001

        /** MessageGuard's own package — never self-flag our FloatingBubble / OverlaySelectionService */
        private const val OWN_PACKAGE = "com.messageguard"

        /** Rate-limit alerts: don't fire more than once per 30s for the same foreground banking app */
        private const val ALERT_COOLDOWN_MS = 30_000L
    }

    private var lastAlertPackage: String? = null
    private var lastAlertTimestamp: Long = 0L

    init {
        ensureNotificationChannel()
    }

    /**
     * Must be called every time AccessibilityEngineService detects a foreground package change.
     * This is the single entry point — cheap to call, returns immediately if not a banking app.
     */
    fun onForegroundPackageChanged(foregroundPackage: String) {
        if (!isBankingApp(foregroundPackage)) return

        val activeThirdPartyOverlays = findActiveThirdPartyOverlays()
        if (activeThirdPartyOverlays.isEmpty()) {
            Log.d(TAG, "Banking app in foreground ($foregroundPackage) — no third-party overlays detected. Safe.")
            return
        }

        // Rate-limit: suppress if same banking app was already alerted recently
        val now = System.currentTimeMillis()
        if (foregroundPackage == lastAlertPackage && (now - lastAlertTimestamp) < ALERT_COOLDOWN_MS) {
            Log.d(TAG, "Overlay alert suppressed (cooldown) for $foregroundPackage")
            return
        }

        lastAlertPackage = foregroundPackage
        lastAlertTimestamp = now

        val overlayNames = activeThirdPartyOverlays.joinToString(", ") { it.appName }
        Log.w(TAG, "OVERLAY PHISHING RISK: Banking app $foregroundPackage in foreground. " +
                "Active overlays: $overlayNames")
        fireOverlayAlert(foregroundPackage, activeThirdPartyOverlays)
    }

    // ─── Banking App Detection ───────────────────────────────────────────────

    /**
     * Checks both the package name and the app label against KNOWN_BANK_KEYWORDS.
     * Reuses BankAppSecurityAnalyzer.KNOWN_BANK_KEYWORDS — no duplicate list.
     */
    private fun isBankingApp(packageName: String): Boolean {
        val lowerPkg = packageName.lowercase()
        if (BankAppSecurityAnalyzer.KNOWN_BANK_KEYWORDS.any { lowerPkg.contains(it) }) return true

        return try {
            val pm = context.packageManager
            val appInfo = pm.getApplicationInfo(packageName, 0)
            val label = pm.getApplicationLabel(appInfo).toString().lowercase()
            BankAppSecurityAnalyzer.KNOWN_BANK_KEYWORDS.any { label.contains(it) }
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    // ─── Active Overlay Enumeration ──────────────────────────────────────────

    data class ActiveOverlayApp(
        val packageName: String,
        val appName: String
    )

    /**
     * Enumerates non-system apps that:
     *   (a) declare SYSTEM_ALERT_WINDOW permission, AND
     *   (b) currently have it GRANTED (Settings.canDrawOverlays returns true), AND
     *   (c) are not MessageGuard's own package.
     *
     * Note: Settings.canDrawOverlays(ctx) tests the *calling* context. To test another
     * app's grant we use the Settings.ACTION_MANAGE_OVERLAY_PERMISSION check pattern:
     * we create a throwaway Context via createPackageContext and evaluate canDrawOverlays
     * on it — this is the only reliable approach without root that doesn't require
     * AppOpsManager (which is @hide on most OEM ROMs).
     */
    private fun findActiveThirdPartyOverlays(): List<ActiveOverlayApp> {
        val pm = context.packageManager
        val results = mutableListOf<ActiveOverlayApp>()

        val packages = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to query installed packages", e)
            return emptyList()
        }

        for (pkg in packages) {
            val pkgName = pkg.packageName ?: continue

            // Self-exclude: skip MessageGuard's own package (FloatingBubble, OverlaySelection, etc.)
            if (pkgName.startsWith(OWN_PACKAGE)) continue

            // Skip pure system apps (not updated)
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            if (isSystem && !isUpdatedSystem) continue

            // Does this app declare SYSTEM_ALERT_WINDOW?
            val declaresOverlay = pkg.requestedPermissions?.contains(
                "android.permission.SYSTEM_ALERT_WINDOW"
            ) == true
            if (!declaresOverlay) continue

            // Is the overlay permission actually GRANTED right now?
            val isGranted = try {
                val pkgCtx = context.createPackageContext(pkgName, 0)
                Settings.canDrawOverlays(pkgCtx)
            } catch (e: Exception) {
                // Some OEM skins throw on createPackageContext; fall back to AppOpsManager check
                isOverlayGrantedViaAppOps(pkgName)
            }
            if (!isGranted) continue

            val appName = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (e: Exception) {
                pkgName
            }

            results.add(ActiveOverlayApp(pkgName, appName))
        }

        return results
    }

    /**
     * Fallback overlay grant check using AppOpsManager when createPackageContext fails
     * (e.g. on OEM-locked devices). Returns false if UID cannot be resolved.
     */
    private fun isOverlayGrantedViaAppOps(packageName: String): Boolean {
        return try {
            val pm = context.packageManager
            val uid = pm.getApplicationInfo(packageName, 0).uid
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as android.app.AppOpsManager
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(
                    android.app.AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                    uid,
                    packageName
                )
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(
                    android.app.AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                    uid,
                    packageName
                )
            }
            mode == android.app.AppOpsManager.MODE_ALLOWED
        } catch (e: Exception) {
            Log.w(TAG, "AppOps overlay check failed for $packageName: ${e.message}")
            false
        }
    }

    // ─── High-Priority Notification ──────────────────────────────────────────

    private fun fireOverlayAlert(
        bankingPackage: String,
        overlays: List<ActiveOverlayApp>
    ) {
        val pm = context.packageManager
        val bankAppName = try {
            pm.getApplicationLabel(pm.getApplicationInfo(bankingPackage, 0)).toString()
        } catch (e: Exception) {
            bankingPackage
        }

        val overlayList = overlays.joinToString("\n") { "• ${it.appName} (${it.packageName})" }
        val title = "⚠️ Overlay Phishing Risk Detected"
        val body = "$bankAppName is open. The following app(s) may be drawing a fake login screen on top:\n$overlayList"

        val tapIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context, NOTIFICATION_ID, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentText(body)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setVibrate(longArrayOf(0, 250, 100, 250))
            .build()

        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, notification)
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    "Banking Overlay Security Alerts",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Fires when an overlay is detected on top of a banking app (phishing risk)"
                    enableVibration(true)
                    vibrationPattern = longArrayOf(0, 250, 100, 250)
                }
                nm.createNotificationChannel(channel)
            }
        }
    }
}
