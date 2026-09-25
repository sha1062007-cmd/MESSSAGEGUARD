package com.messageguard

object Constants {
    const val PREFS_NAME = "messageguard_prefs"
    const val KEY_API_KEY = "claude_api_key"
    const val KEY_SERVICE_ENABLED = "service_enabled"
    const val KEY_MONITOR_GMAIL = "monitor_gmail"
    const val KEY_MONITOR_WHATSAPP = "monitor_whatsapp"
    const val KEY_MONITOR_TELEGRAM = "monitor_telegram"
    const val KEY_MONITOR_SMS = "monitor_sms"
    const val KEY_MONITOR_INSTAGRAM = "monitor_instagram"
    const val KEY_MONITOR_LINKEDIN = "monitor_linkedin"
    
    // Resend API Keys
    const val KEY_EMAIL_ALERTS_ENABLED = "email_alerts_enabled"
    const val KEY_ALERT_EMAIL_ADDRESS = "alert_email_address"
    const val KEY_ALERT_FROM_EMAIL = "alert_from_email"
    const val KEY_RESEND_API_KEY = "resend_api_key"
    const val KEY_EMAIL_ALERT_DANGEROUS = "email_alert_dangerous"
    const val KEY_EMAIL_ALERT_SUSPICIOUS = "email_alert_suspicious"

    // Settings Toggle for scan logging
    const val KEY_LOG_ALL_SCANS = "log_all_scans"
    const val KEY_WEEKLY_EXPORT = "weekly_export"
    const val KEY_RETENTION_DAYS = "retention_days"

    // Onboarding & Theme Toggle preferences
    const val KEY_ONBOARDING_COMPLETED = "onboarding_completed"
    const val KEY_THEME_DARK = "theme_dark"

    // On-device Adaptive Trust Engine Weights
    const val KEY_WEIGHT_URL = "weight_url"
    const val KEY_WEIGHT_NLP = "weight_nlp"
    const val KEY_WEIGHT_BODMAS = "weight_bodmas"
    const val KEY_WEIGHT_TYPOSQUAT = "weight_typosquat"
    const val KEY_WEIGHT_REPUTATION = "weight_reputation"

    // Default normalized weights summing to 1.000f (25.9%, 29.6%, 18.5%, 14.8%, 11.2%)
    // Verified: 0.259f + 0.296f + 0.185f + 0.148f + 0.112f = 1.000f (abs(sum - 1.0f) < 0.001f epsilon tolerance)
    const val DEFAULT_WEIGHT_URL = 0.259f
    const val DEFAULT_WEIGHT_NLP = 0.296f
    const val DEFAULT_WEIGHT_BODMAS = 0.185f
    const val DEFAULT_WEIGHT_TYPOSQUAT = 0.148f
    const val DEFAULT_WEIGHT_REPUTATION = 0.112f

    // Voice trigger settings
    const val KEY_VOICE_TRIGGER_ENABLED = "voice_trigger_enabled"
    const val KEY_VOICE_PRIVACY_DISCLOSED = "voice_privacy_disclosed"

    // UX Bubble declutter toggle
    const val KEY_SHOW_FLOATING_BUBBLE = "show_floating_bubble"

    // Language setting
    const val KEY_LANGUAGE_TAMIL = "language_tamil"
}
