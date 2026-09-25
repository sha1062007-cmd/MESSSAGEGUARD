package com.messageguard

import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

enum class Verdict { SAFE, WARNING, DANGER, UNCERTAIN }

enum class SupportedApp(val packageName: String, val displayName: String) {
    GMAIL("com.google.android.gm", "Gmail"),
    WHATSAPP("com.whatsapp", "WhatsApp"),
    TELEGRAM("org.telegram.messenger", "Telegram"),
    SMS("com.android.mms", "SMS"),
    INSTAGRAM("com.instagram.android", "Instagram"),
    LINKEDIN("com.linkedin.android", "LinkedIn");
    companion object {
        fun fromPackage(pkg: String): SupportedApp? {
            if (pkg == "com.google.android.apps.messaging" || pkg == "com.android.mms" || pkg == "com.samsung.android.messaging") {
                return SMS
            }
            return values().find { it.packageName == pkg }
        }
    }
}

class StringListConverter {
    @TypeConverter fun fromList(list: List<String>): String =
        Gson().toJson(list)
    @TypeConverter fun toList(json: String): List<String> =
        Gson().fromJson(json, object : TypeToken<List<String>>() {}.type)
            ?: emptyList()
}

class VerdictConverter {
    @TypeConverter fun fromVerdict(v: Verdict): String = v.name
    @TypeConverter fun toVerdict(s: String): Verdict = Verdict.valueOf(s)
}

@Entity(tableName = "analysis_history")
@TypeConverters(StringListConverter::class, VerdictConverter::class)
data class AnalysisResult(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
    val appSource: String = "",
    val sender: String = "",
    val subject: String = "",
    val verdict: Verdict = Verdict.SAFE,
    val riskScore: Int = 0,
    val category: String = "",
    val senderTrust: String = "unknown",
    val summary: String = "",
    val flags: List<String> = emptyList(),
    val action: String = "",
    
    // Detailed score fields for breakdown reporting
    val mlScore: Int = 0,      // raw ML ensemble score 0-100
    val aiScore: Int = -1,     // raw Gemini score 0-100, -1 = offline
    
    // Scan Logging fields
    val messageSnippet: String = "",
    val reviewed: Boolean = false,
    val userFeedback: String? = null,
    val flaggedUrls: String = "",
    val explainabilityJson: String = "",
    val typosquatFlag: Boolean = false,
    val senderReputationScore: Float = 0.0f,

    // Model disagreement tracking — when models disagree, the uncertaintyReason explains why
    val uncertaintyReason: String? = null,
    val modelDisagreementScore: Float = 0.0f
) : java.io.Serializable
