package com.messageguard.threatvision.ui.components

import android.content.Context
import android.content.res.Configuration
import com.messageguard.Constants
import com.messageguard.R
import com.messageguard.threatvision.data.model.ComponentStatus
import com.messageguard.threatvision.data.model.RiskAssessment
import com.messageguard.threatvision.data.model.ThreatCategory
import com.messageguard.threatvision.data.model.ThreatVerdict
import java.util.Locale

internal data class ScanResultPresentation(
    val useTamil: Boolean,
    val verdict: String,
    val category: String,
    val summary: String,
    val recommendations: List<String>,
    val recommendationsHeader: String,
    val expandReport: String,
    val collapseReport: String,
    val reportHeader: String
)

/** Selects English or Tamil result strings independently from the device-wide locale. */
internal object ScanResultLocalizer {

    fun loading(context: Context): LoadingPresentation {
        val strings = strings(context, tamilPreferenceEnabled(context))
        return LoadingPresentation(
            title = strings.getString(R.string.scan_loading_title),
            score = strings.getString(R.string.scan_loading_score),
            status = strings.getString(R.string.scan_loading_status),
            summary = strings.getString(R.string.scan_loading_summary),
            recommendations = strings.getString(R.string.scan_loading_recommendations)
        )
    }

    fun result(context: Context, assessment: RiskAssessment): ScanResultPresentation {
        val useTamil = tamilPreferenceEnabled(context) || assessment.isTamilContent
        val strings = strings(context, useTamil)
        val incomplete = !assessment.isComplete
        val verdict = when {
            incomplete -> strings.getString(R.string.result_verdict_incomplete)
            assessment.verdict == ThreatVerdict.SAFE -> strings.getString(R.string.result_verdict_safe)
            assessment.verdict == ThreatVerdict.WARNING -> strings.getString(R.string.result_verdict_warning)
            else -> strings.getString(R.string.result_verdict_danger)
        }
        val category = if (incomplete) {
            strings.getString(R.string.result_category_unavailable)
        } else {
            categoryLabel(strings, assessment.category)
        }
        val summary = when {
            incomplete -> strings.getString(R.string.result_summary_incomplete)
            useTamil -> summaryForVerdict(strings, assessment.verdict)
            else -> assessment.report?.summary ?: assessment.reason
        }
        val recommendations = when {
            incomplete -> listOf(
                strings.getString(R.string.result_recommendation_incomplete_one),
                strings.getString(R.string.result_recommendation_incomplete_two)
            )
            useTamil -> recommendationsForVerdict(strings, assessment.verdict)
            else -> assessment.recommendations
        }

        return ScanResultPresentation(
            useTamil = useTamil,
            verdict = strings.getString(R.string.result_verdict_format, verdict),
            category = strings.getString(R.string.result_category_format, category),
            summary = summary,
            recommendations = recommendations,
            recommendationsHeader = strings.getString(R.string.result_recommendations_header),
            expandReport = strings.getString(R.string.result_expand_report),
            collapseReport = strings.getString(R.string.result_collapse_report),
            reportHeader = strings.getString(R.string.result_report_header)
        )
    }

    fun riskScore(context: Context, score: Int, useTamil: Boolean): String =
        strings(context, useTamil).getString(R.string.result_risk_score_format, score)

    fun componentLabel(context: Context, label: String, useTamil: Boolean): String {
        val resId = when {
            label.contains("UPI") -> R.string.result_component_upi
            label.contains("URL") -> R.string.result_component_url
            label.contains("NLP") -> R.string.result_component_nlp
            label.contains("BODMAS") -> R.string.result_component_heuristic
            label.contains("Typosquat") -> R.string.result_component_typosquat
            label.contains("Cloud") -> R.string.result_component_cloud
            else -> R.string.result_component_security
        }
        return strings(context, useTamil).getString(resId)
    }

    fun componentDetail(
        context: Context,
        status: ComponentStatus,
        original: String?,
        useTamil: Boolean
    ): String? {
        if (!useTamil) return original
        val resId = when (status) {
            ComponentStatus.SAFE -> R.string.result_component_detail_safe
            ComponentStatus.WARNING -> R.string.result_component_detail_warning
            ComponentStatus.DANGER -> R.string.result_component_detail_danger
        }
        return strings(context, true).getString(resId)
    }

    fun componentScore(context: Context, score: Int, applicable: Boolean, useTamil: Boolean): String {
        val strings = strings(context, useTamil)
        return if (applicable) strings.getString(R.string.result_component_score_format, score)
        else strings.getString(R.string.result_component_not_applicable)
    }

    private fun tamilPreferenceEnabled(context: Context): Boolean = context
        .getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
        .getBoolean(Constants.KEY_LANGUAGE_TAMIL, false)

    private fun strings(context: Context, useTamil: Boolean): Context {
        val config = Configuration(context.resources.configuration).apply {
            setLocale(if (useTamil) Locale("ta", "IN") else Locale.US)
        }
        return context.createConfigurationContext(config)
    }

    private fun categoryLabel(context: Context, category: ThreatCategory): String = context.getString(
        when (category) {
            ThreatCategory.SAFE -> R.string.result_category_safe
            ThreatCategory.PHISHING -> R.string.result_category_phishing
            ThreatCategory.SCAM, ThreatCategory.FRAUD -> R.string.result_category_scam
            ThreatCategory.OTP_FRAUD -> R.string.result_category_otp_fraud
            ThreatCategory.FAKE_JOB -> R.string.result_category_fake_job
            ThreatCategory.SUSPICIOUS -> R.string.result_category_suspicious
            ThreatCategory.SPAM -> R.string.result_category_spam
            ThreatCategory.BEC_FRAUD, ThreatCategory.BEC -> R.string.result_category_bec_fraud
            ThreatCategory.SPOOFING, ThreatCategory.SPOOFED -> R.string.result_category_spoofing
            ThreatCategory.IMPERSONATION -> R.string.result_category_spoofing
            ThreatCategory.MALWARE -> R.string.result_category_scam
            else -> R.string.result_category_suspicious
        }
    )

    private fun summaryForVerdict(context: Context, verdict: ThreatVerdict): String = context.getString(
        when (verdict) {
            ThreatVerdict.SAFE -> R.string.result_summary_safe
            ThreatVerdict.WARNING -> R.string.result_summary_warning
            ThreatVerdict.DANGER -> R.string.result_summary_danger
        }
    )

    private fun recommendationsForVerdict(context: Context, verdict: ThreatVerdict): List<String> = when (verdict) {
        ThreatVerdict.SAFE -> listOf(context.getString(R.string.result_recommendation_safe))
        ThreatVerdict.WARNING -> listOf(
            context.getString(R.string.result_recommendation_warning_one),
            context.getString(R.string.result_recommendation_warning_two)
        )
        ThreatVerdict.DANGER -> listOf(
            context.getString(R.string.result_recommendation_danger_one),
            context.getString(R.string.result_recommendation_danger_two),
            context.getString(R.string.result_recommendation_danger_three)
        )
    }
}

internal data class LoadingPresentation(
    val title: String,
    val score: String,
    val status: String,
    val summary: String,
    val recommendations: String
)
