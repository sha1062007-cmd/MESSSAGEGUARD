package com.messageguard.sandbox.ui

import android.content.res.ColorStateList
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.messageguard.AnalysisHistoryDatabase
import com.messageguard.R
import com.messageguard.sandbox.report.ScanReport
import com.messageguard.sandbox.report.ScanSummaryGenerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ScanReportDetailActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_REPORT_ID = "extra_report_id"
        private const val TAG = "ScanReportDetail"
    }

    private var reportId: String? = null
    private var isTechnicalExpanded = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan_report_detail)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = "Threat Analysis Report"

        reportId = intent.getStringExtra(EXTRA_REPORT_ID)
        if (reportId == null) {
            Log.e(TAG, "No report ID provided")
            finish()
            return
        }

        loadReportDetails(reportId!!)
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }

    private fun loadReportDetails(id: String) {
        lifecycleScope.launch {
            val db = AnalysisHistoryDatabase.getInstance(this@ScanReportDetailActivity)
            val report = withContext(Dispatchers.IO) {
                db.scanReportDao().getById(id)
            }

            if (report == null) {
                Log.w(TAG, "Report not found for ID $id")
                finish()
                return@launch
            }

            bindViews(report)
        }
    }

    private fun bindViews(report: ScanReport) {
        val summary = ScanSummaryGenerator.generate(report)

        val tvVerdict = findViewById<TextView>(R.id.tv_detail_verdict)
        val tvScore = findViewById<TextView>(R.id.tv_detail_score)
        val progressScore = findViewById<ProgressBar>(R.id.progress_detail_score)
        val tvFilename = findViewById<TextView>(R.id.tv_detail_filename)
        val tvAppTime = findViewById<TextView>(R.id.tv_detail_app_time)
        val tvPlainSummary = findViewById<TextView>(R.id.tv_detail_plain_summary)
        val tvTechnical = findViewById<TextView>(R.id.tv_detail_technical)
        val layoutToggleTech = findViewById<LinearLayout>(R.id.layout_toggle_technical)
        val tvToggleIcon = findViewById<TextView>(R.id.tv_technical_toggle_icon)

        val color = when (report.verdict) {
            "SAFE" -> Color.parseColor("#00E676")
            "SUSPICIOUS" -> Color.parseColor("#FFC400")
            "MALICIOUS" -> Color.parseColor("#FF1744")
            else -> Color.parseColor("#8F9CAE")
        }

        tvVerdict.text = "${report.verdict} VERDICT"
        tvVerdict.setTextColor(color)
        tvScore.text = "Score: ${report.finalScore}/100"
        tvScore.setTextColor(color)
        progressScore.progress = report.finalScore
        progressScore.progressTintList = ColorStateList.valueOf(color)

        tvFilename.text = "File: ${report.fileName}"
        val dateStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(report.timestamp))
        tvAppTime.text = "Source: ${report.sourceApp.ifBlank { "unknown" }} • $dateStr"

        tvPlainSummary.text = summary.plainSummary
        tvTechnical.text = summary.technicalDetail

        layoutToggleTech.setOnClickListener {
            isTechnicalExpanded = !isTechnicalExpanded
            tvTechnical.visibility = if (isTechnicalExpanded) View.VISIBLE else View.GONE
            tvToggleIcon.text = if (isTechnicalExpanded) "[Hide]" else "[Show]"
        }

        setupFeedbackCard(report)
    }

    private fun setupFeedbackCard(report: ScanReport) {
        val layoutUnflagged = findViewById<LinearLayout>(R.id.layout_feedback_unflagged)
        val layoutFlagged = findViewById<LinearLayout>(R.id.layout_feedback_flagged)
        val btnFlag = findViewById<MaterialButton>(R.id.btn_flag_false_positive)
        val layoutForm = findViewById<LinearLayout>(R.id.layout_feedback_form)
        val etNote = findViewById<EditText>(R.id.et_feedback_note)
        val btnSubmit = findViewById<MaterialButton>(R.id.btn_submit_flag)
        val tvFlaggedNote = findViewById<TextView>(R.id.tv_flagged_note)

        if (report.isFalsePositiveFlagged) {
            layoutUnflagged.visibility = View.GONE
            layoutFlagged.visibility = View.VISIBLE
            if (report.userNote.isNotBlank()) {
                tvFlaggedNote.text = "Note: \"${report.userNote}\""
                tvFlaggedNote.visibility = View.VISIBLE
            }
        } else {
            layoutUnflagged.visibility = View.VISIBLE
            layoutFlagged.visibility = View.GONE

            btnFlag.setOnClickListener {
                layoutForm.visibility = View.VISIBLE
                btnFlag.visibility = View.GONE
            }

            btnSubmit.setOnClickListener {
                val note = etNote.text.toString().trim()
                btnSubmit.isEnabled = false
                lifecycleScope.launch {
                    withContext(Dispatchers.IO) {
                        val db = AnalysisHistoryDatabase.getInstance(this@ScanReportDetailActivity)
                        db.scanReportDao().flagFalsePositive(report.id, note)
                    }
                    Log.i(TAG, "Flagged false positive for report ${report.id}, note: '$note'")
                    layoutUnflagged.visibility = View.GONE
                    layoutFlagged.visibility = View.VISIBLE
                    if (note.isNotBlank()) {
                        tvFlaggedNote.text = "Note: \"$note\""
                        tvFlaggedNote.visibility = View.VISIBLE
                    }
                }
            }
        }
    }
}

