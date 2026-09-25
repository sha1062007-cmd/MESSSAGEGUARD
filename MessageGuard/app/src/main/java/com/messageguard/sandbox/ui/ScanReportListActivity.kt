package com.messageguard.sandbox.ui

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.messageguard.AnalysisHistoryDatabase
import com.messageguard.R
import com.messageguard.sandbox.report.ScanReport
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ScanReportListActivity : AppCompatActivity() {

    private lateinit var adapter: ScanReportAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan_report_list)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar_scan_reports)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener { finish() }

        val rv = findViewById<RecyclerView>(R.id.rv_scan_reports)
        val tvEmpty = findViewById<TextView>(R.id.tv_empty_scan_reports)

        rv.layoutManager = LinearLayoutManager(this)
        adapter = ScanReportAdapter { report ->
            val intent = Intent(this, ScanReportDetailActivity::class.java).apply {
                putExtra(ScanReportDetailActivity.EXTRA_REPORT_ID, report.id)
            }
            startActivity(intent)
        }
        rv.adapter = adapter

        val db = AnalysisHistoryDatabase.getInstance(this)
        db.scanReportDao().getAllLive().observe(this) { reports ->
            adapter.submitList(reports)
            tvEmpty.visibility = if (reports.isNullOrEmpty()) View.VISIBLE else View.GONE
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}

class ScanReportAdapter(
    private val onItemClick: (ScanReport) -> Unit
) : ListAdapter<ScanReport, ScanReportAdapter.ViewHolder>(DiffCallback) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_scan_report, parent, false)
        return ViewHolder(view, onItemClick)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    class ViewHolder(itemView: View, val onItemClick: (ScanReport) -> Unit) : RecyclerView.ViewHolder(itemView) {
        private val viewVerdictBar = itemView.findViewById<View>(R.id.view_verdict_bar)
        private val tvVerdict = itemView.findViewById<TextView>(R.id.tv_scan_report_verdict)
        private val tvSource = itemView.findViewById<TextView>(R.id.tv_scan_report_source)
        private val tvFilename = itemView.findViewById<TextView>(R.id.tv_scan_report_filename)
        private val tvScore = itemView.findViewById<TextView>(R.id.tv_scan_report_score)
        private val tvTime = itemView.findViewById<TextView>(R.id.tv_scan_report_time)

        fun bind(report: ScanReport) {
            val color = when (report.verdict) {
                "SAFE" -> Color.parseColor("#00E676")
                "SUSPICIOUS" -> Color.parseColor("#FFC400")
                "MALICIOUS" -> Color.parseColor("#FF1744")
                else -> Color.parseColor("#8F9CAE")
            }

            viewVerdictBar.setBackgroundColor(color)
            tvVerdict.text = report.verdict
            tvVerdict.setTextColor(color)
            tvSource.text = report.sourceApp.ifBlank { "unknown" }
            tvFilename.text = report.fileName
            tvScore.text = "Score: ${report.finalScore}/100"
            tvTime.text = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault()).format(Date(report.timestamp))

            itemView.setOnClickListener { onItemClick(report) }
        }
    }

    object DiffCallback : DiffUtil.ItemCallback<ScanReport>() {
        override fun areItemsTheSame(oldItem: ScanReport, newItem: ScanReport): Boolean = oldItem.id == newItem.id
        override fun areContentsTheSame(oldItem: ScanReport, newItem: ScanReport): Boolean = oldItem == newItem
    }
}

