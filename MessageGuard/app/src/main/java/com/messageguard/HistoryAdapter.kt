package com.messageguard

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import java.text.SimpleDateFormat
import java.util.Locale

class HistoryAdapter(
    private val onClick: (AnalysisResult) -> Unit
) : ListAdapter<AnalysisResult, HistoryAdapter.ViewHolder>(DIFF) {

    companion object {
        val DIFF = object : DiffUtil.ItemCallback<AnalysisResult>() {
            override fun areItemsTheSame(a: AnalysisResult, b: AnalysisResult) = a.id == b.id
            override fun areContentsTheSame(a: AnalysisResult, b: AnalysisResult) = a == b
        }
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvVerdict: TextView = view.findViewById(R.id.tv_item_verdict)
        val tvSender: TextView = view.findViewById(R.id.tv_item_sender)
        val tvApp: TextView = view.findViewById(R.id.tv_item_app)
        val tvScore: TextView = view.findViewById(R.id.tv_item_score)
        val tvTime: TextView = view.findViewById(R.id.tv_item_time)
        val verdictBar: View = view.findViewById(R.id.view_verdict_bar)
        val container: View = view.findViewById(R.id.layout_item_container)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_history, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val result = getItem(position)
        val fmt = SimpleDateFormat("MMM dd HH:mm", Locale.getDefault())
        holder.tvVerdict.text = result.verdict.name
        holder.tvSender.text = result.sender.take(30)
        holder.tvApp.text = result.appSource
        holder.tvScore.text = "Risk: ${result.riskScore}/100"
        holder.tvTime.text = fmt.format(result.timestamp)

        val containerBg = when (result.verdict) {
            Verdict.SAFE -> R.drawable.bg_emerald_glass_card
            Verdict.WARNING -> R.drawable.bg_amber_glass_card
            Verdict.DANGER -> R.drawable.bg_ruby_glass_card
            Verdict.UNCERTAIN -> R.drawable.bg_amber_glass_card
        }
        holder.container.setBackgroundResource(containerBg)

        val color = when (result.verdict) {
            Verdict.SAFE -> Color.parseColor("#00E676")
            Verdict.WARNING -> Color.parseColor("#FFC400")
            Verdict.DANGER -> Color.parseColor("#FF1744")
            Verdict.UNCERTAIN -> Color.parseColor("#9E9E9E")
        }
        holder.tvVerdict.setTextColor(color)
        holder.itemView.setOnClickListener { onClick(result) }
    }
}
