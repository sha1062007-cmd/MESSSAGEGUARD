package com.messageguard

import android.content.Intent
import android.os.Bundle
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup

class HistoryActivity : AppCompatActivity() {

    private val viewModel: HistoryViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_history)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = "Scan History"

        val rv = findViewById<RecyclerView>(R.id.rv_history)
        val chipGroup = findViewById<ChipGroup>(R.id.chip_group_filter)
        val etSearch = findViewById<android.widget.EditText>(R.id.et_search)

        rv.layoutManager = LinearLayoutManager(this)
        val adapter = HistoryAdapter { result ->
            val intent = Intent(this, DetailActivity::class.java)
            intent.putExtra("result_id", result.id)
            startActivity(intent)
        }
        rv.adapter = adapter

        viewModel.scans.observe(this) { adapter.submitList(it) }

        etSearch.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                viewModel.setSearchQuery(s?.toString() ?: "")
            }
            override fun afterTextChanged(s: android.text.Editable?) {}
        })

        chipGroup.setOnCheckedStateChangeListener { group, checkedIds ->
            when (checkedIds.firstOrNull()) {
                R.id.chip_all -> viewModel.filterBy(null)
                R.id.chip_danger -> viewModel.filterBy(Verdict.DANGER)
                R.id.chip_warning -> viewModel.filterBy(Verdict.WARNING)
                R.id.chip_safe -> viewModel.filterBy(Verdict.SAFE)
                else -> viewModel.filterBy(null)
            }
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }
}
