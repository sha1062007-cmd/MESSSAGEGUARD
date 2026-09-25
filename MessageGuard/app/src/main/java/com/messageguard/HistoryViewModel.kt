package com.messageguard

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch

class HistoryViewModel(app: Application) : AndroidViewModel(app) {

    private val repo = AnalysisRepository(app)
    
    private val allScans: LiveData<List<AnalysisResult>> = repo.getAllLive()
    private val _filter = MutableLiveData<Verdict?>(null)
    private val _searchQuery = MutableLiveData<String>("")

    val scans: LiveData<List<AnalysisResult>> = MediatorLiveData<List<AnalysisResult>>().apply {
        addSource(allScans) { value = filterList(it, _filter.value, _searchQuery.value) }
        addSource(_filter) { value = filterList(allScans.value, it, _searchQuery.value) }
        addSource(_searchQuery) { value = filterList(allScans.value, _filter.value, it) }
    }

    fun filterBy(verdict: Verdict?) { 
        _filter.value = verdict 
    }

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun deleteItem(id: Long) {
        viewModelScope.launch { repo.deleteById(id) }
    }

    private fun filterList(list: List<AnalysisResult>?, verdict: Verdict?, query: String?): List<AnalysisResult> {
        val baseList = list ?: emptyList()
        val q = query?.trim()?.lowercase() ?: ""
        return baseList.filter { item ->
            val matchVerdict = verdict == null || item.verdict == verdict
            val senderText = item.sender?.lowercase().orEmpty()
            val snippetText = item.messageSnippet?.lowercase().orEmpty()
            val subjectText = item.subject?.lowercase().orEmpty()
            val matchQuery = q.isEmpty() || 
                    senderText.contains(q) || 
                    snippetText.contains(q) ||
                    subjectText.contains(q)
            matchVerdict && matchQuery
        }
    }
}
