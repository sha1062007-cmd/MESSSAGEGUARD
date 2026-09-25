package com.messageguard

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.map
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val repo = AnalysisRepository(app)
    private val prefs = app.getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)

    val recentScans: LiveData<List<AnalysisResult>> = repo.getRecentFiveLive()

    private val _stats = MutableLiveData<DashboardStats>()
    val stats: LiveData<DashboardStats> = _stats

    val isEnabled: LiveData<Boolean> = com.messageguard.threatvision.state.ThreatVisionStateHolder.liveData.map { state ->
        state.isProtectionEnabled
    }

    init {
        com.messageguard.threatvision.state.ThreatVisionStateHolder.initialize(app)
        loadStats()
    }

    fun loadStats() {
        viewModelScope.launch {
            _stats.postValue(repo.getDashboardStats())
        }
    }

    fun toggleService(enabled: Boolean) {
        if (enabled) {
            com.messageguard.threatvision.state.ThreatVisionStateHolder.enableProtection(getApplication())
        } else {
            com.messageguard.threatvision.state.ThreatVisionStateHolder.disableProtection(getApplication())
        }
    }
}
