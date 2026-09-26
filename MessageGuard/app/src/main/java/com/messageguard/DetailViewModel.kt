package com.messageguard

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

// ──────────────────────────────────────────────────────────────────────────────
// Data classes for reactive map state
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Represents one geolocated hop in the relay chain that should appear on the map.
 */
data class MapHop(
    val hopIndex: Int,
    val ip: String,
    val lat: Double,
    val lon: Double,
    val city: String,
    val region: String,
    val country: String,
    val isp: String,
    val classification: String,   // "PUBLIC", "PRIVATE", etc.
    val isEarliestPublic: Boolean // ★ the primary forensic marker
)

/**
 * Sealed states for the map component — drives visibility logic.
 */
sealed class MapState {
    /** GeoIP fetch is in progress — show a loading spinner on the map */
    object Loading : MapState()

    /** No public IP was found, or GeoIP failed — show empty-state overlay */
    data class NoLocation(val reason: String) : MapState()

    /** One or more geolocated public hops are ready to display */
    data class Ready(val hops: List<MapHop>) : MapState()
}

/**
 * ViewModel for DetailActivity.
 * Owns the analysis JSON + reactive map state.
 * Survives configuration changes so the map is NOT recreated on rotation.
 */
class DetailViewModel : ViewModel() {

    private val _mapState = MutableStateFlow<MapState>(MapState.Loading)
    val mapState: StateFlow<MapState> = _mapState.asStateFlow()

    private val _analysisJson = MutableStateFlow<String?>(null)
    val analysisJson: StateFlow<String?> = _analysisJson.asStateFlow()

    /** Called once when the Activity receives a new analysis result. */
    fun loadAnalysis(jsonStr: String?) {
        _analysisJson.value = jsonStr
        _mapState.value = MapState.Loading
    }

    /**
     * Resolves the map state from the parsed JSON object.
     * Call this AFTER the JSON has been parsed and GeoIP fields are known.
     *
     * @param hops    All public routable hops with valid lat/lon extracted from relay_chain
     * @param noLocationReason  Human-readable explanation when there are no public hops
     */
    fun resolveMapState(hops: List<MapHop>, noLocationReason: String) {
        _mapState.value = if (hops.isEmpty()) {
            MapState.NoLocation(noLocationReason)
        } else {
            MapState.Ready(hops)
        }
    }

    /** Force a reload / re-analysis without recreating the Activity. */
    fun invalidate() {
        _mapState.value = MapState.Loading
    }
}
