package com.bruno.antitamperingapp

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.bruno.antitamperingapp.detection.DetectionEngine
import com.bruno.antitamperingapp.detection.TamperVerdict
import com.bruno.antitamperingapp.detection.detectors.CloningDetector
import com.bruno.antitamperingapp.detection.detectors.EmulatorDetector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val engine = DetectionEngine.Builder()
        .addDetector(EmulatorDetector())
        .addDetector(CloningDetector())
        // Future: .addDetector(IntegrityDetector())
        // Future: .addDetector(HookingDetector())
        .build()

    private val _uiState = MutableStateFlow<ScanState>(ScanState.Idle)
    val uiState: StateFlow<ScanState> = _uiState.asStateFlow()

    fun runScan() {
        if (_uiState.value is ScanState.Scanning) return
        _uiState.value = ScanState.Scanning

        viewModelScope.launch {
            val verdict = engine.evaluate(getApplication())
            _uiState.value = ScanState.Complete(verdict)
        }
    }
}

sealed class ScanState {
    data object Idle : ScanState()
    data object Scanning : ScanState()
    data class Complete(val verdict: TamperVerdict) : ScanState()
}
