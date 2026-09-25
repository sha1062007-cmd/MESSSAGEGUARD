package com.messageguard.threatvision.domain.voice

import android.content.Context
import android.content.res.Configuration
import android.media.AudioManager
import android.media.ToneGenerator
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.VibrationEffect
import android.os.Vibrator
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.speech.tts.TextToSpeech
import android.util.Log
import com.messageguard.MessageLanguageDetector
import com.messageguard.R
import com.messageguard.threatvision.data.model.ThreatVerdict
import java.util.Locale

/**
 * One-shot, user-initiated voice command manager.
 *
 * Recording starts only after the user long-presses the MessageGuard bubble.
 * This class deliberately contains no wake-word detection or recognizer
 * re-arm path, so it cannot listen in the background or create a restart loop.
 */
class VoiceCommandManager private constructor(private val context: Context) : TextToSpeech.OnInitListener {

    enum class ListeningState {
        ACTIVE_COMMAND,
        ANALYZING,
        STOPPED
    }

    sealed class VoiceCommand {
        object ScanThis : VoiceCommand()
        object ScanPage : VoiceCommand()
        object ToggleOn : VoiceCommand()
        object ToggleOff : VoiceCommand()
        data class Unknown(val spokenText: String) : VoiceCommand()
    }

    var onStateChanged: ((ListeningState) -> Unit)? = null
    var onCommandRecognized: ((VoiceCommand) -> Unit)? = null
    var onError: ((String) -> Unit)? = null

    private var speechRecognizer: SpeechRecognizer? = null
    private var textToSpeech: TextToSpeech? = null
    private var isTtsReady = false

    @Volatile
    var currentState: ListeningState = ListeningState.STOPPED
        private set

    @Volatile
    private var detectedTamilMode = false

    companion object {
        private const val TAG = "ThreatVisionLog"
        private const val TRY_AGAIN_MESSAGE = "Didn't catch that, try again"
        private val mainHandler = Handler(Looper.getMainLooper())

        private val FULL_SCREEN_KEYWORDS = listOf(
            "page", "screen", "all", "entire", "full", "whole", "scan page", "scan the page", "scan entire page", "scan full page", "scan whole page", "scan full screen", "scan the screen", "scan all", "scan whole screen",
            "பக்கத்தை", "பக்கம்", "முழு", "திரை", "திரையை"
        )
        private val SELECTION_KEYWORDS = listOf(
            "this", "circle", "select", "selection", "region", "crop", "area", "scan this message", "check this message", "is this message safe", "scan this", "circle to scan", "scan",
            "இதை", "வட்டம்", "வட்டத்தை", "தேர்வு"
        )
        private val TOGGLE_ON_KEYWORDS = listOf(
            "turn on", "enable", "start threat vision", "turn on threat vision", "activate threat vision"
        )
        private val TOGGLE_OFF_KEYWORDS = listOf(
            "turn off", "disable", "stop threat vision", "turn off threat vision", "deactivate threat vision"
        )

        @Volatile
        private var instance: VoiceCommandManager? = null

        fun getInstance(context: Context): VoiceCommandManager {
            return instance ?: synchronized(this) {
                instance ?: VoiceCommandManager(context.applicationContext).also { instance = it }
            }
        }
    }

    init {
        mainHandler.post {
            textToSpeech = TextToSpeech(context.applicationContext, this)
        }
    }

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS) {
            val result = textToSpeech?.setLanguage(Locale.US)
            isTtsReady = result != TextToSpeech.LANG_MISSING_DATA &&
                result != TextToSpeech.LANG_NOT_SUPPORTED
            Log.d(TAG, "VoiceCommandManager: TTS initialized. isReady=$isTtsReady")
        } else {
            Log.w(TAG, "VoiceCommandManager: TTS initialization failed.")
        }
    }

    /** Starts exactly one speech-recognition session after an explicit PTT gesture. */
    fun startListeningForCommand() {
        mainHandler.post {
            if (!SpeechRecognizer.isRecognitionAvailable(context)) {
                reportRecognitionFailure("recognition unavailable")
                return@post
            }

            destroySpeechRecognizer()
            detectedTamilMode = false
            playListeningStartChime()
            transitionTo(ListeningState.ACTIVE_COMMAND)
            Log.d(TAG, "VoiceCommandManager: PTT recognition started.")

            speechRecognizer = SpeechRecognizer.createSpeechRecognizer(context).apply {
                setRecognitionListener(object : RecognitionListener {
                    override fun onReadyForSpeech(params: Bundle?) {
                        Log.d(TAG, "VoiceCommandManager: PTT ready for speech.")
                    }

                    override fun onBeginningOfSpeech() {
                        Log.d(TAG, "VoiceCommandManager: PTT speech started.")
                    }

                    override fun onRmsChanged(rmsdB: Float) = Unit
                    override fun onBufferReceived(buffer: ByteArray?) = Unit

                    override fun onEndOfSpeech() {
                        Log.d(TAG, "VoiceCommandManager: PTT speech ended.")
                    }

                    override fun onError(error: Int) {
                        reportRecognitionFailure("SpeechRecognizer error=$error")
                    }

                    override fun onResults(results: Bundle?) {
                        val spokenText = results
                            ?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
                            ?.firstOrNull()
                            ?.lowercase(Locale.ROOT)
                            ?.trim()

                        if (spokenText.isNullOrBlank()) {
                            reportRecognitionFailure("empty recognition result")
                            return
                        }

                        Log.d(TAG, "VoiceCommandManager: PTT recognized '$spokenText'.")
                        destroySpeechRecognizer()
                        onCommandRecognized?.invoke(parseCommand(spokenText))
                    }

                    override fun onPartialResults(partialResults: Bundle?) = Unit
                    override fun onEvent(eventType: Int, params: Bundle?) = Unit
                })
            }

            try {
                speechRecognizer?.startListening(createRecognizerIntent())
            } catch (error: Exception) {
                Log.w(TAG, "VoiceCommandManager: Unable to start PTT recognition.", error)
                reportRecognitionFailure("startListening exception")
            }
        }
    }

    /** Cancels an in-progress one-shot recognition session, if any. */
    fun cancelListening() {
        mainHandler.post {
            destroySpeechRecognizer()
            transitionTo(ListeningState.STOPPED)
        }
    }

    fun signalAnalysisComplete() {
        mainHandler.post {
            transitionTo(ListeningState.STOPPED)
        }
    }

    fun signalAnalyzing() {
        mainHandler.post {
            transitionTo(ListeningState.ANALYZING)
        }
    }

    private fun reportRecognitionFailure(detail: String) {
        Log.w(TAG, "VoiceCommandManager: PTT failed: $detail")
        destroySpeechRecognizer()
        playTryAgainChime()
        onError?.invoke(TRY_AGAIN_MESSAGE)
        transitionTo(ListeningState.STOPPED)
    }

    private fun parseCommand(text: String): VoiceCommand {
        detectedTamilMode = text.any { it.code in 0x0B80..0x0BFF }
        val lower = text.lowercase(Locale.ROOT)
        return when {
            TOGGLE_ON_KEYWORDS.any(lower::contains) -> VoiceCommand.ToggleOn
            TOGGLE_OFF_KEYWORDS.any(lower::contains) -> VoiceCommand.ToggleOff
            FULL_SCREEN_KEYWORDS.any(lower::contains) -> VoiceCommand.ScanPage
            SELECTION_KEYWORDS.any(lower::contains) -> VoiceCommand.ScanThis
            else -> VoiceCommand.Unknown(text)
        }
    }

    fun interpretText(text: String): VoiceCommand = parseCommand(text)

    fun playPreScanChime() = playChime(ToneGenerator.TONE_PROP_ACK)

    fun playListeningStartChime() = playChime(ToneGenerator.TONE_PROP_BEEP)

    fun playTryAgainChime() = playChime(ToneGenerator.TONE_PROP_NACK)

    fun playVerdictTone(verdict: ThreatVerdict) {
        val toneType = when (verdict) {
            ThreatVerdict.SAFE -> ToneGenerator.TONE_PROP_BEEP
            ThreatVerdict.WARNING -> ToneGenerator.TONE_PROP_NACK
            ThreatVerdict.DANGER -> ToneGenerator.TONE_SUP_ERROR
        }
        playChime(toneType)
    }

    fun speakVerdict(
        verdict: ThreatVerdict,
        reason: String,
        detectedTamilContent: Boolean = false
    ) {
        // Only speak for WARNING or DANGER — avoid alert fatigue on SAFE
        // 1. Play vibration immediately for user feedback (independent of TTS readiness)
        try {
            val vibrator = context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
            if (vibrator != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    val pattern = when (verdict) {
                        ThreatVerdict.DANGER -> longArrayOf(0, 200, 100, 200, 100, 200)
                        ThreatVerdict.WARNING -> longArrayOf(0, 150, 100, 150)
                        else -> longArrayOf(0, 100)
                    }
                    val effect = VibrationEffect.createWaveform(pattern, -1)
                    vibrator.vibrate(effect)
                } else {
                    val pattern = when (verdict) {
                        ThreatVerdict.DANGER -> longArrayOf(0, 200, 100, 200, 100, 200)
                        ThreatVerdict.WARNING -> longArrayOf(0, 150, 100, 150)
                        else -> longArrayOf(0, 100)
                    }
                    vibrator.vibrate(pattern, -1)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "VoiceCommandManager: Vibration failed", e)
        }

        // Play tone immediately (independent of TTS readiness)
        playVerdictTone(verdict)

        // 2. Speak the warning if TTS is ready
        if (!isTtsReady) {
            Log.d(TAG, "VoiceCommandManager: speakVerdict skipped speaking because TTS is not ready.")
            return
        }

        val prefs = context.getSharedPreferences(com.messageguard.Constants.PREFS_NAME, Context.MODE_PRIVATE)
        val forceTamil = prefs.getBoolean(com.messageguard.Constants.KEY_LANGUAGE_TAMIL, false)
        val isTamilMode = forceTamil || detectedTamilContent || MessageLanguageDetector.shouldUseTamil(reason)

        // Use target locale (Tamil ta_IN if forced or Tamil script present, otherwise system locale)
        val targetLocale = if (isTamilMode) Locale("ta", "IN") else Locale.getDefault()
        val languageResult = runCatching { textToSpeech?.setLanguage(targetLocale) }
            .getOrNull() ?: TextToSpeech.LANG_NOT_SUPPORTED

        if (!isTamilMode && (languageResult == TextToSpeech.LANG_MISSING_DATA || languageResult == TextToSpeech.LANG_NOT_SUPPORTED)) {
            // Fallback to English
            textToSpeech?.language = Locale.US
        }

        var ttsMessage = when (verdict) {
            ThreatVerdict.WARNING -> {
                if (isTamilMode) "எச்சரிக்கை. இந்த செய்தி சந்தேகத்திற்குரியது."
                else context.getString(R.string.tts_verdict_warning)
            }
            ThreatVerdict.DANGER -> {
                if (isTamilMode) "எச்சரிக்கை. இந்த செய்தி ஒரு மோசடியாக இருக்கலாம். எந்தவொரு இணைப்பையும் கிளிக் செய்ய வேண்டாம் அல்லது உங்கள் ஓடிபியைப் பகிர வேண்டாம்."
                else context.getString(R.string.tts_verdict_danger)
            }
            else -> context.getString(R.string.tts_verdict_warning)
        }

        val ttsContext = localizedContext(isTamilMode)
        ttsMessage = when (verdict) {
            ThreatVerdict.SAFE -> ttsContext.getString(R.string.tts_verdict_safe)
            ThreatVerdict.WARNING -> ttsContext.getString(R.string.tts_verdict_warning)
            ThreatVerdict.DANGER -> ttsContext.getString(R.string.tts_verdict_danger)
        }
        Log.i(TAG, "speakVerdict: TTS locale=${targetLocale.toLanguageTag()} (isTamilMode=$isTamilMode) | text='$ttsMessage'")
        textToSpeech?.speak(ttsMessage, TextToSpeech.QUEUE_FLUSH, null, "MessageGuardVerdict")
    }

    private fun localizedContext(useTamil: Boolean): Context {
        val config = Configuration(context.resources.configuration).apply {
            setLocale(if (useTamil) Locale("ta", "IN") else Locale.US)
        }
        return context.createConfigurationContext(config)
    }

    /**
     * Immediately stops any in-progress TTS utterance.
     * Safe to call at any time — does NOT tear down the engine.
     * Call this whenever the result overlay is dismissed so TTS
     * doesn't keep speaking after the UI is gone.
     */
    fun stopSpeaking() {
        textToSpeech?.stop()
        Log.d(TAG, "VoiceCommandManager: TTS stopped (overlay dismissed).")
    }

    fun speakError(message: String) {
        if (!isTtsReady) return
        // Prefer localized short error messages when available
        val localized = when {
            message.contains("Scan failed", ignoreCase = true) -> context.getString(R.string.tts_error_scan_failed)
            message.contains("not active", ignoreCase = true) -> context.getString(R.string.tts_error_not_active)
            message.contains("timed out", ignoreCase = true) -> context.getString(R.string.tts_error_timed_out)
            else -> message
        }
        textToSpeech?.speak(localized, TextToSpeech.QUEUE_FLUSH, null, "MessageGuardError")
    }

    private fun playChime(toneType: Int) {
        try {
            val toneGenerator = ToneGenerator(AudioManager.STREAM_NOTIFICATION, 80)
            toneGenerator.startTone(toneType, 200)
            mainHandler.postDelayed({ toneGenerator.release() }, 300)
        } catch (error: Exception) {
            Log.w(TAG, "VoiceCommandManager: Chime playback failed.", error)
        }
    }

    private fun createRecognizerIntent(): android.content.Intent {
        return android.content.Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            // Use the phone's configured speech language; do not require unavailable offline packs.
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, Locale.getDefault().toLanguageTag())
            putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, false)
            putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 3)
        }
    }

    private fun transitionTo(newState: ListeningState) {
        if (currentState == newState) return
        Log.d(TAG, "VoiceCommandManager: State transition $currentState -> $newState")
        currentState = newState
        onStateChanged?.invoke(newState)
    }

    private fun destroySpeechRecognizer() {
        try {
            speechRecognizer?.stopListening()
            speechRecognizer?.cancel()
            speechRecognizer?.destroy()
        } catch (error: Exception) {
            Log.w(TAG, "VoiceCommandManager: SpeechRecognizer release failed.", error)
        } finally {
            speechRecognizer = null
        }
    }

    fun shutdown() {
        cancelListening()
        mainHandler.post {
            textToSpeech?.stop()
            textToSpeech?.shutdown()
            textToSpeech = null
            isTtsReady = false
            synchronized(VoiceCommandManager::class.java) {
                if (instance === this) instance = null
            }
        }
    }
}
