package com.messageguard.threatvision.ui.main

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.speech.RecognizerIntent
import android.util.Log
import android.widget.Toast
import com.messageguard.threatvision.domain.voice.VoiceCommandManager
import com.messageguard.threatvision.service.FloatingBubbleService
import java.util.Locale

/**
 * Translucent Activity that launches the native Android Speech Recognition Intent
 * (RecognizerIntent.ACTION_RECOGNIZE_SPEECH).
 *
 * Displays the native Android Google Speech dialog box (microphone animation & speech input UI).
 * Upon speech recognition completion, parses the recognized command and forwards it
 * to FloatingBubbleService to trigger full-screen capture or region selection canvas.
 */
class VoiceCommandActivity : Activity() {

    companion object {
        private const val REQUEST_CODE_SPEECH_INPUT = 1001
        private const val TAG = "ThreatVisionLog"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Check if an external or system intent provided the voice command directly
        val directText = intent?.getStringExtra(FloatingBubbleService.EXTRA_SPOKEN_TEXT)
            ?: intent?.getStringExtra(RecognizerIntent.EXTRA_RESULTS)
            ?: intent?.getStringExtra("query")
            ?: intent?.getStringExtra("command")

        if (!directText.isNullOrBlank()) {
            Log.d(TAG, "VoiceCommandActivity: Received direct voice command text: '$directText'")
            forwardSpokenText(directText)
            finish()
            return
        }

        promptSpeechInput()
    }

    private fun forwardSpokenText(spokenText: String) {
        val bubbleIntent = Intent(this, FloatingBubbleService::class.java).apply {
            action = FloatingBubbleService.ACTION_HANDLE_VOICE_COMMAND
            putExtra(FloatingBubbleService.EXTRA_SPOKEN_TEXT, spokenText)
        }
        androidx.core.content.ContextCompat.startForegroundService(this, bubbleIntent)
    }

    private fun promptSpeechInput() {
        val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, Locale.getDefault())
            putExtra(RecognizerIntent.EXTRA_PROMPT, "Say 'scan the page' or 'scan this'")
        }

        try {
            startActivityForResult(intent, REQUEST_CODE_SPEECH_INPUT)
        } catch (e: ActivityNotFoundException) {
            Log.w(TAG, "VoiceCommandActivity: Speech recognition intent not supported on this device. Falling back.", e)
            Toast.makeText(this, "Voice recognition intent unavailable", Toast.LENGTH_SHORT).show()
            // Fallback to service-level SpeechRecognizer
            val voiceManager = VoiceCommandManager.getInstance(this)
            voiceManager.startListeningForCommand()
            finish()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == REQUEST_CODE_SPEECH_INPUT) {
            if (resultCode == RESULT_OK && data != null) {
                val results = data.getStringArrayListExtra(RecognizerIntent.EXTRA_RESULTS)
                val spokenText = results?.firstOrNull()
                Log.d(TAG, "VoiceCommandActivity: Recognized speech via Intent: '$spokenText'")

                if (!spokenText.isNullOrBlank()) {
                    forwardSpokenText(spokenText)
                }
            } else {
                Log.d(TAG, "VoiceCommandActivity: Speech recognition cancelled or returned no result (resultCode=$resultCode)")
            }
            finish()
        }
    }
}
