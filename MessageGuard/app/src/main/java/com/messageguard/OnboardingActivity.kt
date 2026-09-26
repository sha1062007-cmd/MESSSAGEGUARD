package com.messageguard

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.net.Uri
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.recyclerview.widget.RecyclerView
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.button.MaterialButton

class OnboardingActivity : AppCompatActivity() {

    private lateinit var viewPager: ViewPager2
    private lateinit var tvIndicator: TextView
    private lateinit var btnAction: MaterialButton

    data class OnboardingSlide(
        val title: String,
        val subtitle: String,
        val iconResId: Int,
        val showSlideAction: Boolean = false,
        val slideActionLabel: String = "Grant Permission"
    )

    private val slides = listOf(
        OnboardingSlide(
            title = "MessageGuard Security Guard",
            subtitle = "Real-time automated security analytics. MessageGuard coordinates advanced machine learning heuristics, typosquat filters, and brand matching to intercept threat vectors in real time.",
            iconResId = android.R.drawable.ic_lock_lock
        ),
        OnboardingSlide(
            title = "Privacy-First Engine",
            subtitle = "All message verification logic and security logs are processed entirely on-device, never uploaded to any remote server or shared with third parties. Your data remains fully private.",
            iconResId = android.R.drawable.ic_lock_idle_lock
        ),
        OnboardingSlide(
            title = "Grant Accessibility Service",
            subtitle = "To automatically inspect incoming notification and message text across monitored apps (SMS, WhatsApp, Gmail, etc.) and draw immediate security alerts, MessageGuard requires the Accessibility Service permission.",
            iconResId = android.R.drawable.ic_menu_preferences,
            showSlideAction = true
        ),
        OnboardingSlide(
            title = "Grant Notification Access",
            subtitle = "To intercept file downloads from Gmail and WhatsApp before they reach your storage (pre-download sandbox), MessageGuard needs Notification Listener access. Tap below and enable MessageGuard in the list.",
            iconResId = android.R.drawable.stat_notify_sync,
            showSlideAction = true,
            slideActionLabel = "Enable Notification Access"
        )
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        // Read theme settings first to prevent flicker
        val prefs = getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putBoolean(Constants.KEY_THEME_DARK, true).apply()
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)

        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_onboarding)

        viewPager = findViewById(R.id.view_pager)
        tvIndicator = findViewById(R.id.tv_page_indicator)
        btnAction = findViewById(R.id.btn_action)

        viewPager.adapter = OnboardingPagerAdapter(slides) { slide ->
            try {
                val intent = when {
                    slide.slideActionLabel.contains("Notification", ignoreCase = true) ->
                        Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
                    else ->
                        Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
                }
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                startActivity(intent)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

        viewPager.registerOnPageChangeCallback(object : ViewPager2.OnPageChangeCallback() {
            override fun onPageSelected(position: Int) {
                tvIndicator.text = "${position + 1} / ${slides.size}"
                if (position == slides.size - 1) {
                    btnAction.text = "GET STARTED"
                    btnAction.setTextColor(resources.getColor(android.R.color.white, null))
                    btnAction.backgroundTintList = android.content.res.ColorStateList.valueOf(
                        android.graphics.Color.parseColor("#1A00E676") // Emerald glow
                    )
                    btnAction.strokeColor = android.content.res.ColorStateList.valueOf(
                        android.graphics.Color.parseColor("#3300E676")
                    )
                } else {
                    btnAction.text = "NEXT"
                    btnAction.setTextColor(android.graphics.Color.parseColor("#00E5FF")) // Cyan glow
                    btnAction.backgroundTintList = android.content.res.ColorStateList.valueOf(
                        android.graphics.Color.parseColor("#1A00E5FF")
                    )
                    btnAction.strokeColor = android.content.res.ColorStateList.valueOf(
                        android.graphics.Color.parseColor("#3300E5FF")
                    )
                }
            }
        })

        btnAction.setOnClickListener {
            val current = viewPager.currentItem
            if (current < slides.size - 1) {
                viewPager.currentItem = current + 1
            } else {
                // Set onboarding completed and launch main
                prefs.edit().putBoolean(Constants.KEY_ONBOARDING_COMPLETED, true).apply()
                startActivity(Intent(this, MainActivity::class.java))
                finish()
            }
        }
    }

    private class OnboardingPagerAdapter(
        private val slides: List<OnboardingSlide>,
        private val onActionClick: (OnboardingSlide) -> Unit
    ) : RecyclerView.Adapter<OnboardingPagerAdapter.PageViewHolder>() {

        class PageViewHolder(v: View) : RecyclerView.ViewHolder(v) {
            val ivIcon: ImageView = v.findViewById(R.id.iv_illustration)
            val tvTitle: TextView = v.findViewById(R.id.tv_title)
            val tvSubtitle: TextView = v.findViewById(R.id.tv_subtitle)
            val btnAction: MaterialButton = v.findViewById(R.id.btn_slide_action)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): PageViewHolder {
            val view = LayoutInflater.from(parent.context).inflate(R.layout.item_onboarding_page, parent, false)
            return PageViewHolder(view)
        }

        override fun onBindViewHolder(holder: PageViewHolder, position: Int) {
            val slide = slides[position]
            holder.ivIcon.setImageResource(slide.iconResId)
            holder.tvTitle.text = slide.title
            holder.tvSubtitle.text = slide.subtitle
            
            if (slide.showSlideAction) {
                holder.btnAction.visibility = View.VISIBLE
                holder.btnAction.text = slide.slideActionLabel
                holder.btnAction.setOnClickListener { onActionClick(slide) }
            } else {
                holder.btnAction.visibility = View.GONE
            }
        }

        override fun getItemCount() = slides.size
    }
}
