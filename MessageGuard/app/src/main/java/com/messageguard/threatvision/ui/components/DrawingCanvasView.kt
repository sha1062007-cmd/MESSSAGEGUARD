package com.messageguard.threatvision.ui.components

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import kotlin.math.hypot

/**
 * Premium, fluid freehand drawing canvas for Threat Vision "Circle to Scan".
 * Implements Bezier path smoothing, loop-closure assistance, minimum length filtering
 * to prevent accidental triggers, and double-pass neon glow aesthetics.
 */
class DrawingCanvasView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val path = Path()
    private var startX = 0f
    private var startY = 0f
    private var lastX = 0f
    private var lastY = 0f
    private var totalLength = 0f
    private var isCooldown = false

    private val touchTolerance = 4f

    // Outer soft glow paint (Vibrant Emerald Glow)
    private val glowPaint = Paint().apply {
        color = Color.parseColor("#4000E676") // Soft vibrant emerald glow
        isAntiAlias = true
        strokeWidth = 24f
        style = Paint.Style.STROKE
        strokeJoin = Paint.Join.ROUND
        strokeCap = Paint.Cap.ROUND
    }

    // Inner sharp core paint (Premium Electric Green)
    private val corePaint = Paint().apply {
        color = Color.parseColor("#00E676") // Premium electric green core
        isAntiAlias = true
        strokeWidth = 8f
        style = Paint.Style.STROKE
        strokeJoin = Paint.Join.ROUND
        strokeCap = Paint.Cap.ROUND
    }

    // Semi-translucent region fill paint
    private val fillPaint = Paint().apply {
        color = Color.parseColor("#1A00E676") // Subtle translucent emerald fill
        style = Paint.Style.FILL
    }

    // Top instruction banner & cancel pill paints
    private val bannerBgPaint = Paint().apply {
        color = Color.parseColor("#CC0B0E14") // Sleek dark glassmorphism
        style = Paint.Style.FILL
        isAntiAlias = true
    }

    private val bannerBorderPaint = Paint().apply {
        color = Color.parseColor("#3300E676")
        style = Paint.Style.STROKE
        strokeWidth = 2f
        isAntiAlias = true
    }

    private val textTitlePaint = Paint().apply {
        color = Color.parseColor("#00E676")
        textSize = 34f
        isFakeBoldText = true
        textAlign = Paint.Align.CENTER
        isAntiAlias = true
    }

    private val textSubtitlePaint = Paint().apply {
        color = Color.parseColor("#D0D0D0")
        textSize = 24f
        textAlign = Paint.Align.CENTER
        isAntiAlias = true
    }

    private val cancelPillPaint = Paint().apply {
        color = Color.parseColor("#80FF5252")
        style = Paint.Style.STROKE
        strokeWidth = 2f
        isAntiAlias = true
    }

    private val cancelTextPaint = Paint().apply {
        color = Color.parseColor("#FF5252")
        textSize = 24f
        isFakeBoldText = true
        textAlign = Paint.Align.CENTER
        isAntiAlias = true
    }

    private val cancelRect = RectF()

    var onSelectionComplete: ((RectF, Path) -> Unit)? = null
    var onCancelRequested: (() -> Unit)? = null

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        
        // 0. Top HUD Instruction Card
        val cx = width / 2f
        val bannerTop = 80f
        val bannerBottom = 200f
        val bannerRect = RectF(cx - 320f, bannerTop, cx + 320f, bannerBottom)
        canvas.drawRoundRect(bannerRect, 28f, 28f, bannerBgPaint)
        canvas.drawRoundRect(bannerRect, 28f, 28f, bannerBorderPaint)

        canvas.drawText("✦ CIRCLE CONTENT TO SCAN ✦", cx, bannerTop + 50f, textTitlePaint)
        canvas.drawText("Draw around any message, email, or link to analyze", cx, bannerTop + 90f, textSubtitlePaint)

        // Cancel pill
        cancelRect.set(cx - 70f, bannerTop + 105f, cx + 70f, bannerTop + 145f)
        canvas.drawRoundRect(cancelRect, 20f, 20f, bannerBgPaint)
        canvas.drawRoundRect(cancelRect, 20f, 20f, cancelPillPaint)
        canvas.drawText("✕ CANCEL", cx, bannerTop + 133f, cancelTextPaint)

        // 1. Draw area highlight fill
        canvas.drawPath(path, fillPaint)
        // 2. Draw outer neon glow stroke
        canvas.drawPath(path, glowPaint)
        // 3. Draw sharp inner core stroke
        canvas.drawPath(path, corePaint)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (isCooldown) {
            android.util.Log.d("ThreatVisionLog", "DrawingCanvasView: touch ignored due to cooldown.")
            return false
        }

        val x = event.x
        val y = event.y

        when (event.action) {
            MotionEvent.ACTION_DOWN -> {
                android.util.Log.d("ThreatVisionLog", "DrawingCanvasView: ACTION_DOWN at ($x, $y)")

                // Check cancel button hit test
                if (cancelRect.contains(x, y)) {
                    android.util.Log.d("ThreatVisionLog", "DrawingCanvasView: Cancel button tapped.")
                    onCancelRequested?.invoke()
                    return true
                }

                path.reset()
                path.moveTo(x, y)
                startX = x
                startY = y
                lastX = x
                lastY = y
                totalLength = 0f
                invalidate()
                return true
            }
            MotionEvent.ACTION_MOVE -> {
                val dx = Math.abs(x - lastX)
                val dy = Math.abs(y - lastY)
                if (dx >= touchTolerance || dy >= touchTolerance) {
                    // Quadratic Bezier smoothing to midpoint of movement segment
                    path.quadTo(lastX, lastY, (x + lastX) / 2, (y + lastY) / 2)
                    totalLength += hypot((x - lastX).toDouble(), (y - lastY).toDouble()).toFloat()
                    lastX = x
                    lastY = y
                    invalidate()
                }
                return true
            }
            MotionEvent.ACTION_UP -> {
                android.util.Log.d("ThreatVisionLog", "DrawingCanvasView: ACTION_UP at ($x, $y). Total path length: $totalLength px")

                // 1. Filter out stray/accidental touches (e.g. tiny tap or very short drag)
                val bounds = RectF()
                path.computeBounds(bounds, true)
                val boundsArea = bounds.width() * bounds.height()

                if (totalLength < 30f || bounds.width() < 15f || bounds.height() < 15f) {
                    android.util.Log.d("ThreatVisionLog", "DrawingCanvasView: path discarded (accidental tap or stroke too short).")
                    clearCanvas()
                    return true
                }

                // 2. Check Loop Closure: If ends are far apart, auto-close the path back to the start point
                val distToStart = hypot((x - startX).toDouble(), (y - startY).toDouble())
                if (distToStart > 180f) {
                    android.util.Log.d("ThreatVisionLog", "DrawingCanvasView: auto-closing loop back to start ($distToStart px gap).")
                    path.lineTo(startX, startY)
                } else {
                    path.close()
                }
                invalidate()

                // 3. Prevent immediate re-triggers (debounce)
                isCooldown = true

                // Compute final cropped region bounding box
                val finalBounds = RectF()
                path.computeBounds(finalBounds, true)

                onSelectionComplete?.invoke(finalBounds, Path(path))
                return true
            }
            MotionEvent.ACTION_CANCEL -> {
                android.util.Log.d("ThreatVisionLog", "DrawingCanvasView: ACTION_CANCEL")
                clearCanvas()
                return true
            }
        }
        return super.onTouchEvent(event)
    }

    fun clearCanvas() {
        path.reset()
        totalLength = 0f
        isCooldown = false
        invalidate()
    }
}
