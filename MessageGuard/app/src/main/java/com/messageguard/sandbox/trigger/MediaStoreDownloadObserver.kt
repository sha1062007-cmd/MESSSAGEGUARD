package com.messageguard.sandbox.trigger

import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Log
import com.messageguard.sandbox.coordinator.SandboxClaimCoordinator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Primary trigger: ContentObserver scoped strictly to Downloads and WhatsApp Documents.
 * Excludes camera photos, screenshots, voice notes, thumbnails, and unfinished downloads (.tmp/.crdownload).
 */
class MediaStoreDownloadObserver(
    private val context: Context,
    handler: Handler = Handler(Looper.getMainLooper())
) : ContentObserver(handler) {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    companion object {
        private const val TAG = "SandboxDetection"

        @Volatile
        private var instance: MediaStoreDownloadObserver? = null

        fun register(context: Context): MediaStoreDownloadObserver {
            return instance ?: synchronized(this) {
                instance ?: MediaStoreDownloadObserver(context.applicationContext).also { observer ->
                    val resolver = context.applicationContext.contentResolver
                    // API 29+: scope strictly to the Downloads collection only.
                    // MediaStore.Files.getContentUri("external") is intentionally excluded — it fires
                    // on every camera photo, screenshot, and thumbnail, which are not download events.
                    // Pre-Q fallback: MediaStore.Downloads does not exist; use Files URI scoped to
                    // Download/ paths only (DownloadFilterPolicy enforces path filtering in onChange).
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        resolver.registerContentObserver(
                            MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                            true,
                            observer
                        )
                        Log.i(TAG, "MediaStoreDownloadObserver registered on MediaStore.Downloads URI (API 29+).")
                    } else {
                        resolver.registerContentObserver(
                            MediaStore.Files.getContentUri("external"),
                            true,
                            observer
                        )
                        Log.i(TAG, "MediaStoreDownloadObserver registered on MediaStore.Files URI (pre-API 29 fallback).")
                    }
                    instance = observer
                }
            }
        }

        fun unregister(context: Context) {
            synchronized(this) {
                instance?.let { observer ->
                    context.applicationContext.contentResolver.unregisterContentObserver(observer)
                    instance = null
                    Log.i(TAG, "MediaStoreDownloadObserver unregistered.")
                }
            }
        }
    }

    override fun onChange(selfChange: Boolean, uri: Uri?) {
        super.onChange(selfChange, uri)
        Log.d(TAG, "[ContentObserver] onChange fired: uri=$uri, selfChange=$selfChange")
        val targetUri = uri ?: if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            MediaStore.Downloads.EXTERNAL_CONTENT_URI
        } else {
            MediaStore.Files.getContentUri("external")
        }

        scope.launch {
            inspectAndClaimUriWithStabilization(targetUri)
        }
    }

    private suspend fun inspectAndClaimUriWithStabilization(uri: Uri) {
        try {
            val resolver = context.contentResolver
            val projection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                arrayOf(
                    MediaStore.MediaColumns._ID,
                    MediaStore.MediaColumns.DISPLAY_NAME,
                    MediaStore.MediaColumns.SIZE,
                    MediaStore.MediaColumns.RELATIVE_PATH,
                    MediaStore.MediaColumns.MIME_TYPE,
                    MediaStore.MediaColumns.DATE_ADDED,
                    MediaStore.MediaColumns.IS_PENDING
                )
            } else {
                arrayOf(
                    MediaStore.MediaColumns._ID,
                    MediaStore.MediaColumns.DISPLAY_NAME,
                    MediaStore.MediaColumns.SIZE,
                    MediaStore.MediaColumns.DATA,
                    MediaStore.MediaColumns.MIME_TYPE,
                    MediaStore.MediaColumns.DATE_ADDED
                )
            }

            // If uri is the collection root, query the most recently added item
            val isCollectionUri = uri.lastPathSegment?.toLongOrNull() == null
            val queryUri = if (isCollectionUri) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI
                } else {
                    MediaStore.Files.getContentUri("external")
                }
            } else {
                uri
            }

            val sortOrder = if (isCollectionUri) "${MediaStore.MediaColumns.DATE_ADDED} DESC" else null
            
            // 3-step bounded stabilization check with backoff (0ms, 150ms, 300ms)
            var lastSize = -1L
            var stableCount = 0
            var itemData: StableItemData? = null

            for (attempt in 0 until 3) {
                if (attempt > 0) {
                    kotlinx.coroutines.delay((attempt * 150).toLong())
                }

                resolver.query(queryUri, projection, null, null, sortOrder)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val isPending = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            val col = cursor.getColumnIndex(MediaStore.MediaColumns.IS_PENDING)
                            if (col != -1) cursor.getInt(col) == 1 else false
                        } else false

                        if (isPending) {
                            Log.d(TAG, "[ContentObserver] File is currently IS_PENDING (actively writing). Waiting for commit.")
                            return@use
                        }

                        val id = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns._ID))
                        val displayName = cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DISPLAY_NAME)) ?: "unnamed_file"
                        val size = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.SIZE))
                        val mime = cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.MIME_TYPE)) ?: "application/octet-stream"
                        val relativePath = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.RELATIVE_PATH)) ?: ""
                        } else {
                            cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DATA)) ?: ""
                        }

                        if (!DownloadFilterPolicy.isQualifyingDownload(displayName, size, relativePath)) {
                            return@use
                        }

                        val itemUri = if (isCollectionUri) Uri.withAppendedPath(queryUri, id.toString()) else uri
                        val data = StableItemData(id, displayName, size, mime, relativePath, itemUri)

                        if (size > 0L && size == lastSize) {
                            stableCount++
                            itemData = data
                        } else {
                            lastSize = size
                            stableCount = 1
                            itemData = data
                        }
                    }
                }

                // If size is non-zero and stable across checks, proceed immediately
                if (stableCount >= 2 && itemData != null && itemData.size > 0L) {
                    break
                }
            }

            val finalItem = itemData ?: return
            val uriKey = finalItem.itemUri.toString()

            val claimed = SandboxClaimCoordinator.tryClaim(uriKey, "ContentObserver")
            if (claimed) {
                val primed = SandboxClaimCoordinator.matchPrimedIntentForPath(finalItem.relativePath)
                if (primed != null) {
                    Log.i(TAG, "[ContentObserver] Correlated '${finalItem.displayName}' with primed intent from '${primed.sourcePackage}' (${primed.intentType}) based on path '${finalItem.relativePath}'!")
                }

                Log.i(TAG, "[ContentObserver] Claimed '${finalItem.displayName}' (size=${finalItem.size}B, URI=$uriKey). Triggering sandbox capture.")

                com.messageguard.sandbox.capture.SandboxCaptureEngine.captureFile(
                    context = context,
                    sourceUri = finalItem.itemUri,
                    originalFileName = finalItem.displayName,
                    originalMimeType = finalItem.mimeType,
                    sourcePackage = primed?.sourcePackage ?: "com.android.chrome",
                    captureSource = com.messageguard.sandbox.model.CaptureSource.MEDIASTORE_OBSERVER
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error inspecting MediaStore URI: $uri", e)
        }
    }

    private data class StableItemData(
        val id: Long,
        val displayName: String,
        val size: Long,
        val mimeType: String,
        val relativePath: String,
        val itemUri: Uri
    )
}
