package com.messageguard

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object StorageHelper {

    fun exportDatabaseToExcel(context: Context, results: List<AnalysisResult>): String? {
        if (results.isEmpty()) return null

        val sdf = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
        val fileName = "MessageGuard_Export_${sdf.format(Date())}.xlsx"

        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // Scoped Storage (Android 10+)
                val resolver = context.contentResolver
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, "Download/MessageGuard")
                    put(MediaStore.MediaColumns.IS_PENDING, 1)
                }

                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                if (uri != null) {
                    resolver.openOutputStream(uri)?.use { outputStream ->
                        ExcelExporter.exportToStream(results, outputStream)
                    }
                    resolver.update(uri, ContentValues().apply {
                        put(MediaStore.MediaColumns.IS_PENDING, 0)
                    }, null, null)
                    "Downloads/MessageGuard/$fileName"
                } else {
                    fallbackExport(context, fileName, results)
                }
            } else {
                // Legacy storage (Android 9 or below)
                val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                val mgDir = File(downloadsDir, "MessageGuard")
                if (!mgDir.exists()) {
                    mgDir.mkdirs()
                }
                val file = File(mgDir, fileName)
                FileOutputStream(file).use { outputStream ->
                    ExcelExporter.exportToStream(results, outputStream)
                }
                file.absolutePath
            }
        } catch (e: Exception) {
            e.printStackTrace()
            fallbackExport(context, fileName, results)
        }
    }

    private fun fallbackExport(context: Context, fileName: String, results: List<AnalysisResult>): String? {
        return try {
            val exportDir = File(context.getExternalFilesDir(null), "MessageGuard").apply { if (!exists()) mkdirs() }
            val file = File(exportDir, fileName)
            FileOutputStream(file).use { outputStream -> ExcelExporter.exportToStream(results, outputStream) }
            file.absolutePath
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}

