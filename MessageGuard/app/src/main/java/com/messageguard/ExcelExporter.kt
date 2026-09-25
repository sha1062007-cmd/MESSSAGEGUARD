package com.messageguard

import android.content.Context
import org.apache.poi.ss.usermodel.FillPatternType
import org.apache.poi.ss.usermodel.IndexedColors
import org.apache.poi.xssf.usermodel.XSSFColor
import org.apache.poi.xssf.usermodel.XSSFWorkbook
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ExcelExporter {

    fun exportToStream(results: List<AnalysisResult>, outputStream: OutputStream) {
        val workbook = XSSFWorkbook()
        val sheet = workbook.createSheet("Scan Logs")

        // Create Fonts
        val headerFont = workbook.createFont().apply {
            bold = true
            color = IndexedColors.WHITE.getIndex()
        }

        // Header style
        val headerStyle = workbook.createCellStyle().apply {
            setFont(headerFont)
            fillForegroundColor = IndexedColors.GREY_80_PERCENT.getIndex()
            fillPattern = FillPatternType.SOLID_FOREGROUND
        }

        // Row styles for Danger & Warning
        // Apache POI IndexedColors or custom XSSFColor
        val dangerStyle = workbook.createCellStyle().apply {
            fillForegroundColor = IndexedColors.RED.getIndex() // We can use standard colors or soft shades if possible. Soft red index is not directly present, so we can use IndexedColors.CORAL or XSSFColor.
            // Let's use custom HSSF/XSSF colors if possible, but standard IndexedColors are safest to avoid class cast exceptions in some POI builds.
            // Let's use IndexedColors.ROSE.getIndex() for soft red, and IndexedColors.LIGHT_YELLOW.getIndex() for soft yellow.
            fillForegroundColor = IndexedColors.ROSE.getIndex()
            fillPattern = FillPatternType.SOLID_FOREGROUND
        }

        val warningStyle = workbook.createCellStyle().apply {
            fillForegroundColor = IndexedColors.LIGHT_YELLOW.getIndex()
            fillPattern = FillPatternType.SOLID_FOREGROUND
        }

        val safeStyle = workbook.createCellStyle().apply {
            fillForegroundColor = IndexedColors.LIGHT_GREEN.getIndex()
            fillPattern = FillPatternType.SOLID_FOREGROUND
        }

        // Create headers
        val headers = listOf(
            "ID", "Timestamp", "App Source", "Sender", "Subject", "Verdict",
            "Risk Score", "Category", "Trust", "Summary", "Red Flags", "Action",
            "ML Score", "AI Score", "Snippet", "Flagged URLs"
        )

        val headerRow = sheet.createRow(0)
        headers.forEachIndexed { index, header ->
            val cell = headerRow.createCell(index)
            cell.setCellValue(header)
            cell.setCellStyle(headerStyle)
        }

        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())

        // Populate data
        results.forEachIndexed { rowIndex, result ->
            val row = sheet.createRow(rowIndex + 1)
            
            // Choose cell style based on verdict
            val rowStyle = when (result.verdict) {
                Verdict.DANGER -> dangerStyle
                Verdict.WARNING -> warningStyle
                Verdict.SAFE -> safeStyle
                Verdict.UNCERTAIN -> safeStyle
            }

            val cells = listOf(
                result.id.toString(),
                dateFormat.format(Date(result.timestamp)),
                result.appSource,
                result.sender,
                result.subject,
                result.verdict.name,
                result.riskScore.toString(),
                result.category,
                result.senderTrust,
                result.summary,
                result.flags.joinToString("; "),
                result.action,
                result.mlScore.toString(),
                result.aiScore.toString(),
                result.messageSnippet,
                result.flaggedUrls
            )

            cells.forEachIndexed { colIndex, value ->
                val cell = row.createCell(colIndex)
                cell.setCellValue(value)
                if (result.verdict != Verdict.SAFE) {
                    cell.setCellStyle(rowStyle)
                }
            }
        }

        // Avoid autoSizeColumn on Android: it depends on java.awt classes that are not available.
        // Use reasonable fixed widths instead.
        for (i in headers.indices) {
            val width = when (i) {
                0, 6, 12, 13 -> 14
                1 -> 20
                2, 3, 4, 5, 7, 8, 9, 11 -> 18
                10, 14, 15 -> 32
                else -> 20
            }
            sheet.setColumnWidth(i, width * 256)
        }

        workbook.write(outputStream)
        workbook.close()
    }
}
