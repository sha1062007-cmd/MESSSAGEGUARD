package com.messageguard

object EmailTemplate {
    fun getHtmlTemplate(
        threatLevel: String,
        url: String,
        confidence: String,
        aiSummary: String,
        entropy: String,
        brandMimicry: String,
        tldRisk: String,
        timestamp: String,
        deviceName: String
    ): String {
        val bannerColor = if (threatLevel == "DANGER") "#D32F2F" else "#FBC02D"
        val bannerText = if (threatLevel == "DANGER") "🚨 DANGER: Phishing URL Blocked" else "⚠️ WARNING: Suspicious URL Detected"
        
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f7; }
                .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
                .header { background-color: #1a237e; color: white; padding: 20px; text-align: center; }
                .header h1 { margin: 0; font-size: 24px; letter-spacing: 1px; }
                .banner { background-color: $bannerColor; color: ${if (threatLevel == "DANGER") "white" else "black"}; padding: 15px; text-align: center; font-weight: bold; font-size: 18px; }
                .content { padding: 30px; }
                .warning-box { background-color: #fff9c4; border-left: 5px solid #fbc02d; padding: 15px; margin-bottom: 25px; border-radius: 4px; }
                .danger-box { background-color: #ffebee; border-left: 5px solid #d32f2f; padding: 15px; margin-bottom: 25px; border-radius: 4px; }
                .details-table { width: 100%; border-collapse: collapse; margin-bottom: 25px; }
                .details-table th, .details-table td { padding: 12px; border-bottom: 1px solid #eee; text-align: left; }
                .details-table th { color: #666; font-weight: 600; width: 40%; }
                .summary-box { background-color: #f8f9fa; border: 1px solid #e9ecef; padding: 20px; border-radius: 8px; font-style: italic; color: #495057; }
                .footer { background-color: #f8f9fa; color: #999; padding: 20px; text-align: center; font-size: 12px; }
                .bold-warning { color: #d32f2f; font-weight: bold; font-size: 20px; text-align: center; margin: 20px 0; border: 2px dashed #d32f2f; padding: 10px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>MessageGuard Security</h1>
                </div>
                <div class="banner">
                    $bannerText
                </div>
                <div class="content">
                    <div class="${if (threatLevel == "DANGER") "danger-box" else "warning-box"}">
                        <strong>Security Alert:</strong> High-confidence threat patterns detected.
                    </div>
                    
                    <table class="details-table">
                        <tr>
                            <th>Threat Level</th>
                            <td style="color: $bannerColor; font-weight: bold;">$threatLevel</td>
                        </tr>
                        <tr>
                            <th>Flagged URL</th>
                            <td style="word-break: break-all; color: #0d47a1;">$url</td>
                        </tr>
                        <tr>
                            <th>ML Confidence</th>
                            <td>$confidence</td>
                        </tr>
                        <tr>
                            <th>Entropy Score</th>
                            <td>$entropy</td>
                        </tr>
                        <tr>
                            <th>Brand Mimicry</th>
                            <td>$brandMimicry</td>
                        </tr>
                        <tr>
                            <th>TLD Risk</th>
                            <td>$tldRisk</td>
                        </tr>
                        <tr>
                            <th>Device Name</th>
                            <td>$deviceName</td>
                        </tr>
                        <tr>
                            <th>Detected At</th>
                            <td>$timestamp</td>
                        </tr>
                    </table>

                    <h3>Forensic AI Summary</h3>
                    <div class="summary-box">
                        "$aiSummary"
                    </div>

                    <div class="bold-warning">
                        ❌ DO NOT VISIT THIS URL ❌
                    </div>
                </div>
                <div class="footer">
                    Sent by MessageGuard Security Sentinel<br>
                    Autonomous Threat Intelligence Core
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
    }
}
