@echo off
REM Clear current logs and start filtered log capture to a file.
adb logcat -c

echo "Starting filtered logcat. Will capture ThreatVisionLog and SpamAnalyzer tags. Press Ctrl+C to stop and save to file."
adb logcat -v time ThreatVisionLog:V SpamAnalyzer:V *:S > messageguard_log.txt

echo "Log saved to messageguard_log.txt in workspace root when you stop the capture." 
