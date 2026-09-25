@echo off
REM Open Accessibility settings (user must enable MessageGuard manually)
adb shell am start -a android.settings.ACCESSIBILITY_SETTINGS

echo "Please find 'MessageGuard' in Accessibility and enable it."

echo "Pausing. Press any key after you enable accessibility..."
pause

REM Open Overlay permission settings for the package
adb shell am start -a android.settings.action.MANAGE_OVERLAY_PERMISSION -d package:com.messageguard

echo "Please allow 'Display over other apps' for MessageGuard."
echo "Press any key after granting overlay permission..."
pause

echo "Reopen the app on the device and toggle Protection ON."
echo "After toggling, run the dumpsys accessibility check below (this script will run it if you press any key)."

pause

echo "Running: adb shell dumpsys accessibility | findstr /I messageguard"
adb shell dumpsys accessibility | findstr /I messageguard

echo "If you see a bound service entry, the accessibility service is active. If not, re-open Accessibility settings and enable MessageGuard." 
pause
