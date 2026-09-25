# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.

# Keep data classes
-keep class com.messageguard.** { *; }

# Keep Room entities
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao interface * { *; }

# Keep Retrofit interfaces
-keep interface * extends retrofit2.Callback { *; }
-keep class retrofit2.** { *; }
-keepattributes Signature
-keepattributes Exceptions

# Keep Gson models
-keepattributes *Annotation*
-keep class com.google.gson.** { *; }
-keep class sun.misc.Unsafe { *; }

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**

# Apache POI dependencies warnings suppression (R8 / Proguard)
-dontwarn org.apache.poi.**
-dontwarn org.apache.xmlbeans.**
-dontwarn javax.xml.stream.**
-dontwarn net.sf.saxon.**
-dontwarn org.apache.batik.**
-dontwarn org.osgi.framework.**
-dontwarn org.apache.logging.log4j.**
-dontwarn java.awt.**
-dontwarn javax.imageio.**

# Preserve ONNX Runtime Native Linkage & Direct ByteBuffers
-keep class ai.onnxruntime.** { *; }
-dontwarn ai.onnxruntime.**
-keep class java.nio.DirectByteBuffer { *; }

