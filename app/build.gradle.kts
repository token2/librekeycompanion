plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.token2.lkcompanion"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.token2.lkcompanion"
        minSdk = 26          // API 26: USB Host + modern NFC reader mode
        targetSdk = 36      // API 35 required by Google Play; enables edge-to-edge
        versionCode = 40
        versionName = "1.0.4"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("com.google.android.material:material:1.12.0")
    // QR scanning — CameraX (AndroidX, continuous autofocus, rotation-correct
    // preview) + the ZXing *core* decoder. Both GApps-free. The former
    // zxing-android-embedded CaptureActivity was replaced because it launches a
    // separate landscape-locked activity on the legacy Camera1 API (issue #23:
    // 90° rotated preview, flaky autofocus, and the Add dialog being torn down
    // while the scanner was in front).
    implementation("androidx.camera:camera-core:1.3.4")
    implementation("androidx.camera:camera-camera2:1.3.4")
    implementation("androidx.camera:camera-lifecycle:1.3.4")
    implementation("androidx.camera:camera-view:1.3.4")
    implementation("com.google.zxing:core:3.5.3")
    testImplementation("junit:junit:4.13.2")
}
