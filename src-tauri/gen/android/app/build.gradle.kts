plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

android {
    namespace = "io.github.clash_verge_rev.clash_verge_rev"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.clash_verge_rev.clash_verge_rev"
        minSdk = 24
        targetSdk = 35
        versionCode = 20508
        versionName = "2.5.8"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
        }
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

rust {
    rootDirRel = "../../../"
    targets = listOf("arm64", "arm", "x86_64", "x86")
    arches = listOf("arm64", "arm", "x86_64", "x86")
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    // Android TV Leanback support
    implementation("androidx.leanback:leanback:1.0.0")
    implementation(project(":tauri-android"))
}
