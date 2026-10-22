import java.util.Properties

plugins {
    id("com.android.application")
}

val signingProps = Properties()
val signingPropsFile = rootProject.file("signing.properties")
if (signingPropsFile.exists()) signingProps.load(signingPropsFile.inputStream())

android {
    namespace = "df.root"
    compileSdk = 37
    buildToolsVersion = "36.1.0"
    ndkVersion = "28.2.13676358"

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "df.root"
        minSdk = 32
        targetSdk = 37
        versionCode = 40601
        versionName = "4.6-op9rt.1"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    // PORT: signing.properties is optional; upstream dies with
    // "getProperty(...) must not be null" when the file is absent.
    val signingKeys = listOf("KEYSTORE_FILE", "KEYSTORE_PASSWORD", "KEY_ALIAS", "KEY_PASSWORD")
    val haveReleaseSigning = signingKeys.all { !signingProps.getProperty(it).isNullOrBlank() }
    if (gradle.startParameter.taskNames.any { it.contains("release", ignoreCase = true) }) {
        check(haveReleaseSigning) { "Release signing is required. See docs/BUILDING.md." }
    }
    signingConfigs {
        if (haveReleaseSigning) create("release") {
            storeFile = file(signingProps.getProperty("KEYSTORE_FILE"))
            storePassword = signingProps.getProperty("KEYSTORE_PASSWORD")
            keyAlias = signingProps.getProperty("KEY_ALIAS")
            keyPassword = signingProps.getProperty("KEY_PASSWORD")
        }
    }

    buildTypes {
        debug {
            isDebuggable = true
            signingConfig = signingConfigs.getByName("debug")
        }
        release {
            isDebuggable = false
            if (haveReleaseSigning) signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    lint {
        checkReleaseBuilds = false
    }

    externalNativeBuild {
        cmake {
            path("src/main/jni/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

androidComponents {
    onVariants { variant ->
        variant.outputs.forEach { output ->
            output.outputFileName.set(output.versionName.map { vn -> "DFRoot-OnePlus9RT_${vn}.apk" })
        }
    }
}

dependencies {
}

val verifyPortModules by tasks.registering {
    doLast {
        listOf("src/main/assets/kernelsu.ko", "src/main/jni/ko/dfroot-android13-5.4.ko").forEach {
            check(file(it).isFile) { "Missing $it. Run bash scripts/build-modules.sh first." }
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyPortModules) }
