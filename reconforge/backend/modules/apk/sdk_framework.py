"""SDK/framework detection and native library analysis modules."""
from __future__ import annotations

import logging
import os
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable

from backend.config import settings
from backend.modules.base import (
    AssetType,
    BaseModule,
    FindingSeverity,
    ModuleAsset,
    ModuleFinding,
    ModuleResult,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Framework indicators: mapping framework -> list of (path_pattern, is_prefix)
# ---------------------------------------------------------------------------
_FRAMEWORK_INDICATORS: dict[str, list[tuple[str, bool]]] = {
    "Flutter": [
        ("lib/arm64-v8a/libflutter.so", False),
        ("lib/armeabi-v7a/libflutter.so", False),
        ("lib/x86_64/libflutter.so", False),
        ("lib/x86/libflutter.so", False),
        ("assets/flutter_assets/", True),
    ],
    "React Native": [
        ("assets/index.android.bundle", False),
        ("lib/arm64-v8a/libreactnativejni.so", False),
        ("lib/armeabi-v7a/libreactnativejni.so", False),
        ("lib/x86_64/libreactnativejni.so", False),
        ("lib/x86/libreactnativejni.so", False),
        ("lib/arm64-v8a/libjsc.so", False),
        ("lib/armeabi-v7a/libjsc.so", False),
    ],
    "Xamarin": [
        ("assemblies/", True),
        ("lib/arm64-v8a/libmonodroid.so", False),
        ("lib/armeabi-v7a/libmonodroid.so", False),
        ("lib/arm64-v8a/libxamarin-app.so", False),
        ("lib/armeabi-v7a/libxamarin-app.so", False),
    ],
    "Unity": [
        ("lib/arm64-v8a/libunity.so", False),
        ("lib/armeabi-v7a/libunity.so", False),
        ("lib/arm64-v8a/libil2cpp.so", False),
        ("lib/armeabi-v7a/libil2cpp.so", False),
        ("assets/bin/Data/", True),
    ],
    "Cordova": [
        ("assets/www/cordova.js", False),
        ("assets/www/index.html", False),
        ("assets/www/cordova_plugins.js", False),
    ],
}


# ---------------------------------------------------------------------------
# SDK data-collection metadata
# ---------------------------------------------------------------------------
_SDK_PACKAGES: dict[str, dict[str, str]] = {
    "com.google.firebase": {
        "name": "Firebase",
        "collects": "Analytics events, crash reports, device info, app instance IDs, "
                    "user properties, push tokens, A/B test assignments, remote config state",
    },
    "com.google.firebase.analytics": {
        "name": "Firebase Analytics",
        "collects": "Screen views, user interactions, device model, OS version, app version, "
                    "geography, session duration, user demographics (if enabled)",
    },
    "com.google.firebase.crashlytics": {
        "name": "Firebase Crashlytics",
        "collects": "Crash stack traces, device state at crash time, OS version, RAM/disk, "
                    "orientation, rooted/jailbroken status, custom keys/logs set by developer",
    },
    "com.google.firebase.messaging": {
        "name": "Firebase Cloud Messaging",
        "collects": "Push notification tokens, message delivery/open events, device registration info",
    },
    "com.google.firebase.perf": {
        "name": "Firebase Performance Monitoring",
        "collects": "Network request latency, app startup time, screen rendering times, "
                    "device hardware info, custom traces",
    },
    "com.google.android.gms.ads": {
        "name": "Google AdMob / Ads SDK",
        "collects": "Advertising ID, device info, IP address, ad interaction events, "
                    "app usage data, location (if permitted)",
    },
    "com.facebook.sdk": {
        "name": "Facebook SDK",
        "collects": "App events, device info, advertiser ID, Facebook login tokens, "
                    "deep link data, purchase events, custom events",
    },
    "com.facebook.appevents": {
        "name": "Facebook App Events",
        "collects": "In-app events, purchase data, app install attribution, device metadata",
    },
    "com.crashlytics": {
        "name": "Crashlytics (legacy)",
        "collects": "Crash reports, device info, OS state, custom keys/logs",
    },
    "com.adjust.sdk": {
        "name": "Adjust",
        "collects": "Install attribution, in-app events, device IDs (GAID/IDFA), IP address, "
                    "referrer data, session counts, revenue events",
    },
    "com.appsflyer": {
        "name": "AppsFlyer",
        "collects": "Install attribution, in-app events, device IDs, IP address, "
                    "carrier info, referrer, revenue, deep link data",
    },
    "com.amplitude": {
        "name": "Amplitude",
        "collects": "User events, device info, session data, user properties, "
                    "revenue events, IP-based geolocation",
    },
    "com.mixpanel": {
        "name": "Mixpanel",
        "collects": "User events, device info, user profiles, IP address, "
                    "push tokens, A/B test assignments, session replay (if enabled)",
    },
    "com.braze": {
        "name": "Braze (Appboy)",
        "collects": "User events, user profile attributes, device info, push tokens, "
                    "in-app message interactions, location (if permitted), purchase data",
    },
    "io.sentry": {
        "name": "Sentry",
        "collects": "Error/crash reports, stack traces, breadcrumbs, device context, "
                    "OS info, user context (if set), HTTP request/response data",
    },
    "com.segment": {
        "name": "Segment",
        "collects": "Analytics events forwarded to downstream integrations, user identity, "
                    "device info, screen views, custom track calls",
    },
    "com.segment.analytics": {
        "name": "Segment Analytics",
        "collects": "Track/identify/screen calls, device context, session info",
    },
    "com.google.android.gms.analytics": {
        "name": "Google Analytics (legacy)",
        "collects": "Screen views, events, user timing, exceptions, device info, campaigns",
    },
    "com.newrelic": {
        "name": "New Relic Mobile",
        "collects": "Crash data, HTTP transactions, interaction traces, device metrics, "
                    "custom events, handled exceptions",
    },
    "com.bugsnag": {
        "name": "Bugsnag",
        "collects": "Error reports, breadcrumbs, device info, app state, user info (if set)",
    },
    "com.instabug": {
        "name": "Instabug",
        "collects": "Bug reports, crash data, user feedback, session replay, network logs, "
                    "device info, console logs",
    },
    "com.flurry": {
        "name": "Flurry Analytics",
        "collects": "App events, sessions, device info, demographics, crash reports",
    },
    "io.branch": {
        "name": "Branch.io",
        "collects": "Deep link data, install attribution, device fingerprint, "
                    "IP address, user agent, referrer",
    },
    "com.clevertap": {
        "name": "CleverTap",
        "collects": "User events, user profiles, push tokens, device info, "
                    "geofence data (if enabled), in-app interactions",
    },
    "com.onesignal": {
        "name": "OneSignal",
        "collects": "Push tokens, device info, notification interactions, "
                    "tags/segments, IP-based location, session data",
    },
    "com.kochava": {
        "name": "Kochava",
        "collects": "Install attribution, in-app events, device IDs, IP address, "
                    "carrier info, purchase/revenue data",
    },
}


# ---------------------------------------------------------------------------
# Exodus-style tracker list (100+ entries): package_prefix -> (name, data)
# ---------------------------------------------------------------------------
_TRACKERS: dict[str, tuple[str, str]] = {
    "com.google.android.gms.ads": ("Google AdMob", "Advertising ID, device info, ad interactions, location"),
    "com.google.android.gms.analytics": ("Google Analytics", "Screen views, events, device info, sessions"),
    "com.google.firebase.analytics": ("Firebase Analytics", "Events, user properties, device info, sessions"),
    "com.google.firebase.crashlytics": ("Firebase Crashlytics", "Crash reports, device state, stack traces"),
    "com.google.firebase.perf": ("Firebase Performance", "Network latency, app startup, rendering times"),
    "com.google.firebase.messaging": ("Firebase Cloud Messaging", "Push tokens, message delivery events"),
    "com.google.firebase.iid": ("Firebase Instance ID", "App instance IDs, push registration"),
    "com.google.firebase.remoteconfig": ("Firebase Remote Config", "Config values, experiment assignments"),
    "com.google.android.gms.measurement": ("Google Analytics for Firebase", "Events, conversions, audiences"),
    "com.google.android.gms.tagmanager": ("Google Tag Manager", "Tag firing events, container config"),
    "com.facebook.ads": ("Facebook Ads", "Ad impressions, clicks, device info, GAID"),
    "com.facebook.appevents": ("Facebook App Events", "In-app events, purchases, installs"),
    "com.facebook.marketing": ("Facebook Marketing", "Attribution data, ad performance, audience info"),
    "com.facebook.applinks": ("Facebook App Links", "Deep link routing, referrer data"),
    "com.facebook.login": ("Facebook Login", "Authentication tokens, user profile data"),
    "com.facebook.share": ("Facebook Share", "Shared content metadata, share events"),
    "com.adjust.sdk": ("Adjust", "Attribution, events, device IDs, revenue"),
    "com.appsflyer": ("AppsFlyer", "Attribution, events, device IDs, revenue, deep links"),
    "com.amplitude": ("Amplitude", "Events, device info, sessions, user properties"),
    "com.mixpanel": ("Mixpanel", "Events, user profiles, device info, sessions"),
    "com.segment": ("Segment", "Analytics events, identity, device context"),
    "com.segment.analytics": ("Segment Analytics", "Track/identify/screen calls, device info"),
    "com.braze": ("Braze", "Events, user attributes, push tokens, in-app messages"),
    "com.appboy": ("Braze (Appboy legacy)", "Events, user attributes, push tokens"),
    "io.sentry": ("Sentry", "Errors, crash reports, breadcrumbs, device context"),
    "com.bugsnag": ("Bugsnag", "Error reports, device info, breadcrumbs"),
    "com.crashlytics": ("Crashlytics (legacy)", "Crash reports, device info, custom keys"),
    "com.newrelic": ("New Relic", "Crashes, HTTP transactions, interaction traces, device metrics"),
    "com.flurry": ("Flurry", "Events, sessions, device info, demographics, crashes"),
    "com.localytics": ("Localytics", "Events, sessions, user profiles, push tokens, campaigns"),
    "com.onesignal": ("OneSignal", "Push tokens, device info, notifications, tags"),
    "com.pushwoosh": ("Pushwoosh", "Push tokens, device info, notification events"),
    "com.urbanairship": ("Airship (Urban Airship)", "Push tokens, events, user attributes, location"),
    "com.leanplum": ("Leanplum", "Events, user attributes, A/B tests, push tokens, in-app messages"),
    "com.clevertap": ("CleverTap", "Events, user profiles, push tokens, geofence data"),
    "io.branch": ("Branch.io", "Deep link attribution, device fingerprint, install referrer"),
    "com.kochava": ("Kochava", "Attribution, events, device IDs, revenue"),
    "com.tenjin": ("Tenjin", "Attribution, ad revenue, events, device IDs"),
    "com.singular.sdk": ("Singular", "Attribution, events, ad revenue, device IDs, fraud detection"),
    "com.chartboost": ("Chartboost", "Ad impressions, clicks, device info, sessions"),
    "com.unity3d.ads": ("Unity Ads", "Ad impressions, clicks, device info, player ID"),
    "com.vungle": ("Vungle (Liftoff)", "Ad impressions, clicks, device info, GAID"),
    "com.ironsource": ("ironSource", "Ad mediation events, device info, GAID, impressions"),
    "com.applovin": ("AppLovin", "Ad impressions, clicks, device info, GAID, user segments"),
    "com.mopub": ("MoPub (legacy)", "Ad events, device info, GAID, location"),
    "com.inmobi": ("InMobi", "Ad events, device info, GAID, location"),
    "com.startapp": ("StartApp (Start.io)", "Ad events, device info, GAID, location, sensor data"),
    "com.tapjoy": ("Tapjoy", "Ad events, device info, GAID, reward events"),
    "com.adcolony": ("AdColony (Digital Turbine)", "Ad impressions, device info, GAID"),
    "com.fyber": ("Fyber (Digital Turbine)", "Ad mediation events, device info, GAID"),
    "com.ogury": ("Ogury", "Ad events, device info, consent data, app usage"),
    "com.mintegral": ("Mintegral", "Ad events, device info, GAID, network info"),
    "com.bytedance.sdk": ("ByteDance/Pangle Ads", "Ad events, device info, GAID, network info"),
    "com.yandex.metrica": ("Yandex AppMetrica", "Events, sessions, device info, crashes, revenue"),
    "com.yandex.mobile.ads": ("Yandex Mobile Ads", "Ad impressions, clicks, device info"),
    "com.huawei.hms.ads": ("Huawei Ads", "Ad events, device info, OAID"),
    "com.huawei.hms.analytics": ("Huawei Analytics", "Events, sessions, device info, user attributes"),
    "com.microsoft.appcenter": ("Microsoft App Center", "Crashes, analytics events, device info, sessions"),
    "com.microsoft.appcenter.crashes": ("App Center Crashes", "Crash reports, device state, stack traces"),
    "com.microsoft.appcenter.analytics": ("App Center Analytics", "Events, device info, sessions"),
    "com.instabug": ("Instabug", "Bug reports, crashes, feedback, network logs, replays"),
    "com.batch": ("Batch", "Push tokens, device info, in-app events, user attributes"),
    "com.helpshift": ("Helpshift", "Support tickets, device info, user metadata, chat logs"),
    "com.zendesk": ("Zendesk", "Support tickets, device info, user identity"),
    "io.intercom": ("Intercom", "User identity, events, conversations, device info"),
    "com.apptentive": ("Apptentive", "Surveys, ratings prompts, device info, events"),
    "com.uservoice": ("UserVoice", "Feedback, tickets, user identity"),
    "ly.count.android": ("Countly", "Events, sessions, device info, crashes, user profiles"),
    "com.matomo": ("Matomo", "Page views, events, device info, sessions"),
    "org.piwik": ("Piwik (Matomo legacy)", "Page views, events, device info"),
    "com.heap": ("Heap", "Auto-captured events, sessions, device info, user interactions"),
    "com.fullstory": ("FullStory", "Session replay, events, device info, user interactions"),
    "io.embrace": ("Embrace", "Crashes, ANRs, network calls, sessions, device info"),
    "com.datadog": ("Datadog", "RUM events, traces, logs, device info, network requests"),
    "com.dynatrace": ("Dynatrace", "User actions, crashes, network requests, device info"),
    "com.smartlook": ("Smartlook", "Session replay, events, heatmaps, device info"),
    "com.uxcam": ("UXCam", "Session replay, heatmaps, events, device info, gestures"),
    "io.radar": ("Radar", "Geofences, trip tracking, location data, device info"),
    "com.gimbal": ("Gimbal", "Geofence events, beacon proximity, location, device info"),
    "com.mapbox.mapboxsdk": ("Mapbox", "Map tile requests, location data, device info, telemetry"),
    "com.comscore": ("comScore", "Content viewing, audience measurement, device info"),
    "com.nielsen": ("Nielsen", "Content measurement, audience data, device info"),
    "com.moat": ("Moat (Oracle)", "Ad viewability, attention metrics, device info"),
    "com.doubleverify": ("DoubleVerify", "Ad verification, viewability, fraud detection"),
    "com.integral.ads.science": ("IAS (Integral Ad Science)", "Ad viewability, brand safety"),
    "com.scorecard.research": ("Scorecard Research (comScore)", "Audience measurement, web/app usage"),
    "com.quantcast": ("Quantcast", "Audience measurement, device info, ad targeting"),
    "com.lotame": ("Lotame", "Data collection for audience segments, device info"),
    "com.permutive": ("Permutive", "First-party data collection, audience segments"),
    "com.agora": ("Agora", "Audio/video call metadata, network quality, device info"),
    "io.agora": ("Agora", "Audio/video call metadata, network quality, device info"),
    "com.twilio": ("Twilio", "Communication events, device info, call/message metadata"),
    "com.stripe.android": ("Stripe", "Payment card data (PCI scoped), device fingerprint, transaction events"),
    "com.paypal": ("PayPal SDK", "Payment events, device info, transaction data"),
    "com.shopify": ("Shopify Mobile Buy", "Product views, checkout events, device info"),
    "com.revenuecat": ("RevenueCat", "Subscription events, purchase data, device info, user ID"),
    "com.qonversion": ("Qonversion", "Subscription events, revenue data, device info"),
    "com.airbnb.lottie": ("Lottie", "No direct data collection — animation rendering only"),
    "com.squareup.okhttp": ("OkHttp (Square)", "No direct tracking — HTTP client library"),
    "com.squareup.retrofit": ("Retrofit (Square)", "No direct tracking — HTTP client library"),
    "io.realm": ("Realm", "No direct tracking — local database"),
    "com.google.mlkit": ("Google ML Kit", "On-device ML inference metadata, crash reports"),
    "com.spotify.sdk": ("Spotify SDK", "Auth tokens, playback events, device info"),
    "com.twitter.sdk": ("Twitter (X) SDK", "Auth tokens, tweet events, device info"),
    "com.snapchat.kit": ("Snap Kit", "Auth tokens, bitmoji data, creative kit events"),
    "com.tiktok.open.sdk": ("TikTok SDK", "Auth tokens, share events, device info"),
    "com.kakao.sdk": ("Kakao SDK", "Auth tokens, share events, user profile"),
    "com.linecorp": ("LINE SDK", "Auth tokens, messaging events, user profile"),
    "jp.line.android": ("LINE SDK (JP)", "Auth tokens, messaging events, user profile"),
}


# ---------------------------------------------------------------------------
# Known vulnerable native libraries (name pattern -> CVE/issue description)
# ---------------------------------------------------------------------------
_VULNERABLE_LIBS: dict[str, str] = {
    "libssl.so": "Bundled OpenSSL — check version for Heartbleed (CVE-2014-0160) and other CVEs",
    "libcrypto.so": "Bundled OpenSSL crypto — check version for known vulnerabilities",
    "libsqlite.so": "Bundled SQLite — check for CVE-2019-8457, CVE-2020-15358 and others",
    "libcurl.so": "Bundled libcurl — many historical CVEs, check version string",
    "libwebp.so": "Bundled libwebp — CVE-2023-4863 (critical heap buffer overflow)",
    "libpng.so": "Bundled libpng — check for CVE-2019-7317 and others",
    "libjpeg.so": "Bundled libjpeg — check for known buffer overflow CVEs",
    "libxml2.so": "Bundled libxml2 — many historical parsing CVEs",
    "libexpat.so": "Bundled Expat XML parser — check for CVE-2022-25313 and others",
    "libfreetype.so": "Bundled FreeType — check for CVE-2020-15999 and others",
}


class FrameworkDetectModule(BaseModule):
    """Detect the app framework (Flutter, RN, Xamarin, Unity, Cordova, Native)."""

    @property
    def name(self) -> str:
        return "apk_framework_detect"

    @property
    def display_name(self) -> str:
        return "Framework Detection"

    @property
    def description(self) -> str:
        return "Detect the application framework used to build the APK"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "sdk_framework"

    @property
    def timeout(self) -> int:
        return 60

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        if progress_callback:
            await progress_callback("Scanning APK for framework indicators...")

        try:
            zf = zipfile.ZipFile(apk_path, "r")
        except Exception as exc:
            result.error = f"Could not open APK: {exc}"
            return result

        with zf:
            namelist = zf.namelist()
            nameset = set(namelist)

            detected: dict[str, list[str]] = {}

            for framework, indicators in _FRAMEWORK_INDICATORS.items():
                matched: list[str] = []
                for pattern, is_prefix in indicators:
                    if is_prefix:
                        if any(n.startswith(pattern) for n in namelist):
                            matched.append(pattern)
                    else:
                        if pattern in nameset:
                            matched.append(pattern)
                if matched:
                    detected[framework] = matched

            # --- Try to extract version for each detected framework ---
            versions: dict[str, str] = {}

            if "Flutter" in detected:
                # Flutter version can sometimes be extracted from snapshot files
                for n in namelist:
                    if n.endswith("flutter_assets/version.json"):
                        try:
                            data = zf.read(n).decode(errors="replace")
                            import json
                            vdata = json.loads(data)
                            versions["Flutter"] = vdata.get("frameworkVersion", vdata.get("version", "unknown"))
                        except Exception:
                            pass
                        break
                if "Flutter" not in versions:
                    # Try to read version from snapshot_blob.bin header or pubspec
                    for n in namelist:
                        if "flutter_assets/AssetManifest" in n:
                            versions["Flutter"] = "detected (version unavailable)"
                            break

            if "React Native" in detected:
                # RN version can be in the bundle metadata
                if "assets/index.android.bundle" in nameset:
                    try:
                        bundle_bytes = zf.read("assets/index.android.bundle")
                        # First few KB usually contain version markers
                        header = bundle_bytes[:50000].decode(errors="replace")
                        rn_ver_m = re.search(r'"react-native"[^"]*"(\d+\.\d+\.\d+)"', header)
                        if not rn_ver_m:
                            rn_ver_m = re.search(r'ReactNativeVersion.*?major[":,\s]+(\d+).*?minor[":,\s]+(\d+).*?patch[":,\s]+(\d+)', header, re.S)
                            if rn_ver_m:
                                versions["React Native"] = f"{rn_ver_m.group(1)}.{rn_ver_m.group(2)}.{rn_ver_m.group(3)}"
                        else:
                            versions["React Native"] = rn_ver_m.group(1)
                    except Exception:
                        pass

            if "Xamarin" in detected:
                # Check Xamarin assembly versions
                for n in namelist:
                    if n.startswith("assemblies/") and "Xamarin" in n and n.endswith(".dll"):
                        versions["Xamarin"] = f"detected ({n.split('/')[-1]})"
                        break

            if "Unity" in detected:
                # Unity version from globalgamemanagers or data.unity3d
                for n in namelist:
                    if "globalgamemanagers" in n or "data.unity3d" in n:
                        try:
                            chunk = zf.read(n)[:4096]
                            text = chunk.decode(errors="replace")
                            unity_ver_m = re.search(r'(\d+\.\d+\.\d+[a-z]\d*)', text)
                            if unity_ver_m:
                                versions["Unity"] = unity_ver_m.group(1)
                        except Exception:
                            pass
                        break

            if "Cordova" in detected:
                # Cordova version from cordova.js
                if "assets/www/cordova.js" in nameset:
                    try:
                        cdata = zf.read("assets/www/cordova.js").decode(errors="replace")[:5000]
                        cord_m = re.search(r'PLATFORM_VERSION_BUILD_LABEL\s*=\s*["\']([^"\']+)', cdata)
                        if cord_m:
                            versions["Cordova"] = cord_m.group(1)
                    except Exception:
                        pass

        # --- Build results ---
        result.raw_output["detected_frameworks"] = {
            fw: {"indicators": inds, "version": versions.get(fw, "unknown")}
            for fw, inds in detected.items()
        }

        if not detected:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.TECHNOLOGY,
                    value="Native Android (Java/Kotlin)",
                    metadata={"framework": "native", "version": "N/A"},
                )
            )
            result.findings.append(
                ModuleFinding(
                    title="Native Android Application",
                    description="No cross-platform framework detected. App appears to be native Java/Kotlin.",
                    severity=FindingSeverity.INFO,
                    category="sdk_framework",
                    evidence="No Flutter, React Native, Xamarin, Unity, or Cordova indicators found.",
                    impact="Native apps may have standard Android attack surface.",
                    remediation="Proceed with standard Android static/dynamic analysis.",
                    confidence=0.8,
                )
            )
        else:
            for fw, indicators in detected.items():
                version = versions.get(fw, "unknown")
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.TECHNOLOGY,
                        value=fw,
                        metadata={"framework": fw, "version": version, "indicators": indicators},
                    )
                )
                # Security implications per framework
                implications: dict[str, str] = {
                    "Flutter": "Dart AOT code in libapp.so is harder to decompile. Use reFlutter or Doldrums. "
                               "SSL pinning bypass requires Frida with flutter-specific hooks.",
                    "React Native": "JS bundle in assets/ can be extracted and analysed. Hermes bytecode "
                                    "needs hbc-decompiler. Check for sensitive logic in JS.",
                    "Xamarin": "Mono assemblies in assemblies/ can be decompiled with ILSpy/dnSpy. "
                               "Check for hardcoded secrets in .NET DLLs.",
                    "Unity": "il2cpp games: use Il2CppDumper for class/method recovery. Mono games: "
                             "DLLs in assets/ are directly decompilable. Check for debug builds.",
                    "Cordova": "HTML/JS/CSS in assets/www/ is fully readable. Check for XSS, "
                               "insecure WebView config, exposed plugins, and cleartext secrets.",
                }
                result.findings.append(
                    ModuleFinding(
                        title=f"Framework Detected: {fw} (version: {version})",
                        description=f"APK built with {fw}. {implications.get(fw, '')}",
                        severity=FindingSeverity.INFO,
                        category="sdk_framework",
                        evidence=f"Indicators matched: {', '.join(indicators)}",
                        impact=implications.get(fw, "Framework-specific attack surface applies."),
                        remediation="Use framework-appropriate analysis tools.",
                        confidence=0.95,
                    )
                )

        return result


class SdkMapModule(BaseModule):
    """Map third-party SDKs present in the decompiled APK source."""

    @property
    def name(self) -> str:
        return "apk_sdk_map"

    @property
    def display_name(self) -> str:
        return "SDK Mapping"

    @property
    def description(self) -> str:
        return "Identify third-party SDKs in decompiled code and report data collection"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "sdk_framework"

    @property
    def timeout(self) -> int:
        return 120

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        decompiled_dir = scan_context.get("decompiled_dir", "")
        if not decompiled_dir:
            decompiled_dir = str(Path(settings.decompiled_dir) / Path(apk_path).stem)

        decompiled_path = Path(decompiled_dir)
        if not decompiled_path.exists():
            # Attempt jadx decompile
            if progress_callback:
                await progress_callback("Decompiling APK with jadx...")
            decompiled_path.mkdir(parents=True, exist_ok=True)
            stdout, stderr, rc = await self._run_command(
                ["jadx", "-d", str(decompiled_path), "--no-res", apk_path],
                timeout=120,
            )
            if rc != 0 and not any(decompiled_path.iterdir()):
                result.error = f"Decompilation failed: {stderr[:500]}"
                return result

        if progress_callback:
            await progress_callback("Scanning decompiled code for SDK packages...")

        # Build set of directory paths that exist in decompiled source
        existing_dirs: set[str] = set()
        existing_files: set[str] = set()
        for root_dir, dirs, files in os.walk(str(decompiled_path)):
            rel = os.path.relpath(root_dir, str(decompiled_path))
            existing_dirs.add(rel.replace(os.sep, "/"))
            for f in files:
                fp = os.path.join(rel, f).replace(os.sep, "/")
                existing_files.add(fp)

        found_sdks: list[dict[str, Any]] = []

        for package_prefix, sdk_info in _SDK_PACKAGES.items():
            # Convert com.google.firebase -> com/google/firebase to match dir structure
            dir_prefix = package_prefix.replace(".", "/")

            # Check if directory tree contains this package
            matched = False
            for d in existing_dirs:
                if d == dir_prefix or d.startswith(dir_prefix + "/"):
                    matched = True
                    break

            if not matched:
                # Also check if any file paths contain the package as a path prefix
                # (some decompilers place files differently)
                for fp in existing_files:
                    if dir_prefix in fp:
                        matched = True
                        break

            if not matched:
                # Final check: look for import statements mentioning the package
                # Only do a lightweight grep to avoid scanning every file
                package_dot = package_prefix
                # check smali-like paths too
                smali_prefix = package_prefix.replace(".", "/")
                for fp in existing_files:
                    if fp.endswith((".java", ".kt", ".smali")):
                        if smali_prefix in fp:
                            matched = True
                            break

            if matched:
                found_sdks.append({
                    "package": package_prefix,
                    "name": sdk_info["name"],
                    "collects": sdk_info["collects"],
                })
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.SDK,
                        value=sdk_info["name"],
                        metadata={
                            "package": package_prefix,
                            "data_collected": sdk_info["collects"],
                        },
                    )
                )

        result.raw_output["sdks_found"] = found_sdks
        result.raw_output["sdks_scanned"] = len(_SDK_PACKAGES)

        if found_sdks:
            sdk_list = "\n".join(
                f"  - {s['name']} ({s['package']}): {s['collects']}"
                for s in found_sdks
            )
            result.findings.append(
                ModuleFinding(
                    title=f"{len(found_sdks)} Third-Party SDKs Detected",
                    description=f"Found {len(found_sdks)} known SDKs in the decompiled APK. "
                    "Each SDK may collect and transmit user data.",
                    severity=FindingSeverity.INFO,
                    category="sdk_framework",
                    evidence=f"Detected SDKs:\n{sdk_list}",
                    impact="Combined data collection from all SDKs creates a comprehensive "
                    "user profile. Review privacy policy compliance.",
                    remediation="Audit each SDK's data collection against your privacy policy. "
                    "Remove SDKs that collect data not disclosed to users.",
                    confidence=0.85,
                )
            )

            # Flag ad/tracking SDKs specifically
            ad_sdks = [s for s in found_sdks if any(
                kw in s["name"].lower()
                for kw in ("ads", "ad ", "admob", "adcolony", "applovin", "ironsource",
                           "chartboost", "vungle", "mopub", "inmobi", "tapjoy", "pangle")
            )]
            if ad_sdks:
                result.findings.append(
                    ModuleFinding(
                        title=f"{len(ad_sdks)} Advertising SDK(s) Detected",
                        description="App integrates advertising SDKs that typically collect "
                        "advertising IDs, device fingerprints, and may track across apps.",
                        severity=FindingSeverity.LOW,
                        category="sdk_framework",
                        evidence="\n".join(f"  - {s['name']}" for s in ad_sdks),
                        impact="Advertising SDKs typically share data with ad networks and "
                        "may enable cross-app tracking.",
                        remediation="Ensure ad SDK data collection complies with GDPR/CCPA. "
                        "Provide opt-out mechanisms.",
                        confidence=0.9,
                    )
                )
        else:
            result.findings.append(
                ModuleFinding(
                    title="No Known SDKs Detected",
                    description="No known third-party SDKs identified in decompiled source.",
                    severity=FindingSeverity.INFO,
                    category="sdk_framework",
                    evidence=f"Scanned {len(_SDK_PACKAGES)} known SDK package patterns. None matched.",
                    impact="App may use custom or uncommon SDKs not in the signature database.",
                    remediation="Manual review of decompiled source for unknown data collection.",
                    confidence=0.7,
                )
            )

        return result


class TrackerDetectModule(BaseModule):
    """Detect known trackers using Exodus Privacy-style signatures."""

    @property
    def name(self) -> str:
        return "apk_tracker_detect"

    @property
    def display_name(self) -> str:
        return "Tracker Detection"

    @property
    def description(self) -> str:
        return "Detect known trackers (Exodus Privacy signatures) and calculate privacy score"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "sdk_framework"

    @property
    def timeout(self) -> int:
        return 90

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        if progress_callback:
            await progress_callback("Scanning APK for known trackers...")

        # We scan both the APK zip entries (package paths in dex) and decompiled dir
        # First: check APK zip entries for tracker package paths
        tracker_dirs: set[str] = set()
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for entry in zf.namelist():
                    # smali paths: smali/com/google/android/gms/ads/...
                    # or class entries in classes.dex (not directly readable, but smali dirs work)
                    tracker_dirs.add(entry)
        except Exception as exc:
            logger.warning("Could not read APK zip: %s", exc)

        # Also scan decompiled dir if available
        decompiled_dir = scan_context.get("decompiled_dir", "")
        if not decompiled_dir:
            decompiled_dir = str(Path(settings.decompiled_dir) / Path(apk_path).stem)

        decompiled_path = Path(decompiled_dir)
        if decompiled_path.exists():
            for root_dir, dirs, files in os.walk(str(decompiled_path)):
                rel = os.path.relpath(root_dir, str(decompiled_path)).replace(os.sep, "/")
                tracker_dirs.add(rel)

        # Also try: run aapt dump to get class list
        stdout, _, rc = await self._run_command(
            ["aapt", "dump", "badging", apk_path], timeout=30
        )
        # Not very useful for trackers, but the zip entry scan covers smali dirs

        # Match trackers
        found_trackers: list[dict[str, str]] = []
        found_prefixes: set[str] = set()

        for prefix, (tracker_name, data_desc) in _TRACKERS.items():
            # Convert dot notation to path: com.google.firebase -> com/google/firebase
            path_prefix = prefix.replace(".", "/")

            matched = False
            for entry in tracker_dirs:
                # Match both smali/com/google/... and com/google/... forms
                if path_prefix in entry:
                    matched = True
                    break

            if matched and prefix not in found_prefixes:
                found_prefixes.add(prefix)
                found_trackers.append({
                    "package": prefix,
                    "name": tracker_name,
                    "data_collected": data_desc,
                })
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.SDK,
                        value=tracker_name,
                        metadata={
                            "type": "tracker",
                            "package": prefix,
                            "data_collected": data_desc,
                        },
                    )
                )

        # --- Calculate privacy score (0 = great, 100 = terrible) ---
        # Weight categories differently
        tracker_count = len(found_trackers)
        ad_trackers = sum(1 for t in found_trackers if any(
            kw in t["name"].lower()
            for kw in ("ads", "ad ", "admob", "adcolony", "applovin", "chartboost",
                        "vungle", "mopub", "inmobi", "tapjoy", "ironsource", "pangle",
                        "startapp", "ogury", "mintegral", "fyber", "adcolony")
        ))
        analytics_trackers = sum(1 for t in found_trackers if any(
            kw in t["name"].lower()
            for kw in ("analytics", "amplitude", "mixpanel", "flurry", "countly",
                        "heap", "matomo", "segment", "metrica")
        ))
        crash_trackers = sum(1 for t in found_trackers if any(
            kw in t["name"].lower()
            for kw in ("crash", "sentry", "bugsnag", "new relic", "embrace", "app center")
        ))

        # Score: ads=5pts, analytics=3pts, crash/perf=1pt, other=2pts each, max 100
        score = min(100, ad_trackers * 5 + analytics_trackers * 3 + crash_trackers * 1 +
                    (tracker_count - ad_trackers - analytics_trackers - crash_trackers) * 2)

        result.raw_output["trackers"] = found_trackers
        result.raw_output["tracker_count"] = tracker_count
        result.raw_output["privacy_score"] = score
        result.raw_output["breakdown"] = {
            "ad_trackers": ad_trackers,
            "analytics_trackers": analytics_trackers,
            "crash_trackers": crash_trackers,
            "other_trackers": tracker_count - ad_trackers - analytics_trackers - crash_trackers,
        }

        # --- Findings ---
        if tracker_count == 0:
            result.findings.append(
                ModuleFinding(
                    title="No Known Trackers Detected",
                    description="No trackers from the Exodus Privacy database were found.",
                    severity=FindingSeverity.INFO,
                    category="sdk_framework",
                    evidence=f"Scanned against {len(_TRACKERS)} known tracker signatures.",
                    impact="App may still use unknown or custom tracking mechanisms.",
                    remediation="Manual review for custom analytics/tracking code.",
                    confidence=0.75,
                )
            )
        else:
            tracker_list = "\n".join(
                f"  - {t['name']} ({t['package']}): {t['data_collected']}"
                for t in found_trackers
            )

            severity = FindingSeverity.INFO
            if score >= 60:
                severity = FindingSeverity.HIGH
            elif score >= 35:
                severity = FindingSeverity.MEDIUM
            elif score >= 15:
                severity = FindingSeverity.LOW

            result.findings.append(
                ModuleFinding(
                    title=f"{tracker_count} Tracker(s) Detected — Privacy Score: {score}/100",
                    description=f"Found {tracker_count} known tracker(s) in the APK. "
                    f"Ad trackers: {ad_trackers}, Analytics: {analytics_trackers}, "
                    f"Crash reporters: {crash_trackers}. "
                    f"Privacy impact score: {score}/100 (higher = worse).",
                    severity=severity,
                    category="sdk_framework",
                    evidence=f"Detected trackers:\n{tracker_list}\n\n"
                    f"Privacy score: {score}/100\n"
                    f"Breakdown: Ads={ad_trackers}, Analytics={analytics_trackers}, "
                    f"Crash={crash_trackers}, Other="
                    f"{tracker_count - ad_trackers - analytics_trackers - crash_trackers}",
                    impact="Each tracker collects and transmits device/user data to third parties. "
                    "Combined, they create a detailed profile of the user.",
                    remediation="Review each tracker against the app's privacy policy. "
                    "Ensure GDPR/CCPA consent mechanisms are in place. "
                    "Remove trackers not essential for core functionality.",
                    cwe_id="CWE-359",
                    owasp_category="M1: Improper Platform Usage",
                    confidence=0.85,
                )
            )

            if ad_trackers >= 3:
                result.findings.append(
                    ModuleFinding(
                        title=f"Excessive Advertising Trackers ({ad_trackers})",
                        description=f"App contains {ad_trackers} advertising SDKs. "
                        "Multiple ad networks increase data exposure and tracking surface.",
                        severity=FindingSeverity.MEDIUM,
                        category="sdk_framework",
                        evidence="\n".join(
                            f"  - {t['name']}" for t in found_trackers
                            if any(kw in t["name"].lower()
                                   for kw in ("ads", "ad ", "admob", "adcolony", "applovin",
                                              "chartboost", "vungle", "mopub", "inmobi",
                                              "tapjoy", "ironsource", "pangle", "startapp"))
                        ),
                        impact="User data is shared with multiple ad networks simultaneously.",
                        remediation="Consolidate to fewer ad networks. Use mediation via a single SDK.",
                        confidence=0.9,
                    )
                )

        return result


class NativeLibModule(BaseModule):
    """Analyse native .so libraries bundled in the APK."""

    @property
    def name(self) -> str:
        return "apk_native_libs"

    @property
    def display_name(self) -> str:
        return "Native Library Analysis"

    @property
    def description(self) -> str:
        return "List and analyse native .so libraries for suspicious imports and known vulnerabilities"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "sdk_framework"

    @property
    def timeout(self) -> int:
        return 120

    _SUSPICIOUS_IMPORTS = re.compile(
        r'\b(system|execve?|popen|dlopen|dlsym|__system_property_get|'
        r'ptrace|fork|pipe|dup2|mprotect|mmap|eval|Runtime_exec)\b'
    )

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        if progress_callback:
            await progress_callback("Extracting and analysing native libraries...")

        # List all .so files from the APK
        so_files: list[str] = []
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for entry in zf.namelist():
                    if entry.startswith("lib/") and entry.endswith(".so"):
                        so_files.append(entry)
        except Exception as exc:
            result.error = f"Could not read APK: {exc}"
            return result

        if not so_files:
            result.findings.append(
                ModuleFinding(
                    title="No Native Libraries Found",
                    description="APK contains no .so files in lib/ directories.",
                    severity=FindingSeverity.INFO,
                    category="sdk_framework",
                    evidence="No lib/**/*.so entries in APK",
                    impact="App does not use native code directly.",
                    remediation="N/A",
                    confidence=0.95,
                )
            )
            return result

        # Group by library name (across architectures)
        lib_by_name: dict[str, list[str]] = {}
        for so in so_files:
            # lib/arm64-v8a/libfoo.so -> libfoo.so
            basename = so.rsplit("/", 1)[-1]
            lib_by_name.setdefault(basename, []).append(so)

        architectures: set[str] = set()
        for so in so_files:
            parts = so.split("/")
            if len(parts) >= 3:
                architectures.add(parts[1])

        result.raw_output["libraries"] = list(lib_by_name.keys())
        result.raw_output["architectures"] = list(architectures)
        result.raw_output["total_so_files"] = len(so_files)

        for basename in lib_by_name:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.FILE,
                    value=basename,
                    metadata={
                        "type": "native_library",
                        "architectures": [
                            p.split("/")[1] for p in lib_by_name[basename] if len(p.split("/")) >= 3
                        ],
                    },
                )
            )

        # --- Extract and analyse each unique library ---
        analysed = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                zf = zipfile.ZipFile(apk_path, "r")
            except Exception as exc:
                result.error = f"Could not open APK for extraction: {exc}"
                return result

            with zf:
                for basename, paths in lib_by_name.items():
                    if progress_callback:
                        await progress_callback(f"Analysing {basename}...")

                    # Extract one arch variant (prefer arm64)
                    extract_path = None
                    for preferred_arch in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
                        candidate = f"lib/{preferred_arch}/{basename}"
                        if candidate in paths:
                            extract_path = candidate
                            break
                    if not extract_path:
                        extract_path = paths[0]

                    try:
                        extracted = zf.extract(extract_path, tmpdir)
                    except Exception as exc:
                        logger.warning("Failed to extract %s: %s", extract_path, exc)
                        continue

                    # Run strings
                    stdout, stderr, rc = await self._run_command(
                        ["strings", "-n", "6", extracted], timeout=30
                    )
                    if rc != 0:
                        # Fallback: Python-based string extraction
                        try:
                            with open(extracted, "rb") as f:
                                raw = f.read()
                            stdout = "\n".join(
                                m.group(0) for m in re.finditer(rb'[\x20-\x7e]{6,}', raw)
                            )
                            stdout = stdout[:500_000]  # cap at 500KB
                        except Exception:
                            continue

                    strings_output = stdout

                    # Check for suspicious function calls
                    suspicious_matches: list[str] = []
                    for match in self._SUSPICIOUS_IMPORTS.finditer(strings_output):
                        func_name = match.group(1)
                        # Get context around the match
                        start = max(0, match.start() - 50)
                        end = min(len(strings_output), match.end() + 50)
                        context = strings_output[start:end].strip()
                        suspicious_matches.append(f"{func_name}: ...{context}...")

                    if suspicious_matches:
                        # Deduplicate
                        unique_funcs = list(set(m.split(":")[0] for m in suspicious_matches))
                        severity = FindingSeverity.MEDIUM
                        if any(f in unique_funcs for f in ("system", "execve", "popen", "exec")):
                            severity = FindingSeverity.HIGH

                        result.findings.append(
                            ModuleFinding(
                                title=f"Suspicious Native Calls in {basename}",
                                description=f"Library {basename} references potentially dangerous functions: "
                                f"{', '.join(unique_funcs)}. May indicate command execution, "
                                "dynamic loading, or anti-debugging capabilities.",
                                severity=severity,
                                category="sdk_framework",
                                evidence=f"Library: {extract_path}\n"
                                f"Functions found: {', '.join(unique_funcs)}\n\n"
                                "Sample contexts:\n" + "\n".join(suspicious_matches[:10]),
                                impact="Native code can execute system commands, load arbitrary code, "
                                "or manipulate process memory.",
                                remediation="Review native library source code for command injection "
                                "or unsafe dynamic loading patterns.",
                                cwe_id="CWE-78",
                                confidence=0.6,
                                validation_hint=f"Run: strings {extract_path} | grep -E 'system|exec|popen'",
                            )
                        )

                    # Check against known vulnerable libraries
                    for vuln_name, vuln_desc in _VULNERABLE_LIBS.items():
                        if basename == vuln_name or basename.startswith(vuln_name.split(".")[0]):
                            # Try to extract version string
                            version_strings: list[str] = []
                            for vm in re.finditer(
                                r'(?:version|OpenSSL|SQLite|libcurl|libpng|libxml)\s*[\d.]+[a-z]?\b',
                                strings_output,
                                re.I,
                            ):
                                version_strings.append(vm.group(0))

                            result.findings.append(
                                ModuleFinding(
                                    title=f"Known Vulnerable Library: {basename}",
                                    description=f"Bundled library {basename} may contain known "
                                    f"vulnerabilities. {vuln_desc}",
                                    severity=FindingSeverity.MEDIUM,
                                    category="sdk_framework",
                                    evidence=f"Library: {extract_path}\n"
                                    f"Version strings found: {version_strings[:5] if version_strings else 'none detected'}\n"
                                    f"Known issues: {vuln_desc}",
                                    impact="Bundled native libraries with known CVEs can be exploited "
                                    "for code execution or data leaks.",
                                    remediation="Update the bundled library to the latest patched version. "
                                    "Consider using system libraries where possible.",
                                    cwe_id="CWE-1104",
                                    confidence=0.65,
                                    validation_hint=f"Check version: strings {extract_path} | grep -i version",
                                )
                            )
                            break

                    # Look for URLs, IPs, and interesting strings
                    urls_in_lib = re.findall(r'https?://[^\s"\'<>]{5,200}', strings_output)
                    ips_in_lib = re.findall(
                        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
                        strings_output,
                    )

                    if urls_in_lib:
                        for url in list(set(urls_in_lib))[:10]:
                            result.assets.append(
                                ModuleAsset(
                                    asset_type=AssetType.ENDPOINT,
                                    value=url,
                                    metadata={"source": f"native_lib:{basename}"},
                                )
                            )

                    if ips_in_lib:
                        for ip in list(set(ips_in_lib))[:10]:
                            if not ip.startswith(("0.", "127.", "255.")):
                                result.assets.append(
                                    ModuleAsset(
                                        asset_type=AssetType.IP,
                                        value=ip,
                                        metadata={"source": f"native_lib:{basename}"},
                                    )
                                )

                    analysed += 1

        # Summary
        result.findings.append(
            ModuleFinding(
                title=f"Native Library Summary: {len(lib_by_name)} Libraries, {len(architectures)} Arch(s)",
                description=f"APK bundles {len(lib_by_name)} unique native libraries across "
                f"{len(architectures)} architecture(s): {', '.join(sorted(architectures))}. "
                f"Analysed {analysed} libraries.",
                severity=FindingSeverity.INFO,
                category="sdk_framework",
                evidence=f"Libraries: {', '.join(sorted(lib_by_name.keys()))}\n"
                f"Architectures: {', '.join(sorted(architectures))}",
                impact="Native libraries expand the attack surface beyond managed code.",
                remediation="Audit all bundled .so files for known CVEs and unsafe functions.",
                confidence=0.95,
            )
        )

        return result
