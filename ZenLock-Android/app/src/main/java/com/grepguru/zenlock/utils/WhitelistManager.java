package com.grepguru.zenlock.utils;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.util.Log;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Centralized whitelist management to prevent code duplication
 * and ensure consistent whitelist logic across the app
 */
public class WhitelistManager {
    
    private static final String TAG = "WhitelistManager";

    // Essential system packages that must stay reachable while a session runs.
    // SECURITY: Settings and launchers are intentionally absent.
    private static final Set<String> ESSENTIAL_SYSTEM_PACKAGES = new HashSet<>(Arrays.asList(
        "com.android.systemui",           // System UI (status bar, navigation, biometric prompt)
        "com.android.keyguard",           // System lock screen + device credential UI
        "android",                        // Core Android system
        "com.android.phone",              // Phone app (for emergency calls)
        "com.android.incallui",           // In-call UI
        "com.android.dialer",             // Dialer app
        "com.android.emergency",          // Emergency services
        "com.android.camera2",            // Camera (for emergency photos)
        "com.android.camera",             // Camera (alternative)
        "com.google.android.gms",         // Google Play Services
        "com.google.android.gsf"          // Google Services Framework
    ));

    // System windows that sit on top of the app the user is in. They are not a
    // foreground app change: the biometric prompt an allowed banking app waits on,
    // a runtime permission dialog, or a keyguard challenge must never be blocked.
    private static final Set<String> SYSTEM_SURFACE_PACKAGES = new HashSet<>(Arrays.asList(
        "com.android.systemui",              // Status bar, notification shade, biometric prompt
        "com.android.keyguard",              // System lock screen + credential UI
        "android",                           // Framework dialogs hosted by system_server
        "com.android.permissioncontroller",  // Runtime permission dialogs
        "com.google.android.permissioncontroller",
        "com.android.credentialmanager"      // Credential Manager / passkeys
    ));

    // Window classes that render biometric / credential confirmation on behalf of
    // the foreground app. They are authentication UI, not the app's own window.
    private static final String[] AUTH_UI_CLASS_MARKERS = {
        "biometric",
        "fingerprint",
        "authcontainer",
        "confirmdevicecredential",
        "confirmlockpattern",
        "confirmlockpassword",
        "credential"
    };

    // Cached answers for hot-path window classification.
    private static final Map<String, Boolean> systemWindowCache = new ConcurrentHashMap<>();
    private static volatile Set<String> launcherPackages;
    
    /**
     * Check if an app is whitelisted (centralized logic)
     * @param context The context
     * @param packageName The package name to check
     * @return True if the app is whitelisted, false otherwise
     */
    public static boolean isAppWhitelisted(Context context, String packageName) {
        if (packageName == null || packageName.isEmpty()) {
            return false;
        }

        // Always allow the ZenLock app itself
        if (context.getPackageName().equals(packageName)) {
            return true;
        }
        
        if (isEnabledKeyboard(context, packageName)) return true;

        // SECURITY CHECK: Block known security risk packages
        if (isSecurityRisk(packageName)) {
            return false;
        }

        // Allow essential system packages (SECURITY: Removed settings and launcher)
        if (ESSENTIAL_SYSTEM_PACKAGES.contains(packageName)) {
            Log.d(TAG, "Essential system package allowed: " + packageName);
            return true;
        }

        // Check user whitelisted apps
        SharedPreferences preferences = context.getSharedPreferences("FocusLockPrefs", Context.MODE_PRIVATE);
        Set<String> whitelistedApps = preferences.getStringSet("whitelisted_apps", new HashSet<>());
        
        // Get ALL allowed packages (including system services for in-app activities)
        Set<String> allAllowedApps = new HashSet<>(whitelistedApps);
        allAllowedApps.addAll(AppUtils.getAllAllowedPackages(context));
        
        boolean isWhitelisted = allAllowedApps.contains(packageName);
        if (isWhitelisted) {
            Log.d(TAG, "User whitelisted app allowed: " + packageName);
        }
        
        return isWhitelisted;
    }
    
    /** Resolve the IME role from Android, without guessing OEM package names. */
    public static boolean isEnabledKeyboard(Context context, String packageName) {
        if (packageName == null || packageName.isEmpty()) return false;
        try {
            InputMethodManager imm = (InputMethodManager) context.getSystemService(Context.INPUT_METHOD_SERVICE);
            if (imm != null) {
                List<InputMethodInfo> enabledIMEs = imm.getEnabledInputMethodList();
                for (InputMethodInfo imi : enabledIMEs) {
                    if (imi.getPackageName().equals(packageName)) {
                        return true;
                    }
                    if (imi.getServiceInfo() != null && imi.getServiceInfo().packageName.equals(packageName)) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "IME check failed for: " + packageName, e);
        }

        return false;
    }

    /**
     * True for windows that belong to the system UI layer rather than to an app the
     * user opened (biometric prompt, permission dialog, keyguard, notification shade).
     */
    public static boolean isSystemSurfaceWindow(String packageName) {
        return packageName != null && SYSTEM_SURFACE_PACKAGES.contains(packageName);
    }

    /**
     * Supporting UI that must never be treated as the user opening an app.
     *
     * System components without a launcher entry (document pickers, biometric
     * providers, print/AOSP helper activities) are opened by the foreground app,
     * so blocking them closes a dialog an allowed app is waiting on. That is why a
     * banking app asking for a fingerprint used to be interrupted by ZenLock.
     */
    public static boolean isOverlayWindow(Context context, String packageName, String className) {
        if (packageName == null || packageName.isEmpty()) return false;
        if (isSystemSurfaceWindow(packageName)) return true;
        // Settings and launchers stay blockable, except for their auth screens.
        if (isSecurityRisk(packageName)) return isAuthWindowClass(className);
        if (isNonBlockableSystemWindow(context, packageName)) return true;
        return isSystemApp(context, packageName) && isAuthWindowClass(className);
    }

    /** True for system components that have no launcher entry of their own. */
    private static boolean isNonBlockableSystemWindow(Context context, String packageName) {
        Boolean cached = systemWindowCache.get(packageName);
        if (cached != null) return cached;
        boolean nonBlockable = isSystemApp(context, packageName) && !hasLauncherEntry(context, packageName);
        systemWindowCache.put(packageName, nonBlockable);
        return nonBlockable;
    }

    private static boolean isAuthWindowClass(String className) {
        if (className == null || className.isEmpty()) return false;
        String lower = className.toLowerCase(Locale.ROOT);
        for (String marker : AUTH_UI_CLASS_MARKERS) {
            if (lower.contains(marker)) return true;
        }
        return false;
    }

    private static boolean isSystemApp(Context context, String packageName) {
        try {
            ApplicationInfo info = context.getPackageManager().getApplicationInfo(packageName, 0);
            return (info.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private static boolean hasLauncherEntry(Context context, String packageName) {
        Set<String> cached = launcherPackages;
        if (cached == null) {
            Set<String> resolved = new HashSet<>();
            try {
                PackageManager pm = context.getPackageManager();
                Intent intent = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
                for (ResolveInfo info : pm.queryIntentActivities(intent, 0)) {
                    if (info.activityInfo != null) resolved.add(info.activityInfo.packageName);
                }
            } catch (RuntimeException e) {
                // Assume a user-facing app on lookup failure rather than allowing it.
                Log.w(TAG, "Launcher entry lookup failed", e);
                return true;
            }
            launcherPackages = resolved;
            cached = resolved;
        }
        return cached.contains(packageName);
    }

    /**
     * Get a list of all whitelisted packages for debugging
     * @param context The context
     * @return Set of all whitelisted package names
     */
    public static Set<String> getAllWhitelistedPackages(Context context) {
        Set<String> allWhitelisted = new HashSet<>();

        // Add essential system packages
        allWhitelisted.addAll(ESSENTIAL_SYSTEM_PACKAGES);

        // Add user whitelisted apps
        SharedPreferences preferences = context.getSharedPreferences("FocusLockPrefs", Context.MODE_PRIVATE);
        Set<String> whitelistedApps = preferences.getStringSet("whitelisted_apps", new HashSet<>());
        allWhitelisted.addAll(whitelistedApps);
        
        // Add AppUtils allowed packages
        allWhitelisted.addAll(AppUtils.getAllAllowedPackages(context));
        
        return allWhitelisted;
    }
    
    /**
     * Log all whitelisted packages for debugging
     * @param context The context
     */
    public static void logAllWhitelistedPackages(Context context) {
        Set<String> allWhitelisted = getAllWhitelistedPackages(context);
        Log.d(TAG, "All whitelisted packages (" + allWhitelisted.size() + "): " + allWhitelisted);
    }
    
    /**
     * Check if a package is a security risk (settings, launcher, etc.)
     * @param packageName The package name to check
     * @return True if the package is a security risk
     */
    public static boolean isSecurityRisk(String packageName) {
        if (packageName == null || packageName.isEmpty()) {
            return false;
        }
        
        String[] securityRiskPackages = {
            "com.android.settings",           // Allows force stop
            // Samsung
            "com.sec.android.app.launcher",   // Samsung One UI Launcher
            "com.samsung.android.launcher",   // Samsung Launcher (legacy)
            // Google / AOSP
            "com.google.android.apps.nexuslauncher", // Pixel Launcher
            "com.android.launcher",           // Stock launcher
            "com.android.launcher2",          // Legacy launcher
            "com.android.launcher3",          // AOSP launcher
            "com.google.android.launcher",    // Google Now Launcher (legacy)
            // Xiaomi / Redmi / POCO
            "com.miui.home",                  // MIUI / HyperOS launcher
            "com.mi.android.globallauncher",  // POCO launcher
            // OnePlus
            "com.oneplus.launcher",           // OnePlus launcher (newer)
            "net.oneplus.launcher",           // OnePlus launcher (older)
            // Huawei / Honor
            "com.huawei.android.launcher",    // Huawei launcher
            "com.hihonor.android.launcher",   // Honor launcher
            // Oppo / Realme
            "com.oppo.launcher",              // OPPO / Realme launcher
            "com.realme.launcher",            // Realme launcher (legacy)
            // Vivo
            "com.bbk.launcher2",              // Vivo launcher
            "com.vivo.launcher",              // Vivo launcher (legacy)
            // Nothing
            "com.nothing.launcher",           // Nothing Phone launcher
            // Motorola
            "com.motorola.launcher3",         // Moto launcher
            "com.motorola.launcher",          // Moto launcher (legacy)
            // Nokia (HMD)
            "com.hmd.launcher",               // Nokia launcher
            // ASUS
            "com.asus.launcher",              // ASUS launcher
            // Lenovo
            "com.lenovo.launcher",            // Lenovo launcher
            // Sony
            "com.sonymobile.home",            // Sony Xperia Home (older)
            "com.sonymobile.launcher",        // Sony Xperia launcher (newer)
            "com.sony.launcher",              // Sony launcher (legacy)
            // LG (legacy)
            "com.lge.launcher2",              // LG launcher (older)
            "com.lge.launcher3",              // LG launcher (newer)
            // HTC
            "com.htc.launcher",               // HTC Sense Home
            "com.htc.launcher.edge",          // HTC Edge launcher
            // Tecno / Infinix / itel (Transsion)
            "com.transsion.hilauncher",       // Tecno HiOS launcher
            "com.transsion.XOSLauncher",      // Infinix XOS launcher
            "com.transsion.itel.launcher",    // itel launcher
            // ZTE / Nubia
            "com.zte.mifavor.launcher",       // ZTE MiFavor launcher
            "com.nubia.launcher"              // Nubia launcher
        };
        
        for (String riskPackage : securityRiskPackages) {
            if (riskPackage.equals(packageName)) {
                Log.w(TAG, "SECURITY RISK: Package " + packageName + " is blocked for security reasons");
                return true;
            }
        }
        
        return false;
    }
}
