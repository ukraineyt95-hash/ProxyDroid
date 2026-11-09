package com.proxydroid

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean


class ProxyVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.proxydroid.action.START"
        const val ACTION_STOP = "com.proxydroid.action.STOP"
        private const val CHANNEL_ID = "proxydroid_vpn"
        private const val NOTIFICATION_ID = 7412
        private const val TUN_MTU = 1500
        private const val IPV4_TUN_ADDRESS = "10.73.0.1"
        private const val IPV4_DNS_ADDRESS = "10.73.0.2"
        private const val IPV6_TUN_ADDRESS = "fd00:5052:4f58:59::1"
        private const val IPV6_DNS_ADDRESS = "fd00:5052:4f58:59::2"
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val stopRequested = AtomicBoolean(false)
    @Volatile private var starting = false
    @Volatile private var active = false
    @Volatile private var runnerModule: PyObject? = null
    private var monitorJob: kotlinx.coroutines.Job? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopRequested.set(true)
                serviceScope.launch {
                    stopTunnel("Отключено", stopService = true)
                }
            }
            ACTION_START -> {
                if (active || starting) return START_STICKY
                stopRequested.set(false)
                starting = true
                RuntimeState.update(
                    ProxyRuntimeStatus(
                        active = false,
                        message = "Подключение…",
                        detail = "Запуск прокси и создание системного TUN-интерфейса.",
                    ),
                )
                try {
                    startForegroundCompat(buildNotification("Подключение…"))
                    serviceScope.launch { startTunnel() }
                } catch (error: Throwable) {
                    starting = false
                    RuntimeState.update(
                        ProxyRuntimeStatus(
                            active = false,
                            message = "Не удалось запустить VPN",
                            detail = error.message ?: "Ошибка foreground-сервиса.",
                        ),
                    )
                    stopSelf(startId)
                }
            }
            else -> return START_NOT_STICKY
        }
        return START_STICKY
    }

    private suspend fun startTunnel() {
        var detachedFd: Int? = null
        try {
            val settings = ProxySettingsStore(this).load()
            settings.validationError()?.let { throw IllegalArgumentException(it) }

            val builder = Builder()
                .setSession("ProxyDroid")
                .setMtu(TUN_MTU)
                .addAddress(IPV4_TUN_ADDRESS, 24)
                .addAddress(IPV6_TUN_ADDRESS, 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(IPV4_DNS_ADDRESS)
                .addDnsServer(IPV6_DNS_ADDRESS)
                // The Python proxy's own sockets must bypass this VPN to avoid a route loop.
                .addDisallowedApplication(packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setBlocking(false)
            }

            val pfd = builder.establish()
                ?: throw IllegalStateException("Android не выдал TUN-интерфейс. Проверьте разрешение VPN.")
            detachedFd = pfd.detachFd()
            pfd.close()

            val fdForPython = detachedFd
                ?: throw IllegalStateException("Не удалось получить файловый дескриптор TUN.")
            if (stopRequested.get()) throw CancellationException("Подключение отменено")
            val module = withContext(Dispatchers.IO) {
                if (!Python.isStarted()) {
                    Python.start(AndroidPlatform(this@ProxyVpnService))
                }
                val runner = Python.getInstance().getModule("android_runner")
                runner.callAttr(
                    "start",
                    fdForPython,
                    JSONObject(settings.toPythonMap()).toString(),
                )
                runner
            }
            // android_runner duplicates the descriptor before reporting ready.
            runCatching { ParcelFileDescriptor.adoptFd(fdForPython).close() }
            detachedFd = null
            runnerModule = module

            if (stopRequested.get()) {
                stopTunnel("Отключено", stopService = true)
                return
            }

            starting = false
            active = true
            RuntimeState.update(
                ProxyRuntimeStatus(
                    active = true,
                    message = "Подключено",
                    detail = if (settings.upstreamProxy.isBlank()) {
                        "TUN активен · встроенный SOCKS5 ${settings.host}:${settings.port}"
                    } else {
                        "TUN активен · upstream ${settings.upstreamProxy}"
                    },
                ),
            )
            updateNotification("Туннель активен · SOCKS5 ${settings.port}")
            monitorRunner(module)
        } catch (error: Throwable) {
            detachedFd?.let { fd -> runCatching { ParcelFileDescriptor.adoptFd(fd).close() } }
            starting = false
            active = false
            val detail = when (error) {
                is CancellationException -> "Подключение отменено."
                else -> error.message ?: error.javaClass.simpleName
            }
            runnerModule?.let { module ->
                withContext(Dispatchers.IO) { runCatching { module.callAttr("stop") } }
            }
            runnerModule = null
            RuntimeState.update(
                ProxyRuntimeStatus(
                    active = false,
                    message = "Ошибка подключения",
                    detail = detail,
                ),
            )
            withContext(Dispatchers.Main) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun monitorRunner(module: PyObject) {
        monitorJob?.cancel()
        monitorJob = serviceScope.launch {
            while (isActive) {
                delay(1500)
                val running = withContext(Dispatchers.IO) {
                    runCatching { module.callAttr("is_running").toBoolean() }.getOrDefault(false)
                }
                if (!running) {
                    if (stopRequested.get()) return@launch
                    val error = withContext(Dispatchers.IO) {
                        runCatching { module.callAttr("last_error").toString() }
                            .getOrDefault("")
                    }
                    stopTunnel(
                        error.ifBlank { "Прокси или обработчик TUN остановился." },
                        stopService = true,
                        failed = true,
                    )
                    return@launch
                }
            }
        }
    }

    private suspend fun stopTunnel(
        reason: String,
        stopService: Boolean,
        failed: Boolean = false,
    ) {
        stopRequested.set(true)
        if (starting && runnerModule == null) return
        monitorJob?.cancel()
        monitorJob = null
        active = false
        starting = false
        val module = runnerModule
        runnerModule = null
        if (module != null) {
            withContext(Dispatchers.IO) {
                runCatching { module.callAttr("stop") }
            }
        }
        RuntimeState.update(
            ProxyRuntimeStatus(
                active = false,
                message = if (failed) "Туннель остановлен" else "Отключено",
                detail = reason,
            ),
        )
        withContext(Dispatchers.Main) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            if (stopService) stopSelf()
        }
    }

    override fun onRevoke() {
        stopRequested.set(true)
        serviceScope.launch {
            stopTunnel("Системное разрешение VPN отозвано.", stopService = true)
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        stopRequested.set(true)
        monitorJob?.cancel()
        runnerModule?.let { module ->
            runCatching { module.callAttr("stop") }
        }
        runnerModule = null
        active = false
        starting = false
        if (RuntimeState.status.value.active || RuntimeState.status.value.message == "Подключение…") {
            RuntimeState.update(
                ProxyRuntimeStatus(
                    active = false,
                    message = "Отключено",
                    detail = "Служба VPN остановлена.",
                ),
            )
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(text: String) {
        runCatching {
            NotificationManagerCompat.from(this).notify(NOTIFICATION_ID, buildNotification(text))
        }
    }

    private fun buildNotification(text: String): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopService = PendingIntent.getService(
            this,
            1,
            Intent(this, ProxyVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_proxy)
            .setContentTitle("ProxyDroid")
            .setContentText(text)
            .setContentIntent(openApp)
            .setOngoing(active || starting)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .addAction(0, "Отключить", stopService)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "VPN ProxyDroid",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Статус локального SOCKS5-прокси и TUN-туннеля"
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }
}
