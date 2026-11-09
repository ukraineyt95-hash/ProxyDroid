package com.proxydroid

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ProxyDroidTheme {
                ProxyDroidApp()
            }
        }
    }
}

private val ProxyDroidColors = darkColorScheme(
    primary = Color(0xFF62DCC6),
    onPrimary = Color(0xFF052822),
    secondary = Color(0xFF9BB4F5),
    background = Color(0xFF09111E),
    surface = Color(0xFF111C2A),
    surfaceVariant = Color(0xFF19283A),
    onBackground = Color(0xFFEAF2FA),
    onSurface = Color(0xFFEAF2FA),
    onSurfaceVariant = Color(0xFFA7B6C9),
    error = Color(0xFFFF8E83),
)

@Composable
private fun ProxyDroidTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = ProxyDroidColors, content = content)
}

@Composable
private fun ProxyDroidApp() {
    val context = LocalContext.current
    val store = remember { ProxySettingsStore(context) }
    var settings by remember { mutableStateOf(store.load()) }
    var savedSettings by remember { mutableStateOf(settings) }
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var dialogMessage by remember { mutableStateOf<String?>(null) }
    val status by RuntimeState.status.collectAsStateWithLifecycle()

    val vpnConsent = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService(context)
        } else {
            dialogMessage = "Для создания TUN-интерфейса нужно разрешить ProxyDroid подключаться как VPN."
        }
    }
    val notificationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        requestVpnConsent(context) { intent -> vpnConsent.launch(intent) }
    }

    fun saveSettings(): Boolean {
        val validation = settings.validationError()
        if (validation != null) {
            dialogMessage = validation
            return false
        }
        store.save(settings)
        savedSettings = settings
        return true
    }

    fun connect() {
        if (status.active) {
            context.startService(
                Intent(context, ProxyVpnService::class.java).setAction(ProxyVpnService.ACTION_STOP),
            )
            return
        }
        if (!saveSettings()) return
        if (settings.isExposedWithoutAuthentication()) {
            dialogMessage = "Прокси будет доступен не только этому устройству. Задайте логин и пароль SOCKS5 в настройках или используйте 127.0.0.1."
            selectedTab = 1
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestVpnConsent(context) { intent -> vpnConsent.launch(intent) }
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            NavigationBar(containerColor = Color(0xFF0D1725)) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Text("VPN", fontSize = 10.sp, fontWeight = FontWeight.Bold) },
                    label = { Text("Туннель") },
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Text("•••", fontSize = 12.sp, fontWeight = FontWeight.Bold) },
                    label = { Text("Настройки") },
                )
            }
        },
    ) { insets ->
        when (selectedTab) {
            0 -> HomeScreen(
                modifier = Modifier.padding(insets),
                status = status,
                settings = settings,
                onConnect = ::connect,
                onOpenSettings = { selectedTab = 1 },
            )
            else -> SettingsScreen(
                modifier = Modifier.padding(insets),
                settings = settings,
                enabled = !status.active && status.message != "Подключение…",
                saved = settings == savedSettings,
                onSettingsChange = { settings = it },
                onSave = {
                    if (saveSettings()) {
                        Toast.makeText(context, "Настройки сохранены", Toast.LENGTH_SHORT).show()
                    }
                },
            )
        }
    }

    dialogMessage?.let { message ->
        AlertDialog(
            onDismissRequest = { dialogMessage = null },
            title = { Text("ProxyDroid") },
            text = { Text(message) },
            confirmButton = {
                TextButton(onClick = { dialogMessage = null }) { Text("Понятно") }
            },
            containerColor = MaterialTheme.colorScheme.surface,
        )
    }
}

private fun requestVpnConsent(context: Context, launch: (Intent) -> Unit) {
    val consentIntent = VpnService.prepare(context)
    if (consentIntent == null) {
        startVpnService(context)
    } else {
        launch(consentIntent)
    }
}

private fun startVpnService(context: Context) {
    val intent = Intent(context, ProxyVpnService::class.java)
        .setAction(ProxyVpnService.ACTION_START)
    ContextCompat.startForegroundService(context, intent)
}

@Composable
private fun HomeScreen(
    modifier: Modifier = Modifier,
    status: ProxyRuntimeStatus,
    settings: ProxySettings,
    onConnect: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(
                    "PROXYDROID",
                    color = MaterialTheme.colorScheme.primary,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 2.sp,
                )
                Text(
                    "Туннель под контролем",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 13.sp,
                )
            }
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.size(44.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text("P", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Black)
                }
            }
        }

        Card(
            shape = RoundedCornerShape(26.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(22.dp),
                verticalArrangement = Arrangement.spacedBy(18.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .clip(CircleShape)
                            .background(if (status.active) MaterialTheme.colorScheme.primary else Color(0xFF59677A)),
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        status.message.uppercase(),
                        color = if (status.active) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.1.sp,
                    )
                }
                Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text(
                        if (status.active) "Ваш туннель работает" else "Ваш трафик. Ваш маршрут.",
                        color = MaterialTheme.colorScheme.onSurface,
                        fontSize = 24.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        status.detail,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 14.sp,
                        lineHeight = 20.sp,
                    )
                }
                Button(
                    onClick = onConnect,
                    enabled = status.message != "Подключение…",
                    modifier = Modifier.fillMaxWidth().height(54.dp),
                    shape = RoundedCornerShape(17.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (status.active) Color(0xFF26364A) else MaterialTheme.colorScheme.primary,
                        contentColor = if (status.active) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onPrimary,
                    ),
                ) {
                    Text(
                        when {
                            status.active -> "Отключиться"
                            status.message == "Подключение…" -> "Создаём TUN-интерфейс…"
                            else -> "Подключить ProxyDroid"
                        },
                        fontWeight = FontWeight.Bold,
                    )
                }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SummaryCard(
                modifier = Modifier.weight(1f),
                eyebrow = "SOCKS5",
                value = "${settings.host}:${settings.port}",
                detail = if (settings.upstreamProxy.isBlank()) "встроенный прокси" else "локальный слушатель",
            )
            SummaryCard(
                modifier = Modifier.weight(1f),
                eyebrow = "TUN",
                value = if (status.active) "Активен" else "Готов",
                detail = "IPv4 + IPv6",
            )
        }

        if (settings.hasNoAuthentication()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF382525)),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (settings.isExposedWithoutAuthentication()) {
                        "Внимание: слушатель доступен по сети без пароля. Перед подключением добавьте учётные данные SOCKS5."
                    } else {
                        "Без SOCKS5-пароля к локальному порту могут подключаться другие приложения Android. Рекомендуем включить авторизацию."
                    },
                    modifier = Modifier.padding(16.dp),
                    color = Color(0xFFFFC2B8),
                    fontSize = 13.sp,
                    lineHeight = 19.sp,
                )
            }
        }

        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onOpenSettings),
            shape = RoundedCornerShape(20.dp),
            color = MaterialTheme.colorScheme.surfaceVariant,
        ) {
            Row(
                modifier = Modifier.padding(18.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text("Параметры прокси и DNS", fontWeight = FontWeight.SemiBold)
                    Text(
                        if (settings.udpOverTcp) "UDP-over-TCP включён" else "UDP-over-TCP выключен",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 13.sp,
                    )
                }
                Text("Настроить  ›", color = MaterialTheme.colorScheme.primary, fontSize = 13.sp)
            }
        }

        Text(
            "ProxyDroid создаёт VPN-интерфейс Android и передаёт пакеты встроенному SOCKS5-движку. Само приложение исключено из VPN, чтобы соединения прокси не зацикливались.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 12.sp,
            lineHeight = 18.sp,
            modifier = Modifier.padding(horizontal = 2.dp),
        )
        Spacer(Modifier.height(4.dp))
    }
}

@Composable
private fun SummaryCard(
    modifier: Modifier = Modifier,
    eyebrow: String,
    value: String,
    detail: String,
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                eyebrow,
                color = MaterialTheme.colorScheme.primary,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
            )
            Text(value, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
            Text(detail, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
        }
    }
}

@Composable
private fun SettingsScreen(
    modifier: Modifier = Modifier,
    settings: ProxySettings,
    enabled: Boolean,
    saved: Boolean,
    onSettingsChange: (ProxySettings) -> Unit,
    onSave: () -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Настройки", fontSize = 28.sp, fontWeight = FontWeight.Bold)
            Text(
                "Поля соответствуют параметрам запуска встроенного socks5_proxy.py.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 14.sp,
                lineHeight = 19.sp,
            )
        }

        if (!enabled) {
            InfoCard("Чтобы применить изменения, сначала отключите VPN.")
        }

        SettingsSection("SOCKS5 · ФЛАГИ ПРОКСИ") {
            SettingsField(
                label = "Адрес прослушивания · --host",
                value = settings.host,
                hint = "По умолчанию 127.0.0.1 — только на этом устройстве.",
                enabled = enabled,
                onValueChange = { onSettingsChange(settings.copy(host = it)) },
            )
            SettingsField(
                label = "Порт · --port",
                value = settings.port,
                hint = "1–65535",
                enabled = enabled,
                keyboardType = KeyboardType.Number,
                onValueChange = { onSettingsChange(settings.copy(port = it)) },
            )
            SettingsField(
                label = "Логин · --username",
                value = settings.username,
                hint = "Заполните вместе с паролем; при первом запуске логин создаётся автоматически.",
                enabled = enabled,
                onValueChange = { onSettingsChange(settings.copy(username = it)) },
            )
            PasswordField(
                value = settings.password,
                enabled = enabled,
                onValueChange = { onSettingsChange(settings.copy(password = it)) },
            )
            SwitchSetting(
                title = "Печатать TLS-сертификат · --print-cert",
                description = "Выводит сертификат встроенного mKCP/H2Mux-транспорта в лог сервиса.",
                checked = settings.printCert,
                enabled = enabled,
                onCheckedChange = { onSettingsChange(settings.copy(printCert = it)) },
            )
        }

        SettingsSection("ВНЕШНИЙ SOCKS5 ДЛЯ TUN · ДОПОЛНИТЕЛЬНО") {
            SettingsField(
                label = "Адрес внешнего SOCKS5",
                value = settings.upstreamProxy,
                hint = "Пусто — использовать встроенный прокси. Например socks5://proxy.example:1080.",
                enabled = enabled,
                onValueChange = { onSettingsChange(settings.copy(upstreamProxy = it)) },
            )
            SettingsField(
                label = "Логин внешнего SOCKS5",
                value = settings.upstreamUsername,
                hint = "Необязательно; заполните вместе с паролем.",
                enabled = enabled,
                onValueChange = { onSettingsChange(settings.copy(upstreamUsername = it)) },
            )
            PasswordField(
                label = "Пароль внешнего SOCKS5",
                hint = "Зашифрован Android Keystore.",
                value = settings.upstreamPassword,
                enabled = enabled,
                onValueChange = { onSettingsChange(settings.copy(upstreamPassword = it)) },
            )
            Text(
                "При заполнении адреса трафик TUN пойдёт через внешний SOCKS5; встроенный сервер продолжит работать отдельно.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp,
                lineHeight = 16.sp,
            )
        }

        SettingsSection("DNS · ФЛАГИ РЕЗОЛВЕРА") {
            SettingsField(
                label = "Адрес DNS-сервера · --dns-host",
                value = settings.dnsHost,
                hint = "Адрес привязки встроенного DNS-сервера.",
                enabled = enabled,
                onValueChange = { onSettingsChange(settings.copy(dnsHost = it)) },
            )
            SettingsField(
                label = "Порт DNS · --dns-port",
                value = settings.dnsPort,
                hint = "UDP-порт 1–65535; по умолчанию 1053.",
                enabled = enabled,
                keyboardType = KeyboardType.Number,
                onValueChange = { onSettingsChange(settings.copy(dnsPort = it)) },
            )
            SettingsField(
                label = "DNS-upstream · --dns-upstream",
                value = settings.dnsUpstream,
                hint = "Например 1.1.1.1:53 или [2001:db8::1]:53.",
                enabled = enabled,
                onValueChange = { onSettingsChange(settings.copy(dnsUpstream = it)) },
            )
            SettingsField(
                label = "Fake-IP сеть · --fake-ip-range",
                value = settings.fakeIpRange,
                hint = "IPv4 CIDR, например 198.18.0.0/15.",
                enabled = enabled,
                onValueChange = { onSettingsChange(settings.copy(fakeIpRange = it)) },
            )
        }

        SettingsSection("ТРАНСПОРТ") {
            SwitchSetting(
                title = "UDP-over-TCP",
                description = "Передавать UDP-пакеты TUN по TCP-каналу ProxyDroid. Для внешнего SOCKS-сервера требуется поддержка расширения ProxyDroid.",
                checked = settings.udpOverTcp,
                enabled = enabled,
                onCheckedChange = { onSettingsChange(settings.copy(udpOverTcp = it)) },
            )
        }

        if (settings.hasNoAuthentication()) {
            InfoCard(
                if (settings.isExposedWithoutAuthentication()) {
                    "Безопасность: адрес прослушивания доступен по сети без пароля. Добавьте логин и пароль или верните 127.0.0.1."
                } else {
                    "Безопасность: даже слушатель на 127.0.0.1 может быть доступен другим приложениям на устройстве. Включите SOCKS5-авторизацию."
                },
                warning = true,
            )
        }

        Button(
            onClick = onSave,
            enabled = enabled && !saved,
            modifier = Modifier.fillMaxWidth().height(54.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            Text(if (saved) "Настройки сохранены" else "Сохранить настройки", fontWeight = FontWeight.Bold)
        }
        Text(
            "Пароль хранится в Android Keystore и не записывается в открытом виде в настройки приложения.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 12.sp,
            lineHeight = 18.sp,
            modifier = Modifier.padding(horizontal = 2.dp),
        )
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun SettingsSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                title,
                color = MaterialTheme.colorScheme.primary,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.2.sp,
            )
            Divider(color = Color(0xFF26364A))
            content()
        }
    }
}

@Composable
private fun SettingsField(
    label: String,
    value: String,
    hint: String,
    enabled: Boolean,
    keyboardType: KeyboardType = KeyboardType.Text,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    trailingContent: (@Composable () -> Unit)? = null,
    onValueChange: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(label, fontSize = 13.sp, fontWeight = FontWeight.Medium)
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier.fillMaxWidth(),
            enabled = enabled,
            singleLine = true,
            visualTransformation = visualTransformation,
            keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
            trailingIcon = trailingContent,
            supportingText = { Text(hint, fontSize = 11.sp, lineHeight = 15.sp) },
            shape = RoundedCornerShape(14.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = Color(0xFF34465B),
                disabledBorderColor = Color(0xFF26364A),
                focusedTextColor = MaterialTheme.colorScheme.onSurface,
                unfocusedTextColor = MaterialTheme.colorScheme.onSurface,
                disabledTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                focusedContainerColor = Color(0xFF0B1522),
                unfocusedContainerColor = Color(0xFF0B1522),
                disabledContainerColor = Color(0xFF0B1522),
            ),
        )
    }
}

@Composable
private fun PasswordField(
    value: String,
    enabled: Boolean,
    label: String = "Пароль · --password",
    hint: String = "При первом запуске пароль создаётся автоматически и хранится через Android Keystore.",
    onValueChange: (String) -> Unit,
) {
    var visible by rememberSaveable { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(label, fontSize = 13.sp, fontWeight = FontWeight.Medium)
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier.fillMaxWidth(),
            enabled = enabled,
            singleLine = true,
            visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                TextButton(onClick = { visible = !visible }, enabled = enabled) {
                    Text(if (visible) "Скрыть" else "Показать", fontSize = 11.sp)
                }
            },
            supportingText = { Text(hint, fontSize = 11.sp) },
            shape = RoundedCornerShape(14.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = Color(0xFF34465B),
                disabledBorderColor = Color(0xFF26364A),
                focusedTextColor = MaterialTheme.colorScheme.onSurface,
                unfocusedTextColor = MaterialTheme.colorScheme.onSurface,
                disabledTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                focusedContainerColor = Color(0xFF0B1522),
                unfocusedContainerColor = Color(0xFF0B1522),
                disabledContainerColor = Color(0xFF0B1522),
            ),
        )
    }
}

@Composable
private fun SwitchSetting(
    title: String,
    description: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .clickable(enabled = enabled) { onCheckedChange(!checked) }
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, fontSize = 13.sp, fontWeight = FontWeight.Medium)
            Text(
                description,
                fontSize = 11.sp,
                lineHeight = 16.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange, enabled = enabled)
    }
}

@Composable
private fun InfoCard(text: String, warning: Boolean = false) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = if (warning) Color(0xFF382525) else Color(0xFF132B34),
    ) {
        Text(
            text,
            modifier = Modifier.padding(14.dp),
            color = if (warning) Color(0xFFFFC2B8) else Color(0xFFB8E8E0),
            fontSize = 12.sp,
            lineHeight = 18.sp,
        )
    }
}
