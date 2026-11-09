package com.proxydroid

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow


data class ProxyRuntimeStatus(
    val active: Boolean = false,
    val message: String = "Отключено",
    val detail: String = "Нажмите «Подключить», чтобы создать TUN-интерфейс.",
)

object RuntimeState {
    private val mutableStatus = MutableStateFlow(ProxyRuntimeStatus())
    val status: StateFlow<ProxyRuntimeStatus> = mutableStatus.asStateFlow()

    fun update(status: ProxyRuntimeStatus) {
        mutableStatus.value = status
    }
}
