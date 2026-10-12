package io.github.guidin9.warpshot

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/** A device that another member added to the group (protocol §4.6). */
data class DeviceAlert(val id: String, val name: String, val platform: ULong, val byId: String, val byName: String)

/**
 * Open "new device" alerts. The core reports them (via [CoreObserver]) when the
 * membership log it pulls or syncs gains a device this phone didn't add; the
 * notification carries the same data, so a tap restores an alert after the
 * process was gone.
 */
object GroupAlerts {
    private const val EXTRA_ID = "alert_id"
    private const val EXTRA_NAME = "alert_name"
    private const val EXTRA_PLATFORM = "alert_platform"
    private const val EXTRA_BY_ID = "alert_by_id"
    private const val EXTRA_BY_NAME = "alert_by_name"

    private val _state = MutableStateFlow<List<DeviceAlert>>(emptyList())
    val state: StateFlow<List<DeviceAlert>> = _state

    fun add(a: DeviceAlert) = _state.update { l -> l.filter { it.id != a.id } + a }

    fun dismiss(ctx: Context, id: String) {
        _state.update { l -> l.filter { it.id != id } }
        Notifier.clearAlert(ctx, id)
    }

    fun intent(ctx: Context, a: DeviceAlert): Intent = Intent(ctx, MainActivity::class.java)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        .putExtra(EXTRA_ID, a.id)
        .putExtra(EXTRA_NAME, a.name)
        .putExtra(EXTRA_PLATFORM, a.platform.toLong())
        .putExtra(EXTRA_BY_ID, a.byId)
        .putExtra(EXTRA_BY_NAME, a.byName)

    /** Restores the alert a notification tap carries. */
    fun fromIntent(i: Intent?): DeviceAlert? {
        val id = i?.getStringExtra(EXTRA_ID) ?: return null
        return DeviceAlert(
            id,
            i.getStringExtra(EXTRA_NAME).orEmpty(),
            i.getLongExtra(EXTRA_PLATFORM, 0).toULong(),
            i.getStringExtra(EXTRA_BY_ID).orEmpty(),
            i.getStringExtra(EXTRA_BY_NAME).orEmpty(),
        )
    }
}

fun platformName(ctx: Context, platform: ULong): String = ctx.getString(
    when (platform) {
        1uL -> R.string.platform_windows
        2uL -> R.string.platform_android
        else -> R.string.platform_other
    },
)

/** "“Laptop” (Windows) was added by DESKTOP-7Q2L9." */
fun alertText(ctx: Context, a: DeviceAlert): String = if (a.byName.isEmpty()) {
    ctx.getString(R.string.alert_text_unknown, a.name, platformName(ctx, a.platform))
} else {
    ctx.getString(R.string.alert_text, a.name, platformName(ctx, a.platform), a.byName)
}

/**
 * "This wasn't me" (§4.6): removes the device with reason "not me", and the
 * device that added it too if the user ticks that box.
 */
@Composable
fun DeviceAlertDialog(alert: DeviceAlert, busy: Boolean, onNotMe: (alsoAdder: Boolean) -> Unit, onWasMe: () -> Unit) {
    val ctx = LocalContext.current
    var alsoAdder by remember(alert.id) { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = {},
        title = { Text(stringResource(R.string.alert_title)) },
        text = {
            Column {
                Text(alertText(ctx, alert), style = MaterialTheme.typography.bodyLarge)
                Spacer(Modifier.padding(top = 8.dp))
                Text(stringResource(R.string.alert_body))
                if (alert.byId.isNotEmpty() && alert.byName.isNotEmpty()) {
                    Row(
                        Modifier.fillMaxWidth().padding(top = 12.dp)
                            .toggleable(value = alsoAdder, role = Role.Checkbox) { alsoAdder = it },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(checked = alsoAdder, onCheckedChange = null)
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.alert_also_adder, alert.byName))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy,
                onClick = { onNotMe(alsoAdder) },
                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
            ) { Text(stringResource(R.string.alert_not_me)) }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onWasMe) { Text(stringResource(R.string.alert_was_me)) } },
    )
}
