package com.plcoding.bluetoothchat.ui.theme

import Shapes
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme

import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = Purple200,
    secondary = Purple700,
    tertiary = Purple500
)

private val LightColorScheme = lightColorScheme(
    primary = Purple200,
    secondary = Purple700,
    tertiary = Purple500
)

@Composable
fun BluetoothChatTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) {
        DarkColorScheme
    } else {
        LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,

        shapes = Shapes,
        content = content
    )
}