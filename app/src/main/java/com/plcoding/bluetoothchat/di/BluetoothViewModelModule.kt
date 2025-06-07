package com.plcoding.bluetoothchat.di

import androidx.compose.ui.input.key.Key
import androidx.lifecycle.ViewModel
import com.plcoding.bluetoothchat.presentation.BluetoothViewModel
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ViewModelComponent
import dagger.hilt.android.internal.lifecycle.HiltViewModelMap
import dagger.multibindings.IntoMap

@Module
@InstallIn(ViewModelComponent::class)
abstract class BluetoothViewModelModule {

    @Binds
    @IntoMap
    @ViewModelKey(BluetoothViewModel::class)
    abstract fun bindViewModel(viewModel: BluetoothViewModel): ViewModel
}