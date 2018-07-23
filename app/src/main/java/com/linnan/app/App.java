package com.linnan.app;

import android.app.Application;

/**
 * time:2018/7/18 下午5:34
 * author:maolinnan
 * desc:this is App
 **/

public class App extends Application {
    private static App instance;

    public static App get() {
        return instance;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
    }
}
