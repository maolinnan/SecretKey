package com.linnan.app;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import java.security.MessageDigest;

/**
 * time:2018/7/18 下午4:28
 * author:maolinnan
 * desc:this is SecreKey
 **/

public class SecreKey {
    static {
        System.loadLibrary("secrekey");
    }

    public static native boolean isPassVerify();


    public String getSignValidString(){
        try {
            Context context = App.get();
            String packageName = context.getPackageName();
            PackageManager packageManager= context.getPackageManager();
            PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 64);
            Signature signature = packageInfo.signatures[0];
            byte[] input = signature.toByteArray();

            MessageDigest localMessageDigest = MessageDigest.getInstance("MD5");
            localMessageDigest.update(input);
            byte[] paramArrayOfByte = localMessageDigest.digest();
            StringBuilder localStringBuilder = new StringBuilder(2 * paramArrayOfByte.length);
            for (int i = 0; i < paramArrayOfByte.length; i++) {
                String str = Integer.toString(0xFF & paramArrayOfByte[i], 16);
                if (str.length() == 1) {
                    str = "0" + str;
                }
                localStringBuilder.append(str);
            }
            return localStringBuilder.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }
}
