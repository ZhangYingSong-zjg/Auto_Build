package com.pjy.totp;

public class TotpManager {
    public native String generateTotp(long timestamp);
    public native long calcExpireTime(long networkTime);
}
