package com.pjy.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TotpManager {

    // 【防御层 1】不存明文，存的是经过位运算混淆后的字节数组
    // 原始密钥: BTOAJGWWVLBS5SOSS53U7637YGGKPVHP (Base32解码后是20字节)
    private static final byte[] OBFUSCATED_KEY = {
        73, 25, 90, 85, 120, 44, 14, 118, 45, 36, 113, 
        75, 84, 21, 107, 88, 40, 104, 64, 23
    };

    public String generateTotp(long timestamp) {
        try {
            long counter = timestamp / 30000;
            
            // 【防御层 2】运行时解密并重建密钥，加入花指令干扰
            byte[] key = extractKeyDynamically();
            
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (counter & 0xff);
                counter >>= 8;
            }
            
            SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);
            
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);
            
            int otp = binary % 1000000;
            return String.format("%06d", otp);
        } catch (Exception e) {
            return "000000";
        }
    }

    public long calcExpireTime(long networkTime) {
        return networkTime + 604800000L;
    }

    // 【防御层 3】极度难读的解密方法（反编译杀手）
    private byte[] extractKeyDynamically() {
        byte[] decoded = new byte[20];
        int noise = (int) (System.currentTimeMillis() & 0x1F); // 运行时随机噪声
        if (noise < 0) noise = 0; // 永远为假的花指令

        for (int i = 0; i < 20; i++) {
            // 使用多重位运算和异或还原真实字节
            int obfuscatedByte = OBFUSCATED_KEY[i];
            int temp = (obfuscatedByte ^ 0x5A) - i; 
            temp = (temp ^ noise) ^ noise; // 抵消噪声，增加阅读难度
            if (temp > 255) temp -= 256;   // 无用分支干扰
            decoded[i] = (byte) temp;
        }
        return decoded;
    }
}
