package com.pjy.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TotpManager {

    public String generateTotp(long timestamp) {
        try {
            long counter = timestamp / 30000;
            
            // 【防御】运行时动态生成真实密钥
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

    // 【防御层】将原密钥 BTOAJGWWVLBS5SOSS53U7637YGGKPVHP 拆成碎片
    // 这样别人在反编译工具里搜 "BTOA" 是绝对搜不到的
    private byte[] extractKeyDynamically() {
        String p1 = "BTO" + "AJG";
        String p2 = "WWV" + "LBS";
        String p3 = "5SO" + "SS5";
        String p4 = "3U7" + "637";
        String p5 = "YGG" + "KPV";
        String p6 = "HP";
        
        String base32Secret = p1 + p2 + p3 + p4 + p5 + p6;
        
        return base32Decode(base32Secret);
    }

    // 标准的 Base32 解码逻辑
    private byte[] base32Decode(String base32) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer = 0, bitsLeft = 0, count = 0;
        byte[] result = new byte[base32.length() * 5 / 8];
        for (char c : base32.toCharArray()) {
            int val = alphabet.indexOf(c);
            if (val < 0) continue;
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                result[count++] = (byte) (buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }
        byte[] exact = new byte[count];
        System.arraycopy(result, 0, exact, 0, count);
        return exact;
    }
}
