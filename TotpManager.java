package com.pjy.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TotpManager {
    private static final String BASE32_SECRET = "BTOAJGWWVLBS5SOSS53U7637YGGKPVHP";

    public String generateTotp(long timestamp) {
        try {
            long counter = timestamp / 30000;
            byte[] key = base32Decode(BASE32_SECRET);
            
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
        return networkTime + 604800000L; // 7天
    }

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
