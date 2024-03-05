package com.wultra.security.powerauth.test.shared;

import java.util.concurrent.ConcurrentHashMap;

public class SharedSessionData {
    public static ConcurrentHashMap<String, Object> transferVariable = new ConcurrentHashMap<>();
}
