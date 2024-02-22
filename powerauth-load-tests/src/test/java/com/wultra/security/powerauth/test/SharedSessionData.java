package com.wultra.security.powerauth.test;

import java.util.concurrent.ConcurrentHashMap;

public class SharedSessionData {
    public static ConcurrentHashMap<String, Object> transferVariable = new ConcurrentHashMap<>();
}
