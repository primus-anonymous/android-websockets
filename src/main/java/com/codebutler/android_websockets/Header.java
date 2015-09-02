package com.codebutler.android_websockets;


public final class Header {
    private String name;

    private String value;

    public Header(String name, String value) {
        this.name = name;
        this.value = value;
    }
    
    public String getValue() {
        return value;
    }

    public String getName() {
        return name;
    }
}
