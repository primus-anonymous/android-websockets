package com.codebutler.android_websockets;


final class StatusLine {
    private String message;

    private int code;

    StatusLine(String message, int code) {
        this.message = message;
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
