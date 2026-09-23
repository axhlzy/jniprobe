package com.test.jnifull;

public class SubTarget extends Target {

    @Override
    public String virtualName() {
        return "Sub.virtual";
    }

    public String subOnly() {
        return "sub-only";
    }
}
