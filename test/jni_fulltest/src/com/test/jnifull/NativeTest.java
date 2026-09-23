package com.test.jnifull;

public class NativeTest {

    public static native int runAll();

    public static native int getPassCount();

    public static native int getFailCount();

    public static native int getSkipCount();

    public static native String nativeVersion();

    public static native void deepCall();

    public static native int staticAdd(int a, int b);

    public static native String staticHello(String name);

    public static native int[] staticFlip(int[] input);

    public static native long staticSum(long[] input);

    public static native void staticThrow() throws IllegalStateException;

    public static native Object staticRoundTrip(Object o);

    public static native int dynAdd(int a, int b);

    public static native String dynHello(String name);
}
