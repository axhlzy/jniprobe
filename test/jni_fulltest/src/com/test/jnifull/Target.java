package com.test.jnifull;

public class Target {

    public int ifield = 11;
    public long lfield = 12L;
    public short sfield = 13;
    public byte bfield = 14;
    public char cfield = 'Z';
    public boolean zfield = true;
    public float ffield = 1.5f;
    public double dfield = 2.5;
    public String strfield = "inst";
    public Object objfield = "obj-inst";

    public static int sifield = 21;
    public static long slfield = 22L;
    public static short ssfield = 23;
    public static byte sbfield = 24;
    public static char scfield = 'Y';
    public static boolean szfield = false;
    public static float sffield = 3.5f;
    public static double sdffield = 4.5;
    public static String sstrfield = "static-str";
    public static Object sobjfield = "obj-static";

    public Target() {
    }

    public Target(int v) {
        this.ifield = v;
    }

    public Object getObjectR() {
        return objfield;
    }

    public boolean getBooleanR() {
        return zfield;
    }

    public byte getByteR() {
        return bfield;
    }

    public char getCharR() {
        return cfield;
    }

    public short getShortR() {
        return sfield;
    }

    public int getIntR() {
        return ifield;
    }

    public long getLongR() {
        return lfield;
    }

    public float getFloatR() {
        return ffield;
    }

    public double getDoubleR() {
        return dfield;
    }

    public void setIntV(int v) {
        this.ifield = v;
    }

    public void noop() {
    }

    public String virtualName() {
        return "Target.virtual";
    }

    public int addInts(int a, int b) {
        return a + b;
    }

    public synchronized void syncMethod() {
    }

    public static Object sGetObjectR() {
        return sobjfield;
    }

    public static boolean sGetBooleanR() {
        return szfield;
    }

    public static byte sGetByteR() {
        return sbfield;
    }

    public static char sGetCharR() {
        return scfield;
    }

    public static short sGetShortR() {
        return ssfield;
    }

    public static int sGetIntR() {
        return sifield;
    }

    public static long sGetLongR() {
        return slfield;
    }

    public static float sGetFloatR() {
        return sffield;
    }

    public static double sGetDoubleR() {
        return sdffield;
    }

    public static void sNoop() {
    }

    public static int sAdd(int a, int b) {
        return a + b;
    }

    @Override
    public String toString() {
        return "Target";
    }
}
