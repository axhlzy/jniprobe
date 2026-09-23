package com.test.jnifull;

public class Main {

    public static void main(String[] args) {
        System.out.println("==========================================================");
        System.out.println("[Java] JNI Full Coverage Test (app_process)");
        System.out.println("==========================================================");

        System.out.println("[Java] PID = " + currentPid() + "  (attach your tracer now)");
        System.out.flush();

        waitForAnyKey();

        System.out.println("[Java] java.vm.name   = " + System.getProperty("java.vm.name"));
        System.out.println("[Java] os.arch        = " + System.getProperty("os.arch"));

        String libPath = System.getenv("JNI_LIB_PATH");
        if (libPath == null || libPath.isEmpty()) {
            libPath = "/data/local/tmp/jnifull/libjnifull.so";
        }
        try {
            System.load(libPath);
            System.out.println("[Java] System.load(" + libPath + ") -> OK");
            NativeTest.deepCall();
        } catch (Throwable t) {
            System.out.println("[Java] System.load FAILED: " + t);
            t.printStackTrace();
            System.exit(2);
            return;
        }

        int errors = 0;

        try {
            System.out.println("[Java] nativeVersion()      = " + NativeTest.nativeVersion());
            expect("staticAdd", NativeTest.staticAdd(2, 3), 5);
            expect("staticHello", NativeTest.staticHello("java"), "hello java");
            int[] flipped = NativeTest.staticFlip(new int[]{1, 2, 3, 4});
            expect("staticFlip", java.util.Arrays.toString(flipped), "[4, 3, 2, 1]");
            expect("staticSum", NativeTest.staticSum(new long[]{10, 20, 30}), 60L);
            expect("dynAdd", NativeTest.dynAdd(40, 2), 42);
            expect("dynHello", NativeTest.dynHello("dyn"), "dyn-Ok");

            Object rt = new Object();
            expect("staticRoundTrip", NativeTest.staticRoundTrip(rt) == rt, true);

            try {
                NativeTest.staticThrow();
                System.out.println("[Java] staticThrow did NOT throw -> FAIL");
                errors++;
            } catch (IllegalStateException e) {
                System.out.println("[Java] staticThrow threw expected: " + e.getMessage());
            }
        } catch (Throwable t) {
            System.out.println("[Java] sanity calls failed:");
            t.printStackTrace();
            errors++;
        }

        int fails = NativeTest.runAll();
        int passes = NativeTest.getPassCount();
        int skips = NativeTest.getSkipCount();

        System.out.println("==========================================================");
        System.out.println("[Java] JNI table coverage: " + passes + " passed, "
                + fails + " failed, " + skips + " skipped");
        System.out.println("==========================================================");

        System.exit((fails + errors) == 0 ? 0 : 1);
    }

    private static void expect(String name, Object actual, Object expected) {
        boolean ok = (actual == null) ? expected == null : actual.equals(expected);
        System.out.println("[Java] " + name + " = " + actual + (ok ? "  ok" : "  MISMATCH expected " + expected));
    }

    private static String currentPid() {
        try {
            String p = new java.io.File("/proc/self").getCanonicalPath();
            int i = p.lastIndexOf('/');
            return (i >= 0) ? p.substring(i + 1) : p;
        } catch (Throwable t) {
            return "unknown";
        }
    }

    /** Block until the user presses a key (any byte, e.g. Enter) on stdin.
     *  Set JNI_NO_WAIT=1 to run unattended (CI). */
    private static void waitForAnyKey() {
        if (System.getenv("JNI_NO_WAIT") != null) {
            System.out.println("[Java] JNI_NO_WAIT set -> skipping key wait");
            return;
        }
        System.out.print("[Java] >>> Press any key (Enter) to start the test ... ");
        System.out.flush();
        try {
            int b = System.in.read();
            System.out.println();
            if (b < 0) {
                System.out.println("[Java] stdin closed, starting anyway");
            } else {
                System.out.println("[Java] key received (0x" + Integer.toHexString(b) + "), starting");
            }
        } catch (Throwable t) {
            System.out.println();
            System.out.println("[Java] stdin not readable (" + t + "), starting");
        }
        System.out.flush();
    }
}
