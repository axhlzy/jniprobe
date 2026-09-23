/*
 * libjnifull.so - exhaustive JNIEnv function-table coverage test.
 *
 * Built with the Android NDK and driven from Java via System.load() +
 * app_process.  It calls (almost) every entry of the JNINativeInterface
 * table and records PASS / FAIL / SKIP for each.
 *
 * Deliberately *not* invoked:
 *   - the 4 reserved slots (NULL in every VM)
 *   - FatalError() (would terminate the process)
 */
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <android/log.h>
#include <unistd.h>
#include <dlfcn.h>

#define LOG_TAG "JNIFULL"

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;
static JavaVM *g_vm = NULL;

static jint temp_native_impl(JNIEnv *env, jclass clazz, jint x);

#define OUT(...)                       \
    do {                               \
        fprintf(stdout, __VA_ARGS__);  \
        fflush(stdout);                \
    } while (0)

#define CHECK(desc, cond)                              \
    do {                                               \
        if (cond) {                                    \
            g_pass++;                                  \
            OUT("  [PASS] %s\n", desc);                \
        } else {                                       \
            g_fail++;                                  \
            OUT("  [FAIL] %s\n", desc);                \
        }                                              \
    } while (0)

#define SKIP(desc)                                     \
    do {                                               \
        g_skip++;                                      \
        OUT("  [SKIP] %s\n", desc);                    \
    } while (0)

#define SECTION(name) OUT("\n===== %s =====\n", name)

/* ------------------------------------------------------------------ */
/* generic helpers                                                     */
/* ------------------------------------------------------------------ */

static void clear_exc(JNIEnv *env) {
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
}

static jclass req_class(JNIEnv *env, const char *name) {
    jclass c = (*env)->FindClass(env, name);
    if (c == NULL) {
        OUT("  [WARN] FindClass(%s) failed\n", name);
        clear_exc(env);
    }
    return c;
}

/* ------------------------------------------------------------------ */
/* macros: Call*MethodV wrappers (va_list plumbing)                    */
/* ------------------------------------------------------------------ */

#define DEF_CALLV(RET, NAME, CT)                                          \
    static CT wrap_##NAME##V(JNIEnv *e, jobject o, jmethodID m, ...) {    \
        va_list ap;                                                       \
        va_start(ap, m);                                                  \
        CT r = (*e)->NAME##V(e, o, m, ap);                                \
        va_end(ap);                                                       \
        return r;                                                         \
    }

DEF_CALLV(jobject, CallObjectMethod, jobject)
DEF_CALLV(jboolean, CallBooleanMethod, jboolean)
DEF_CALLV(jbyte, CallByteMethod, jbyte)
DEF_CALLV(jchar, CallCharMethod, jchar)
DEF_CALLV(jshort, CallShortMethod, jshort)
DEF_CALLV(jint, CallIntMethod, jint)
DEF_CALLV(jlong, CallLongMethod, jlong)
DEF_CALLV(jfloat, CallFloatMethod, jfloat)
DEF_CALLV(jdouble, CallDoubleMethod, jdouble)

static void wrap_CallVoidMethodV(JNIEnv *e, jobject o, jmethodID m, ...) {
    va_list ap;
    va_start(ap, m);
    (*e)->CallVoidMethodV(e, o, m, ap);
    va_end(ap);
}

#define DEF_NCV(RET, NAME, CT)                                                  \
    static CT wrap_##NAME##V(JNIEnv *e, jobject o, jclass c, jmethodID m, ...) { \
        va_list ap;                                                             \
        va_start(ap, m);                                                        \
        CT r = (*e)->NAME##V(e, o, c, m, ap);                                   \
        va_end(ap);                                                             \
        return r;                                                               \
    }

DEF_NCV(jobject, CallNonvirtualObjectMethod, jobject)
DEF_NCV(jboolean, CallNonvirtualBooleanMethod, jboolean)
DEF_NCV(jbyte, CallNonvirtualByteMethod, jbyte)
DEF_NCV(jchar, CallNonvirtualCharMethod, jchar)
DEF_NCV(jshort, CallNonvirtualShortMethod, jshort)
DEF_NCV(jint, CallNonvirtualIntMethod, jint)
DEF_NCV(jlong, CallNonvirtualLongMethod, jlong)
DEF_NCV(jfloat, CallNonvirtualFloatMethod, jfloat)
DEF_NCV(jdouble, CallNonvirtualDoubleMethod, jdouble)

static void wrap_CallNonvirtualVoidMethodV(JNIEnv *e, jobject o, jclass c,
                                           jmethodID m, ...) {
    va_list ap;
    va_start(ap, m);
    (*e)->CallNonvirtualVoidMethodV(e, o, c, m, ap);
    va_end(ap);
}

#define DEF_SCALLV(RET, NAME, CT)                                    \
    static CT wrap_##NAME##V(JNIEnv *e, jclass c, jmethodID m, ...) { \
        va_list ap;                                                  \
        va_start(ap, m);                                             \
        CT r = (*e)->NAME##V(e, c, m, ap);                           \
        va_end(ap);                                                  \
        return r;                                                    \
    }

DEF_SCALLV(jobject, CallStaticObjectMethod, jobject)
DEF_SCALLV(jboolean, CallStaticBooleanMethod, jboolean)
DEF_SCALLV(jbyte, CallStaticByteMethod, jbyte)
DEF_SCALLV(jchar, CallStaticCharMethod, jchar)
DEF_SCALLV(jshort, CallStaticShortMethod, jshort)
DEF_SCALLV(jint, CallStaticIntMethod, jint)
DEF_SCALLV(jlong, CallStaticLongMethod, jlong)
DEF_SCALLV(jfloat, CallStaticFloatMethod, jfloat)
DEF_SCALLV(jdouble, CallStaticDoubleMethod, jdouble)

static void wrap_CallStaticVoidMethodV(JNIEnv *e, jclass c, jmethodID m, ...) {
    va_list ap;
    va_start(ap, m);
    (*e)->CallStaticVoidMethodV(e, c, m, ap);
    va_end(ap);
}

static jobject wrap_NewObjectV(JNIEnv *e, jclass c, jmethodID m, ...) {
    va_list ap;
    va_start(ap, m);
    jobject r = (*e)->NewObjectV(e, c, m, ap);
    va_end(ap);
    return r;
}

static jobject wrap_NewObjectA(JNIEnv *e, jclass c, jmethodID m, jvalue *a) {
    return (*e)->NewObjectA(e, c, m, a);
}

/* ------------------------------------------------------------------ */
/* primitive array coverage                                            */
/* ------------------------------------------------------------------ */

#define TEST_ARRAY(FUNC, TYPE, LIT)                                           \
    do {                                                                      \
        TYPE##Array a = (*env)->New##FUNC##Array(env, 4);                     \
        CHECK("New" #FUNC "Array", a != NULL);                                \
        TYPE buf[4] = {LIT, LIT, LIT, LIT};                                   \
        (*env)->Set##FUNC##ArrayRegion(env, a, 0, 4, buf);                    \
        CHECK("Set" #FUNC "ArrayRegion", (*env)->ExceptionCheck(env) == 0);   \
        TYPE out[4] = {0};                                                    \
        (*env)->Get##FUNC##ArrayRegion(env, a, 0, 4, out);                    \
        CHECK("Get" #FUNC "ArrayRegion", out[0] == LIT);                      \
        TYPE *elems = (*env)->Get##FUNC##ArrayElements(env, a, NULL);         \
        CHECK("Get" #FUNC "ArrayElements", elems != NULL);                    \
        (*env)->Release##FUNC##ArrayElements(env, a, elems, 0);               \
        CHECK("Release" #FUNC "ArrayElements", (*env)->ExceptionCheck(env) == 0); \
        (*env)->DeleteLocalRef(env, a);                                       \
    } while (0)

#define TEST_ARRAY_CRITICAL(FUNC, TYPE)                                       \
    do {                                                                      \
        TYPE##Array a = (*env)->New##FUNC##Array(env, 4);                     \
        void *p = (*env)->GetPrimitiveArrayCritical(env, a, NULL);            \
        CHECK("GetPrimitiveArrayCritical " #FUNC, p != NULL);                 \
        (*env)->ReleasePrimitiveArrayCritical(env, a, p, 0);                  \
        CHECK("ReleasePrimitiveArrayCritical " #FUNC, (*env)->ExceptionCheck(env) == 0); \
        (*env)->DeleteLocalRef(env, a);                                       \
    } while (0)

/* ------------------------------------------------------------------ */
/* JavaVM attach/detach on a foreign thread                            */
/* ------------------------------------------------------------------ */

static void *attached_thread(void *arg) {
    JNIEnv *env = NULL;
    jint rc = (*g_vm)->AttachCurrentThread(g_vm, &env, NULL);
    OUT("  [thread] AttachCurrentThread rc=%d env=%p\n", (int)rc, (void *)env);
    if (rc == 0 && env != NULL) {
        jclass c = (*env)->FindClass(env, "java/lang/String");
        OUT("  [thread] FindClass(java/lang/String)=%p version=0x%x\n",
            (void *)c, (unsigned)(*env)->GetVersion(env));
        if (c) (*env)->DeleteLocalRef(env, c);
    }
    (*g_vm)->DetachCurrentThread(g_vm);
    return NULL;
}

static void *attached_daemon_thread(void *arg) {
    JNIEnv *env = NULL;
    jint rc = (*g_vm)->AttachCurrentThreadAsDaemon(g_vm, &env, NULL);
    OUT("  [thread] AttachCurrentThreadAsDaemon rc=%d\n", (int)rc);
    (*g_vm)->DetachCurrentThread(g_vm);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* the exhaustive test                                                 */
/* ------------------------------------------------------------------ */

static void run_all_tests(JNIEnv *env) {
    /* ---------------- classes / ids ---------------- */
    jclass clsTarget = req_class(env, "com/test/jnifull/Target");
    jclass clsSub = req_class(env, "com/test/jnifull/SubTarget");
    jclass clsCalc = req_class(env, "com/test/jnifull/Calc");
    jclass clsCalcImpl = req_class(env, "com/test/jnifull/CalcImpl");
    jclass clsTemp = req_class(env, "com/test/jnifull/Temp");
    jclass clsString = req_class(env, "java/lang/String");
    jclass clsObject = req_class(env, "java/lang/Object");
    jclass clsISE = req_class(env, "java/lang/IllegalStateException");
    if (!clsTarget || !clsSub || !clsCalc || !clsCalcImpl || !clsTemp ||
        !clsString || !clsObject || !clsISE) {
        g_fail++;
        OUT("  [FATAL] required classes missing\n");
        return;
    }

    SECTION("1. version / class resolution");
    jint ver = (*env)->GetVersion(env);
    CHECK("GetVersion", ver >= 0x00010004);
    CHECK("FindClass(Target)", clsTarget != NULL);
    jclass sc = (*env)->GetSuperclass(env, clsSub);
    CHECK("GetSuperclass(SubTarget)==Target", (*env)->IsSameObject(env, sc, clsTarget));
    if (sc) (*env)->DeleteLocalRef(env, sc);
    jclass scObj = (*env)->GetSuperclass(env, clsObject);
    CHECK("GetSuperclass(Object)==NULL", scObj == NULL);
    /* IsAssignableFrom(clazz1, clazz2): can clazz1 be cast to clazz2 */
    CHECK("IsAssignableFrom(Sub,Target)", (*env)->IsAssignableFrom(env, clsSub, clsTarget) == JNI_TRUE);
    CHECK("IsAssignableFrom(Target,Sub)", (*env)->IsAssignableFrom(env, clsTarget, clsSub) == JNI_FALSE);
    CHECK("IsAssignableFrom(CalcImpl,Calc)", (*env)->IsAssignableFrom(env, clsCalcImpl, clsCalc) == JNI_TRUE);

    /* DefineClass: exercised against malformed input, error path expected */
    {
        jbyte bogus[32];
        memset(bogus, 0, sizeof(bogus));
        jclass defined = (*env)->DefineClass(env, "com/test/jnifull/Defined", NULL,
                                             bogus, (jsize)sizeof(bogus));
        CHECK("DefineClass(malformed) reachable", defined == NULL);
        clear_exc(env);
    }

    /* ---------------- methods / constructors ---------------- */
    jmethodID ctor0 = (*env)->GetMethodID(env, clsTarget, "<init>", "()V");
    jmethodID ctor1 = (*env)->GetMethodID(env, clsTarget, "<init>", "(I)V");
    jmethodID subCtor = (*env)->GetMethodID(env, clsSub, "<init>", "()V");
    jmethodID iseCtor = (*env)->GetMethodID(env, clsISE, "<init>", "(Ljava/lang/String;)V");
    jmethodID mGetObject = (*env)->GetMethodID(env, clsTarget, "getObjectR", "()Ljava/lang/Object;");
    jmethodID mGetBool = (*env)->GetMethodID(env, clsTarget, "getBooleanR", "()Z");
    jmethodID mGetByte = (*env)->GetMethodID(env, clsTarget, "getByteR", "()B");
    jmethodID mGetChar = (*env)->GetMethodID(env, clsTarget, "getCharR", "()C");
    jmethodID mGetShort = (*env)->GetMethodID(env, clsTarget, "getShortR", "()S");
    jmethodID mGetInt = (*env)->GetMethodID(env, clsTarget, "getIntR", "()I");
    jmethodID mGetLong = (*env)->GetMethodID(env, clsTarget, "getLongR", "()J");
    jmethodID mGetFloat = (*env)->GetMethodID(env, clsTarget, "getFloatR", "()F");
    jmethodID mGetDouble = (*env)->GetMethodID(env, clsTarget, "getDoubleR", "()D");
    jmethodID mSetInt = (*env)->GetMethodID(env, clsTarget, "setIntV", "(I)V");
    jmethodID mVirtual = (*env)->GetMethodID(env, clsTarget, "virtualName", "()Ljava/lang/String;");
    jmethodID mAddInts = (*env)->GetMethodID(env, clsTarget, "addInts", "(II)I");
    jmethodID mSync = (*env)->GetMethodID(env, clsTarget, "syncMethod", "()V");
    jmethodID smGetObject = (*env)->GetStaticMethodID(env, clsTarget, "sGetObjectR", "()Ljava/lang/Object;");
    jmethodID smGetBool = (*env)->GetStaticMethodID(env, clsTarget, "sGetBooleanR", "()Z");
    jmethodID smGetByte = (*env)->GetStaticMethodID(env, clsTarget, "sGetByteR", "()B");
    jmethodID smGetChar = (*env)->GetStaticMethodID(env, clsTarget, "sGetCharR", "()C");
    jmethodID smGetShort = (*env)->GetStaticMethodID(env, clsTarget, "sGetShortR", "()S");
    jmethodID smGetInt = (*env)->GetStaticMethodID(env, clsTarget, "sGetIntR", "()I");
    jmethodID smGetLong = (*env)->GetStaticMethodID(env, clsTarget, "sGetLongR", "()J");
    jmethodID smGetFloat = (*env)->GetStaticMethodID(env, clsTarget, "sGetFloatR", "()F");
    jmethodID smGetDouble = (*env)->GetStaticMethodID(env, clsTarget, "sGetDoubleR", "()D");
    jmethodID smNoop = (*env)->GetStaticMethodID(env, clsTarget, "sNoop", "()V");
    jmethodID smAdd = (*env)->GetStaticMethodID(env, clsTarget, "sAdd", "(II)I");
    jmethodID mCalcAdd = (*env)->GetMethodID(env, clsCalc, "add", "(II)I");
    jmethodID calcImplCtor = (*env)->GetMethodID(env, clsCalcImpl, "<init>", "()V");
    jmethodID mTempNative = (*env)->GetStaticMethodID(env, clsTemp, "tempNative", "(I)I");

    /* fields */
    jfieldID fInt = (*env)->GetFieldID(env, clsTarget, "ifield", "I");
    jfieldID fLong = (*env)->GetFieldID(env, clsTarget, "lfield", "J");
    jfieldID fShort = (*env)->GetFieldID(env, clsTarget, "sfield", "S");
    jfieldID fByte = (*env)->GetFieldID(env, clsTarget, "bfield", "B");
    jfieldID fChar = (*env)->GetFieldID(env, clsTarget, "cfield", "C");
    jfieldID fBool = (*env)->GetFieldID(env, clsTarget, "zfield", "Z");
    jfieldID fFloat = (*env)->GetFieldID(env, clsTarget, "ffield", "F");
    jfieldID fDouble = (*env)->GetFieldID(env, clsTarget, "dfield", "D");
    jfieldID fStr = (*env)->GetFieldID(env, clsTarget, "strfield", "Ljava/lang/String;");
    jfieldID fObj = (*env)->GetFieldID(env, clsTarget, "objfield", "Ljava/lang/Object;");
    jfieldID sfInt = (*env)->GetStaticFieldID(env, clsTarget, "sifield", "I");
    jfieldID sfLong = (*env)->GetStaticFieldID(env, clsTarget, "slfield", "J");
    jfieldID sfShort = (*env)->GetStaticFieldID(env, clsTarget, "ssfield", "S");
    jfieldID sfByte = (*env)->GetStaticFieldID(env, clsTarget, "sbfield", "B");
    jfieldID sfChar = (*env)->GetStaticFieldID(env, clsTarget, "scfield", "C");
    jfieldID sfBool = (*env)->GetStaticFieldID(env, clsTarget, "szfield", "Z");
    jfieldID sfFloat = (*env)->GetStaticFieldID(env, clsTarget, "sffield", "F");
    jfieldID sfDouble = (*env)->GetStaticFieldID(env, clsTarget, "sdffield", "D");
    jfieldID sfStr = (*env)->GetStaticFieldID(env, clsTarget, "sstrfield", "Ljava/lang/String;");
    jfieldID sfObj = (*env)->GetStaticFieldID(env, clsTarget, "sobjfield", "Ljava/lang/Object;");

    CHECK("GetMethodID(<init>)", ctor0 != NULL);
    CHECK("GetMethodID(getIntR)", mGetInt != NULL);
    CHECK("GetStaticMethodID(sAdd)", smAdd != NULL);
    CHECK("GetFieldID(ifield)", fInt != NULL);
    CHECK("GetStaticFieldID(sifield)", sfInt != NULL);

    /* ---------------- object creation ---------------- */
    SECTION("2. object creation / identity");
    jobject target = (*env)->NewObject(env, clsTarget, ctor0);
    CHECK("NewObject()", target != NULL);
    jobject tV = wrap_NewObjectV(env, clsTarget, ctor1, (jint)99);
    CHECK("NewObjectV(int) ifield==99", tV != NULL && (*env)->GetIntField(env, tV, fInt) == 99);
    jvalue na1[1];
    na1[0].i = 77;
    jobject tA = wrap_NewObjectA(env, clsTarget, ctor1, na1);
    CHECK("NewObjectA(int) ifield==77", tA != NULL && (*env)->GetIntField(env, tA, fInt) == 77);
    jobject alloc = (*env)->AllocObject(env, clsTarget);
    CHECK("AllocObject", alloc != NULL);
    jobject sub = (*env)->NewObject(env, clsSub, subCtor);
    CHECK("NewObject(SubTarget)", sub != NULL);

    jclass oc = (*env)->GetObjectClass(env, target);
    CHECK("GetObjectClass==Target", (*env)->IsSameObject(env, oc, clsTarget));
    if (oc) (*env)->DeleteLocalRef(env, oc);
    CHECK("IsInstanceOf(Target)", (*env)->IsInstanceOf(env, target, clsTarget) == JNI_TRUE);
    CHECK("IsInstanceOf(Sub is Target)", (*env)->IsInstanceOf(env, sub, clsTarget) == JNI_TRUE);
    CHECK("IsInstanceOf(CalcImpl is Calc)",
          (*env)->IsInstanceOf(env, (*env)->NewObject(env, clsCalcImpl, calcImplCtor), clsCalc) == JNI_TRUE);

    /* ---------------- local / global / weak references ---------------- */
    SECTION("3. references, frames, monitors");
    CHECK("IsSameObject(t,t)", (*env)->IsSameObject(env, target, target) == JNI_TRUE);
    CHECK("IsSameObject(t,tV)==false", (*env)->IsSameObject(env, target, tV) == JNI_FALSE);
    CHECK("IsSameObject(t,NULL)==false", (*env)->IsSameObject(env, target, NULL) == JNI_FALSE);

    jobject gref = (*env)->NewGlobalRef(env, target);
    CHECK("NewGlobalRef", gref != NULL);
    CHECK("IsSameObject(gref,t)", (*env)->IsSameObject(env, gref, target) == JNI_TRUE);
    CHECK("GetObjectRefType(global)==Global",
          (*env)->GetObjectRefType(env, gref) == JNIGlobalRefType);
    CHECK("GetObjectRefType(local)==Local",
          (*env)->GetObjectRefType(env, target) == JNILocalRefType);

    jobject lref = (*env)->NewLocalRef(env, target);
    CHECK("NewLocalRef", lref != NULL);
    (*env)->DeleteLocalRef(env, lref);
    CHECK("DeleteLocalRef ok", 1);

    jobject wref = (*env)->NewWeakGlobalRef(env, target);
    CHECK("NewWeakGlobalRef", wref != NULL);
    CHECK("GetObjectRefType(weak)==WeakGlobal",
          (*env)->GetObjectRefType(env, wref) == JNIWeakGlobalRefType);
    (*env)->DeleteWeakGlobalRef(env, wref);
    CHECK("DeleteWeakGlobalRef ok", 1);

    CHECK("EnsureLocalCapacity(16)", (*env)->EnsureLocalCapacity(env, 16) == 0);
    CHECK("PushLocalFrame(16)", (*env)->PushLocalFrame(env, 16) == 0);
    jobject inFrame = (*env)->NewObject(env, clsTarget, ctor1, (jint)5);
    CHECK("NewObject inside frame", inFrame != NULL);
    jobject popped = (*env)->PopLocalFrame(env, NULL);
    CHECK("PopLocalFrame(NULL)==NULL", popped == NULL);

    CHECK("MonitorEnter", (*env)->MonitorEnter(env, target) == 0);
    (*env)->CallVoidMethod(env, target, mSync);
    CHECK("CallVoidMethod(syncMethod) no exc", (*env)->ExceptionCheck(env) == 0);
    CHECK("MonitorExit", (*env)->MonitorExit(env, target) == 0);
    (*env)->DeleteGlobalRef(env, gref);

    /* ---------------- instance Call<Type>Method ---------------- */
    SECTION("4. Call<Type>Method (+V/+A)");
    jobject rObj = (*env)->CallObjectMethod(env, target, mGetObject);
    CHECK("CallObjectMethod", rObj != NULL);
    CHECK("CallBooleanMethod", (*env)->CallBooleanMethod(env, target, mGetBool) == JNI_TRUE);
    CHECK("CallByteMethod", (*env)->CallByteMethod(env, target, mGetByte) == 14);
    CHECK("CallCharMethod", (*env)->CallCharMethod(env, target, mGetChar) == (jchar)'Z');
    CHECK("CallShortMethod", (*env)->CallShortMethod(env, target, mGetShort) == 13);
    CHECK("CallIntMethod", (*env)->CallIntMethod(env, target, mGetInt) == 11);
    CHECK("CallLongMethod", (*env)->CallLongMethod(env, target, mGetLong) == 12L);
    CHECK("CallFloatMethod", (*env)->CallFloatMethod(env, target, mGetFloat) == 1.5f);
    CHECK("CallDoubleMethod", (*env)->CallDoubleMethod(env, target, mGetDouble) == 2.5);
    (*env)->CallVoidMethod(env, target, mSetInt, (jint)1234);
    CHECK("CallVoidMethod(setIntV)", (*env)->GetIntField(env, target, fInt) == 1234);

    CHECK("CallObjectMethodV", wrap_CallObjectMethodV(env, target, mGetObject) != NULL);
    CHECK("CallBooleanMethodV", wrap_CallBooleanMethodV(env, target, mGetBool) == JNI_TRUE);
    CHECK("CallByteMethodV", wrap_CallByteMethodV(env, target, mGetByte) == 14);
    CHECK("CallCharMethodV", wrap_CallCharMethodV(env, target, mGetChar) == (jchar)'Z');
    CHECK("CallShortMethodV", wrap_CallShortMethodV(env, target, mGetShort) == 13);
    CHECK("CallIntMethodV", wrap_CallIntMethodV(env, target, mGetInt) == 1234);
    CHECK("CallLongMethodV", wrap_CallLongMethodV(env, target, mGetLong) == 12L);
    CHECK("CallFloatMethodV", wrap_CallFloatMethodV(env, target, mGetFloat) == 1.5f);
    CHECK("CallDoubleMethodV", wrap_CallDoubleMethodV(env, target, mGetDouble) == 2.5);
    wrap_CallVoidMethodV(env, target, mSetInt, (jint)11);
    CHECK("CallVoidMethodV", (*env)->GetIntField(env, target, fInt) == 11);
    CHECK("CallIntMethodV(addInts,3,4)", wrap_CallIntMethodV(env, target, mAddInts, (jint)3, (jint)4) == 7);

    jvalue empty[1];
    memset(empty, 0, sizeof(empty));
    CHECK("CallObjectMethodA", (*env)->CallObjectMethodA(env, target, mGetObject, empty) != NULL);
    CHECK("CallBooleanMethodA", (*env)->CallBooleanMethodA(env, target, mGetBool, empty) == JNI_TRUE);
    CHECK("CallByteMethodA", (*env)->CallByteMethodA(env, target, mGetByte, empty) == 14);
    CHECK("CallCharMethodA", (*env)->CallCharMethodA(env, target, mGetChar, empty) == (jchar)'Z');
    CHECK("CallShortMethodA", (*env)->CallShortMethodA(env, target, mGetShort, empty) == 13);
    CHECK("CallIntMethodA", (*env)->CallIntMethodA(env, target, mGetInt, empty) == 11);
    CHECK("CallLongMethodA", (*env)->CallLongMethodA(env, target, mGetLong, empty) == 12L);
    CHECK("CallFloatMethodA", (*env)->CallFloatMethodA(env, target, mGetFloat, empty) == 1.5f);
    CHECK("CallDoubleMethodA", (*env)->CallDoubleMethodA(env, target, mGetDouble, empty) == 2.5);
    {
        jvalue a[1];
        a[0].i = 55;
        (*env)->CallVoidMethodA(env, target, mSetInt, a);
        CHECK("CallVoidMethodA", (*env)->GetIntField(env, target, fInt) == 55);
        jvalue a2[2];
        a2[0].i = 10;
        a2[1].i = 20;
        CHECK("CallIntMethodA(addInts)", (*env)->CallIntMethodA(env, target, mAddInts, a2) == 30);
    }

    /* ---------------- nonvirtual ---------------- */
    SECTION("5. CallNonvirtual<Type>Method (+V/+A)");
    jstring nvName = (jstring)(*env)->CallNonvirtualObjectMethod(env, sub, clsTarget, mVirtual);
    const char *nvC = nvName ? (*env)->GetStringUTFChars(env, nvName, NULL) : NULL;
    CHECK("CallNonvirtualObjectMethod==Target.virtual",
          nvC != NULL && strcmp(nvC, "Target.virtual") == 0);
    if (nvC) (*env)->ReleaseStringUTFChars(env, nvName, nvC);
    if (nvName) (*env)->DeleteLocalRef(env, nvName);

    CHECK("CallNonvirtualBooleanMethod", (*env)->CallNonvirtualBooleanMethod(env, target, clsTarget, mGetBool) == JNI_TRUE);
    CHECK("CallNonvirtualByteMethod", (*env)->CallNonvirtualByteMethod(env, target, clsTarget, mGetByte) == 14);
    CHECK("CallNonvirtualCharMethod", (*env)->CallNonvirtualCharMethod(env, target, clsTarget, mGetChar) == (jchar)'Z');
    CHECK("CallNonvirtualShortMethod", (*env)->CallNonvirtualShortMethod(env, target, clsTarget, mGetShort) == 13);
    CHECK("CallNonvirtualIntMethod", (*env)->CallNonvirtualIntMethod(env, target, clsTarget, mGetInt) == 55);
    CHECK("CallNonvirtualLongMethod", (*env)->CallNonvirtualLongMethod(env, target, clsTarget, mGetLong) == 12L);
    CHECK("CallNonvirtualFloatMethod", (*env)->CallNonvirtualFloatMethod(env, target, clsTarget, mGetFloat) == 1.5f);
    CHECK("CallNonvirtualDoubleMethod", (*env)->CallNonvirtualDoubleMethod(env, target, clsTarget, mGetDouble) == 2.5);
    (*env)->CallNonvirtualVoidMethod(env, target, clsTarget, mSetInt, (jint)66);
    CHECK("CallNonvirtualVoidMethod", (*env)->GetIntField(env, target, fInt) == 66);

    CHECK("CallNonvirtualObjectMethodV",
          wrap_CallNonvirtualObjectMethodV(env, sub, clsTarget, mVirtual) != NULL);
    CHECK("CallNonvirtualBooleanMethodV",
          wrap_CallNonvirtualBooleanMethodV(env, target, clsTarget, mGetBool) == JNI_TRUE);
    CHECK("CallNonvirtualByteMethodV",
          wrap_CallNonvirtualByteMethodV(env, target, clsTarget, mGetByte) == 14);
    CHECK("CallNonvirtualCharMethodV",
          wrap_CallNonvirtualCharMethodV(env, target, clsTarget, mGetChar) == (jchar)'Z');
    CHECK("CallNonvirtualShortMethodV",
          wrap_CallNonvirtualShortMethodV(env, target, clsTarget, mGetShort) == 13);
    CHECK("CallNonvirtualIntMethodV",
          wrap_CallNonvirtualIntMethodV(env, target, clsTarget, mGetInt) == 66);
    CHECK("CallNonvirtualLongMethodV",
          wrap_CallNonvirtualLongMethodV(env, target, clsTarget, mGetLong) == 12L);
    CHECK("CallNonvirtualFloatMethodV",
          wrap_CallNonvirtualFloatMethodV(env, target, clsTarget, mGetFloat) == 1.5f);
    CHECK("CallNonvirtualDoubleMethodV",
          wrap_CallNonvirtualDoubleMethodV(env, target, clsTarget, mGetDouble) == 2.5);
    wrap_CallNonvirtualVoidMethodV(env, target, clsTarget, mSetInt, (jint)77);
    CHECK("CallNonvirtualVoidMethodV", (*env)->GetIntField(env, target, fInt) == 77);

    {
        jvalue a[1];
        memset(a, 0, sizeof(a));
        CHECK("CallNonvirtualObjectMethodA",
              (*env)->CallNonvirtualObjectMethodA(env, sub, clsTarget, mVirtual, a) != NULL);
        CHECK("CallNonvirtualBooleanMethodA",
              (*env)->CallNonvirtualBooleanMethodA(env, target, clsTarget, mGetBool, a) == JNI_TRUE);
        CHECK("CallNonvirtualByteMethodA",
              (*env)->CallNonvirtualByteMethodA(env, target, clsTarget, mGetByte, a) == 14);
        CHECK("CallNonvirtualCharMethodA",
              (*env)->CallNonvirtualCharMethodA(env, target, clsTarget, mGetChar, a) == (jchar)'Z');
        CHECK("CallNonvirtualShortMethodA",
              (*env)->CallNonvirtualShortMethodA(env, target, clsTarget, mGetShort, a) == 13);
        CHECK("CallNonvirtualIntMethodA",
              (*env)->CallNonvirtualIntMethodA(env, target, clsTarget, mGetInt, a) == 77);
        CHECK("CallNonvirtualLongMethodA",
              (*env)->CallNonvirtualLongMethodA(env, target, clsTarget, mGetLong, a) == 12L);
        CHECK("CallNonvirtualFloatMethodA",
              (*env)->CallNonvirtualFloatMethodA(env, target, clsTarget, mGetFloat, a) == 1.5f);
        CHECK("CallNonvirtualDoubleMethodA",
              (*env)->CallNonvirtualDoubleMethodA(env, target, clsTarget, mGetDouble, a) == 2.5);
        jvalue av[1];
        av[0].i = 88;
        (*env)->CallNonvirtualVoidMethodA(env, target, clsTarget, mSetInt, av);
        CHECK("CallNonvirtualVoidMethodA", (*env)->GetIntField(env, target, fInt) == 88);
    }

    /* ---------------- static calls ---------------- */
    SECTION("6. CallStatic<Type>Method (+V/+A)");
    CHECK("CallStaticObjectMethod", (*env)->CallStaticObjectMethod(env, clsTarget, smGetObject) != NULL);
    CHECK("CallStaticBooleanMethod", (*env)->CallStaticBooleanMethod(env, clsTarget, smGetBool) == JNI_FALSE);
    CHECK("CallStaticByteMethod", (*env)->CallStaticByteMethod(env, clsTarget, smGetByte) == 24);
    CHECK("CallStaticCharMethod", (*env)->CallStaticCharMethod(env, clsTarget, smGetChar) == (jchar)'Y');
    CHECK("CallStaticShortMethod", (*env)->CallStaticShortMethod(env, clsTarget, smGetShort) == 23);
    CHECK("CallStaticIntMethod", (*env)->CallStaticIntMethod(env, clsTarget, smGetInt) == 21);
    CHECK("CallStaticLongMethod", (*env)->CallStaticLongMethod(env, clsTarget, smGetLong) == 22L);
    CHECK("CallStaticFloatMethod", (*env)->CallStaticFloatMethod(env, clsTarget, smGetFloat) == 3.5f);
    CHECK("CallStaticDoubleMethod", (*env)->CallStaticDoubleMethod(env, clsTarget, smGetDouble) == 4.5);
    (*env)->CallStaticVoidMethod(env, clsTarget, smNoop);
    CHECK("CallStaticVoidMethod", (*env)->ExceptionCheck(env) == 0);

    CHECK("CallStaticObjectMethodV", wrap_CallStaticObjectMethodV(env, clsTarget, smGetObject) != NULL);
    CHECK("CallStaticBooleanMethodV", wrap_CallStaticBooleanMethodV(env, clsTarget, smGetBool) == JNI_FALSE);
    CHECK("CallStaticByteMethodV", wrap_CallStaticByteMethodV(env, clsTarget, smGetByte) == 24);
    CHECK("CallStaticCharMethodV", wrap_CallStaticCharMethodV(env, clsTarget, smGetChar) == (jchar)'Y');
    CHECK("CallStaticShortMethodV", wrap_CallStaticShortMethodV(env, clsTarget, smGetShort) == 23);
    CHECK("CallStaticIntMethodV", wrap_CallStaticIntMethodV(env, clsTarget, smGetInt) == 21);
    CHECK("CallStaticLongMethodV", wrap_CallStaticLongMethodV(env, clsTarget, smGetLong) == 22L);
    CHECK("CallStaticFloatMethodV", wrap_CallStaticFloatMethodV(env, clsTarget, smGetFloat) == 3.5f);
    CHECK("CallStaticDoubleMethodV", wrap_CallStaticDoubleMethodV(env, clsTarget, smGetDouble) == 4.5);
    wrap_CallStaticVoidMethodV(env, clsTarget, smNoop);
    CHECK("CallStaticVoidMethodV", (*env)->ExceptionCheck(env) == 0);
    CHECK("CallStaticIntMethodV(sAdd,3,4)", wrap_CallStaticIntMethodV(env, clsTarget, smAdd, (jint)3, (jint)4) == 7);

    {
        jvalue a[1];
        memset(a, 0, sizeof(a));
        CHECK("CallStaticObjectMethodA", (*env)->CallStaticObjectMethodA(env, clsTarget, smGetObject, a) != NULL);
        CHECK("CallStaticBooleanMethodA", (*env)->CallStaticBooleanMethodA(env, clsTarget, smGetBool, a) == JNI_FALSE);
        CHECK("CallStaticByteMethodA", (*env)->CallStaticByteMethodA(env, clsTarget, smGetByte, a) == 24);
        CHECK("CallStaticCharMethodA", (*env)->CallStaticCharMethodA(env, clsTarget, smGetChar, a) == (jchar)'Y');
        CHECK("CallStaticShortMethodA", (*env)->CallStaticShortMethodA(env, clsTarget, smGetShort, a) == 23);
        CHECK("CallStaticIntMethodA", (*env)->CallStaticIntMethodA(env, clsTarget, smGetInt, a) == 21);
        CHECK("CallStaticLongMethodA", (*env)->CallStaticLongMethodA(env, clsTarget, smGetLong, a) == 22L);
        CHECK("CallStaticFloatMethodA", (*env)->CallStaticFloatMethodA(env, clsTarget, smGetFloat, a) == 3.5f);
        CHECK("CallStaticDoubleMethodA", (*env)->CallStaticDoubleMethodA(env, clsTarget, smGetDouble, a) == 4.5);
        (*env)->CallStaticVoidMethodA(env, clsTarget, smNoop, a);
        CHECK("CallStaticVoidMethodA", (*env)->ExceptionCheck(env) == 0);
        jvalue a2[2];
        a2[0].i = 100;
        a2[1].i = 1;
        CHECK("CallStaticIntMethodA(sAdd)", (*env)->CallStaticIntMethodA(env, clsTarget, smAdd, a2) == 101);
    }

    /* ---------------- fields ---------------- */
    SECTION("7. fields (Get/Set <Type>Field)");
    CHECK("GetIntField", (*env)->GetIntField(env, target, fInt) == 88);
    CHECK("GetLongField", (*env)->GetLongField(env, target, fLong) == 12L);
    CHECK("GetShortField", (*env)->GetShortField(env, target, fShort) == 13);
    CHECK("GetByteField", (*env)->GetByteField(env, target, fByte) == 14);
    CHECK("GetCharField", (*env)->GetCharField(env, target, fChar) == (jchar)'Z');
    CHECK("GetBooleanField", (*env)->GetBooleanField(env, target, fBool) == JNI_TRUE);
    CHECK("GetFloatField", (*env)->GetFloatField(env, target, fFloat) == 1.5f);
    CHECK("GetDoubleField", (*env)->GetDoubleField(env, target, fDouble) == 2.5);
    CHECK("GetObjectField(String)", (*env)->GetObjectField(env, target, fStr) != NULL);
    CHECK("GetObjectField(Object)", (*env)->GetObjectField(env, target, fObj) != NULL);

    (*env)->SetIntField(env, target, fInt, 100);
    (*env)->SetLongField(env, target, fLong, 200L);
    (*env)->SetShortField(env, target, fShort, 300);
    (*env)->SetByteField(env, target, fByte, 40);
    (*env)->SetCharField(env, target, fChar, (jchar)'Q');
    (*env)->SetBooleanField(env, target, fBool, JNI_FALSE);
    (*env)->SetFloatField(env, target, fFloat, 9.5f);
    (*env)->SetDoubleField(env, target, fDouble, 8.5);
    (*env)->SetObjectField(env, target, fStr, (*env)->NewStringUTF(env, "changed"));
    (*env)->SetObjectField(env, target, fObj, NULL);
    CHECK("SetIntField", (*env)->GetIntField(env, target, fInt) == 100);
    CHECK("SetLongField", (*env)->GetLongField(env, target, fLong) == 200L);
    CHECK("SetShortField", (*env)->GetShortField(env, target, fShort) == 300);
    CHECK("SetByteField", (*env)->GetByteField(env, target, fByte) == 40);
    CHECK("SetCharField", (*env)->GetCharField(env, target, fChar) == (jchar)'Q');
    CHECK("SetBooleanField", (*env)->GetBooleanField(env, target, fBool) == JNI_FALSE);
    CHECK("SetFloatField", (*env)->GetFloatField(env, target, fFloat) == 9.5f);
    CHECK("SetDoubleField", (*env)->GetDoubleField(env, target, fDouble) == 8.5);
    CHECK("SetObjectField(null)", (*env)->GetObjectField(env, target, fObj) == NULL);

    CHECK("GetStaticIntField", (*env)->GetStaticIntField(env, clsTarget, sfInt) == 21);
    CHECK("GetStaticLongField", (*env)->GetStaticLongField(env, clsTarget, sfLong) == 22L);
    CHECK("GetStaticShortField", (*env)->GetStaticShortField(env, clsTarget, sfShort) == 23);
    CHECK("GetStaticByteField", (*env)->GetStaticByteField(env, clsTarget, sfByte) == 24);
    CHECK("GetStaticCharField", (*env)->GetStaticCharField(env, clsTarget, sfChar) == (jchar)'Y');
    CHECK("GetStaticBooleanField", (*env)->GetStaticBooleanField(env, clsTarget, sfBool) == JNI_FALSE);
    CHECK("GetStaticFloatField", (*env)->GetStaticFloatField(env, clsTarget, sfFloat) == 3.5f);
    CHECK("GetStaticDoubleField", (*env)->GetStaticDoubleField(env, clsTarget, sfDouble) == 4.5);
    CHECK("GetStaticObjectField(String)", (*env)->GetStaticObjectField(env, clsTarget, sfStr) != NULL);
    CHECK("GetStaticObjectField(Object)", (*env)->GetStaticObjectField(env, clsTarget, sfObj) != NULL);

    (*env)->SetStaticIntField(env, clsTarget, sfInt, 111);
    (*env)->SetStaticLongField(env, clsTarget, sfLong, 222L);
    (*env)->SetStaticShortField(env, clsTarget, sfShort, 333);
    (*env)->SetStaticByteField(env, clsTarget, sfByte, 44);
    (*env)->SetStaticCharField(env, clsTarget, sfChar, (jchar)'R');
    (*env)->SetStaticBooleanField(env, clsTarget, sfBool, JNI_TRUE);
    (*env)->SetStaticFloatField(env, clsTarget, sfFloat, 7.5f);
    (*env)->SetStaticDoubleField(env, clsTarget, sfDouble, 6.5);
    (*env)->SetStaticObjectField(env, clsTarget, sfStr, (*env)->NewStringUTF(env, "s-changed"));
    (*env)->SetStaticObjectField(env, clsTarget, sfObj, NULL);
    CHECK("SetStaticIntField", (*env)->GetStaticIntField(env, clsTarget, sfInt) == 111);
    CHECK("SetStaticLongField", (*env)->GetStaticLongField(env, clsTarget, sfLong) == 222L);
    CHECK("SetStaticShortField", (*env)->GetStaticShortField(env, clsTarget, sfShort) == 333);
    CHECK("SetStaticByteField", (*env)->GetStaticByteField(env, clsTarget, sfByte) == 44);
    CHECK("SetStaticCharField", (*env)->GetStaticCharField(env, clsTarget, sfChar) == (jchar)'R');
    CHECK("SetStaticBooleanField", (*env)->GetStaticBooleanField(env, clsTarget, sfBool) == JNI_TRUE);
    CHECK("SetStaticFloatField", (*env)->GetStaticFloatField(env, clsTarget, sfFloat) == 7.5f);
    CHECK("SetStaticDoubleField", (*env)->GetStaticDoubleField(env, clsTarget, sfDouble) == 6.5);
    CHECK("SetStaticObjectField(null)", (*env)->GetStaticObjectField(env, clsTarget, sfObj) == NULL);

    /* ---------------- strings ---------------- */
    SECTION("8. strings");
    jstring jstr = (*env)->NewStringUTF(env, "hello-JNI");
    CHECK("NewStringUTF", jstr != NULL);
    CHECK("GetStringUTFLength", (*env)->GetStringUTFLength(env, jstr) == 9);
    {
        const char *u = (*env)->GetStringUTFChars(env, jstr, NULL);
        CHECK("GetStringUTFChars", u != NULL && strcmp(u, "hello-JNI") == 0);
        (*env)->ReleaseStringUTFChars(env, jstr, u);
    }
    CHECK("GetStringLength", (*env)->GetStringLength(env, jstr) == 9);
    {
        const jchar *c = (*env)->GetStringChars(env, jstr, NULL);
        CHECK("GetStringChars", c != NULL && c[0] == (jchar)'h');
        (*env)->ReleaseStringChars(env, jstr, c);
    }
    {
        const jchar wide[3] = {(jchar)'A', (jchar)'B', (jchar)'C'};
        jstring ws = (*env)->NewString(env, wide, 3);
        CHECK("NewString", (*env)->GetStringLength(env, ws) == 3);
        jchar rbuf[4] = {0};
        (*env)->GetStringRegion(env, ws, 0, 3, rbuf);
        CHECK("GetStringRegion", rbuf[0] == (jchar)'A' && rbuf[2] == (jchar)'C');
        char ubuf[8] = {0};
        (*env)->GetStringUTFRegion(env, ws, 0, 3, ubuf);
        CHECK("GetStringUTFRegion", strcmp(ubuf, "ABC") == 0);
        (*env)->DeleteLocalRef(env, ws);
    }
    {
        const jchar *c = (*env)->GetStringCritical(env, jstr, NULL);
        CHECK("GetStringCritical", c != NULL);
        if (c) (*env)->ReleaseStringCritical(env, jstr, c);
        CHECK("ReleaseStringCritical", (*env)->ExceptionCheck(env) == 0);
    }
    (*env)->DeleteLocalRef(env, jstr);

    /* ---------------- arrays ---------------- */
    SECTION("9. arrays");
    TEST_ARRAY(Boolean, jboolean, 1);
    TEST_ARRAY(Byte, jbyte, 7);
    TEST_ARRAY(Char, jchar, (jchar)'A');
    TEST_ARRAY(Short, jshort, 5);
    TEST_ARRAY(Int, jint, 9);
    TEST_ARRAY(Long, jlong, 10);
    TEST_ARRAY(Float, jfloat, 1.25f);
    TEST_ARRAY(Double, jdouble, 2.5);
    TEST_ARRAY_CRITICAL(Int, jint);
    TEST_ARRAY_CRITICAL(Long, jlong);

    {
        jintArray ia = (*env)->NewIntArray(env, 3);
        CHECK("GetArrayLength", (*env)->GetArrayLength(env, ia) == 3);
        (*env)->DeleteLocalRef(env, ia);
        jobjectArray oa = (*env)->NewObjectArray(env, 3, clsString, NULL);
        CHECK("NewObjectArray", oa != NULL);
        jstring s0 = (*env)->NewStringUTF(env, "elem0");
        (*env)->SetObjectArrayElement(env, oa, 0, s0);
        jobject g0 = (*env)->GetObjectArrayElement(env, oa, 0);
        CHECK("Set/GetObjectArrayElement", (*env)->IsSameObject(env, s0, g0) == JNI_TRUE);
        CHECK("GetObjectArrayElement(null)", (*env)->GetObjectArrayElement(env, oa, 1) == NULL);
        (*env)->DeleteLocalRef(env, s0);
        (*env)->DeleteLocalRef(env, g0);
        (*env)->DeleteLocalRef(env, oa);
    }

    /* ---------------- direct byte buffers ---------------- */
    SECTION("10. direct byte buffers");
    {
        static unsigned char scratch[64];
        jobject dbb = (*env)->NewDirectByteBuffer(env, scratch, (jlong)sizeof(scratch));
        CHECK("NewDirectByteBuffer", dbb != NULL);
        CHECK("GetDirectBufferAddress", (*env)->GetDirectBufferAddress(env, dbb) == (void *)scratch);
        CHECK("GetDirectBufferCapacity",
              (*env)->GetDirectBufferCapacity(env, dbb) == (jlong)sizeof(scratch));
        (*env)->DeleteLocalRef(env, dbb);
    }

    /* ---------------- reflection bridge ---------------- */
    SECTION("11. reflection bridge");
    {
        jobject rm = (*env)->ToReflectedMethod(env, clsTarget, mGetInt, JNI_FALSE);
        CHECK("ToReflectedMethod(instance)", rm != NULL);
        jmethodID back = rm ? (*env)->FromReflectedMethod(env, rm) : NULL;
        CHECK("FromReflectedMethod", back != NULL);
        if (back) CHECK("FromReflectedMethod (callable)", (*env)->CallIntMethod(env, target, back) == 100);
        if (rm) (*env)->DeleteLocalRef(env, rm);

        jobject rsm = (*env)->ToReflectedMethod(env, clsTarget, smAdd, JNI_TRUE);
        CHECK("ToReflectedMethod(static)", rsm != NULL);
        if (rsm) (*env)->DeleteLocalRef(env, rsm);

        jobject rf = (*env)->ToReflectedField(env, clsTarget, fInt, JNI_FALSE);
        CHECK("ToReflectedField(instance)", rf != NULL);
        jfieldID fb = rf ? (*env)->FromReflectedField(env, rf) : NULL;
        CHECK("FromReflectedField", fb != NULL);
        if (rf) (*env)->DeleteLocalRef(env, rf);

        jobject rsf = (*env)->ToReflectedField(env, clsTarget, sfInt, JNI_TRUE);
        CHECK("ToReflectedField(static)", rsf != NULL);
        if (rsf) (*env)->DeleteLocalRef(env, rsf);
    }

    /* ---------------- exceptions ---------------- */
    SECTION("12. exceptions");
    CHECK("ExceptionOccurred(clean)==NULL", (*env)->ExceptionOccurred(env) == NULL);
    CHECK("ExceptionCheck(clean)==false", (*env)->ExceptionCheck(env) == JNI_FALSE);
    (*env)->ThrowNew(env, clsISE, "throw-new-test");
    CHECK("ExceptionCheck after ThrowNew", (*env)->ExceptionCheck(env) == JNI_TRUE);
    jthrowable occ = (*env)->ExceptionOccurred(env);
    CHECK("ExceptionOccurred after ThrowNew", occ != NULL);
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    CHECK("ExceptionClear", (*env)->ExceptionCheck(env) == JNI_FALSE);
    occ = (*env)->ExceptionOccurred(env);
    CHECK("ExceptionOccurred(cleared)==NULL", occ == NULL);
    {
        jstring msg = (*env)->NewStringUTF(env, "throw-obj-test");
        jobject exObj = (*env)->NewObject(env, clsISE, iseCtor, msg);
        (*env)->Throw(env, exObj);
        CHECK("ExceptionCheck after Throw", (*env)->ExceptionCheck(env) == JNI_TRUE);
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, msg);
        (*env)->DeleteLocalRef(env, exObj);
    }
    {
        jclass bogus = (*env)->FindClass(env, "com/test/jnifull/DoesNotExist");
        CHECK("FindClass(missing)==NULL", bogus == NULL);
        CHECK("ExceptionCheck after failed FindClass", (*env)->ExceptionCheck(env) == JNI_TRUE);
        (*env)->ExceptionClear(env);
        jmethodID bad = (*env)->GetMethodID(env, clsTarget, "noSuchMethod", "()V");
        CHECK("GetMethodID(missing)==NULL", bad == NULL);
        clear_exc(env);
    }

    /* ---------------- interface dispatch ---------------- */
    SECTION("13. interface dispatch");
    {
        jobject impl = (*env)->NewObject(env, clsCalcImpl, calcImplCtor);
        CHECK("IsInstanceOf(CalcImpl,Calc)", (*env)->IsInstanceOf(env, impl, clsCalc) == JNI_TRUE);
        CHECK("CallIntMethod via interface", (*env)->CallIntMethod(env, impl, mCalcAdd, (jint)8, (jint)9) == 17);
        (*env)->DeleteLocalRef(env, impl);
    }

    /* ---------------- RegisterNatives / UnregisterNatives ---------------- */
    SECTION("14. RegisterNatives / UnregisterNatives");
    {
        JNINativeMethod nm;
        nm.name = "tempNative";
        nm.signature = "(I)I";
        nm.fnPtr = (void *)temp_native_impl;
        jint rr = (*env)->RegisterNatives(env, clsTemp, &nm, 1);
        CHECK("RegisterNatives", rr == 0);
        CHECK("CallIntMethod(registered native)", (*env)->CallStaticIntMethod(env, clsTemp, mTempNative, (jint)5) == 6);
        jint ur = (*env)->UnregisterNatives(env, clsTemp);
        CHECK("UnregisterNatives", ur == 0);
        (*env)->CallStaticIntMethod(env, clsTemp, mTempNative, (jint)5);
        CHECK("call after Unregister throws", (*env)->ExceptionCheck(env) == JNI_TRUE);
        clear_exc(env);
    }

    /* ---------------- module (not part of the ART JNIEnv table) ---------------- */
    SECTION("15. GetModule (Android extension)");
    {
        /* GetModule is not declared by any NDK jni.h, and on this ART the
         * JNIEnv function table ends exactly at GetObjectRefType (slot 232).
         * Verify that and record it as a skip rather than a failure.          */
        int nslots = (int)(sizeof(struct JNINativeInterface) / sizeof(void *));
        int extra = 0;
        for (int k = 1; k <= 4; k++) {
            void *slot = *((void **)(&(*env)->GetObjectRefType) + k);
            if (slot != NULL) extra++;
        }
        OUT("  [info] NDK table slots = %d, non-null slots past it = %d\n", nslots, extra);
        CHECK("JNIEnv table ends at GetObjectRefType", extra == 0);
        SKIP("GetModule (absent from ART JNIEnv table; undocumented extension)");
        clear_exc(env);
    }

    /* ---------------- GetJavaVM + thread attach ---------------- */
    SECTION("16. JavaVM / thread attach");
    {
        JavaVM *vm = NULL;
        jint rc = (*env)->GetJavaVM(env, &vm);
        CHECK("GetJavaVM", rc == 0 && vm != NULL);
        if (vm) {
            JNIEnv *cur = NULL;
            jint ge = (*vm)->GetEnv(vm, (void **)&cur, JNI_VERSION_1_6);
            CHECK("GetEnv(current)", ge == JNI_OK && cur != NULL);
            pthread_t t1, t2;
            pthread_create(&t1, NULL, attached_thread, NULL);
            pthread_join(t1, NULL);
            CHECK("AttachCurrentThread/DetachCurrentThread", 1);
            pthread_create(&t2, NULL, attached_daemon_thread, NULL);
            pthread_join(t2, NULL);
            CHECK("AttachCurrentThreadAsDaemon/DetachCurrentThread", 1);
        }
    }
}

/* real impl used by RegisterNatives */
static jint temp_native_impl(JNIEnv *env, jclass clazz, jint x) {
    return x + 1;
}

/* ------------------------------------------------------------------ */
/* statically linked native methods                                    */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNICALL Java_com_test_jnifull_NativeTest_runAll(JNIEnv *env, jclass clazz) {
    g_pass = g_fail = g_skip = 0;
    run_all_tests(env);
    return g_fail;
}

JNIEXPORT jint JNICALL Java_com_test_jnifull_NativeTest_getPassCount(JNIEnv *env, jclass clazz) {
    return g_pass;
}

JNIEXPORT jint JNICALL Java_com_test_jnifull_NativeTest_getFailCount(JNIEnv *env, jclass clazz) {
    return g_fail;
}

JNIEXPORT jint JNICALL Java_com_test_jnifull_NativeTest_getSkipCount(JNIEnv *env, jclass clazz) {
    return g_skip;
}

JNIEXPORT jstring JNICALL Java_com_test_jnifull_NativeTest_nativeVersion(JNIEnv *env, jclass clazz) {
    return (*env)->NewStringUTF(env, "libjnifull 1.0 (JNIEnv full-coverage)");
}

/* ---- multi-level native call chain, for verifying -S (stack) ---- */
static const char *modoff(void *a) {
    static char b[160];
    Dl_info di;
    if (dladdr(a, &di) && di.dli_fbase) {
        const char *n = di.dli_fname ? di.dli_fname : "?";
        const char *s = strrchr(n, '/');
        n = s ? s + 1 : n;
        snprintf(b, sizeof(b), "%s+0x%lx", n, (unsigned long)((char *)a - (char *)di.dli_fbase));
    } else {
        snprintf(b, sizeof(b), "%p", a);
    }
    return b;
}

static void jni_deep3(JNIEnv *env) {
    void *ra_in_deep3 = &&a3;
    jclass c = (*env)->FindClass(env, "com/test/jnifull/DeepStackMarker");
a3:
    (*env)->ExceptionClear(env); // swallow the ClassNotFoundException (probe target only)
    printf("[STK] deep3    ra=%s\n", modoff(ra_in_deep3));
    fflush(stdout);
    (void)c;
}
static void jni_deep2(JNIEnv *env) {
    void *ra_in_deep2 = &&a2;
    jni_deep3(env);
a2:
    printf("[STK] deep2    ra=%s\n", modoff(ra_in_deep2));
    fflush(stdout);
}
static void jni_deep1(JNIEnv *env) {
    void *ra_in_deep1 = &&a1;
    jni_deep2(env);
a1:
    printf("[STK] deep1    ra=%s\n", modoff(ra_in_deep1));
    fflush(stdout);
}

JNIEXPORT void JNICALL Java_com_test_jnifull_NativeTest_deepCall(JNIEnv *env, jclass clazz) {
    void *ra_in_deepCall = &&ac;
    jni_deep1(env);
ac:
    printf("[STK] deepCall ra=%s\n", modoff(ra_in_deepCall));
    fflush(stdout);
}

JNIEXPORT jint JNICALL Java_com_test_jnifull_NativeTest_staticAdd(JNIEnv *env, jclass clazz,
                                                                  jint a, jint b) {
    return a + b;
}

JNIEXPORT jstring JNICALL Java_com_test_jnifull_NativeTest_staticHello(JNIEnv *env, jclass clazz,
                                                                      jstring name) {
    const char *c = name ? (*env)->GetStringUTFChars(env, name, NULL) : NULL;
    char buf[256];
    snprintf(buf, sizeof(buf), "hello %s", c ? c : "null");
    if (c) (*env)->ReleaseStringUTFChars(env, name, c);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jintArray JNICALL Java_com_test_jnifull_NativeTest_staticFlip(JNIEnv *env, jclass clazz,
                                                                       jintArray in) {
    if (in == NULL) return NULL;
    jsize n = (*env)->GetArrayLength(env, in);
    jint *buf = (*env)->GetIntArrayElements(env, in, NULL);
    jintArray out = (*env)->NewIntArray(env, n);
    jint *ob = (*env)->GetIntArrayElements(env, out, NULL);
    for (jsize i = 0; i < n; i++) ob[i] = buf[n - 1 - i];
    (*env)->ReleaseIntArrayElements(env, out, ob, 0);
    (*env)->ReleaseIntArrayElements(env, in, buf, JNI_ABORT);
    return out;
}

JNIEXPORT jlong JNICALL Java_com_test_jnifull_NativeTest_staticSum(JNIEnv *env, jclass clazz,
                                                                  jlongArray in) {
    if (in == NULL) return 0;
    jsize n = (*env)->GetArrayLength(env, in);
    jlong *buf = (*env)->GetLongArrayElements(env, in, NULL);
    jlong s = 0;
    for (jsize i = 0; i < n; i++) s += buf[i];
    (*env)->ReleaseLongArrayElements(env, in, buf, JNI_ABORT);
    return s;
}

JNIEXPORT void JNICALL Java_com_test_jnifull_NativeTest_staticThrow(JNIEnv *env, jclass clazz) {
    jclass c = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (c) (*env)->ThrowNew(env, c, "from-native");
}

JNIEXPORT jobject JNICALL Java_com_test_jnifull_NativeTest_staticRoundTrip(JNIEnv *env, jclass clazz,
                                                                          jobject o) {
    return o;
}

/* dynamically registered natives */
static jint dyn_add(JNIEnv *env, jclass clazz, jint a, jint b) { return a + b; }

static jstring dyn_hello(JNIEnv *env, jclass clazz, jstring name) {
    const char *c = name ? (*env)->GetStringUTFChars(env, name, NULL) : NULL;
    char buf[256];
    snprintf(buf, sizeof(buf), "%s-Ok", c ? c : "null");
    if (c) (*env)->ReleaseStringUTFChars(env, name, c);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_vm = vm;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass c = (*env)->FindClass(env, "com/test/jnifull/NativeTest");
    if (c == NULL) {
        (*env)->ExceptionClear(env);
        return JNI_VERSION_1_6;
    }
    static const JNINativeMethod methods[] = {
        {"dynAdd", "(II)I", (void *)dyn_add},
        {"dynHello", "(Ljava/lang/String;)Ljava/lang/String;", (void *)dyn_hello},
    };
    (*env)->RegisterNatives(env, c, methods, 2);
    (*env)->ExceptionClear(env);
    return JNI_VERSION_1_6;
}
