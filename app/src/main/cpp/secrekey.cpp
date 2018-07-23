#include <jni.h>
#include <cstring>
/**注释掉日志
#include <android/log.h>

#define TAG "linnan"
// 定义error信息
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)
*/
/**
 * 定义可以通过校验的预定义签名MD5值
 */
const char * md5Strs[] = {"81F11E5411A986A21618061F7A54C090"};//本机测试apk的debug签名

/**
 * 获取Context对象
 * @param env
 * @return
 */
jobject getContext(JNIEnv* env,jclass appClass){
    //获取App对象
    jmethodID  appGetMethod = env->GetStaticMethodID(appClass,"get","()Lcom/linnan/app/App;");
    jobject appObject = env->CallStaticObjectMethod(appClass,appGetMethod);
    return appObject;
}


/**
 * 获取应用包名
 * @param env
 * @param context
 * @return
 */
jstring getPackageName(JNIEnv* env,jobject context,jclass appClass){
    //获取包名
    jmethodID  getPackageNameMethod = env->GetMethodID(appClass,"getPackageName","()Ljava/lang/String;");
    jstring packageName = (jstring) env->CallObjectMethod(context, getPackageNameMethod);
    const char *str = env->GetStringUTFChars(packageName,0);
//    LOGE("当前应用的包名为：%s",str);
    return packageName;
}

/**
 * 获取签名的字节数组
 * @param env
 * @param context
 * @param appClass
 * @param packageName
 * @return
 */
jbyteArray getSignatureByteArray(JNIEnv* env,jobject context,jclass appClass,jstring packageName){
    //获取PackageManager对象
    jmethodID getPackageManagerMethod = env->GetMethodID(appClass,"getPackageManager","()Landroid/content/pm/PackageManager;");
    jobject packageManagerObject = env->CallObjectMethod(context,getPackageManagerMethod);
    //获取PackageInfo对象
    jclass packageManagerClass = env->GetObjectClass(packageManagerObject);
    jmethodID  getPackageInfoMethod = env->GetMethodID(packageManagerClass,"getPackageInfo","(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject packageInfoObject = env->CallObjectMethod(packageManagerObject,getPackageInfoMethod,packageName,64);
    //获取签名数组
    jclass packageInfoClass = env->GetObjectClass(packageInfoObject);
    jfieldID signaturesField = env->GetFieldID(packageInfoClass,"signatures","[Landroid/content/pm/Signature;");
    jobjectArray signaturesObject = (jobjectArray) env->GetObjectField(packageInfoObject, signaturesField);
    jobject signatureObject = env->GetObjectArrayElement(signaturesObject,0);
    jclass signatureClass = env->GetObjectClass(signatureObject);
    jmethodID toByteArrayMethod = env->GetMethodID(signatureClass,"toByteArray","()[B");
    jbyteArray inputSignature = (jbyteArray) env->CallObjectMethod(signatureObject, toByteArrayMethod);
    return inputSignature;
}

/**
 * 获取X509协议的字节数组
 * @return
 */
jbyteArray getCertByteArray(JNIEnv* env,jbyteArray inputSignature){
    //把byte数组转成流
    jclass byteArrayInputClass=env->FindClass("java/io/ByteArrayInputStream");
    jmethodID initMethodId=env->GetMethodID(byteArrayInputClass,"<init>","([B)V");
    jobject byteArrayInputObject=env->NewObject(byteArrayInputClass,initMethodId,inputSignature);
    //实例化X.509
    jclass certificateFactoryClass=env->FindClass("java/security/cert/CertificateFactory");
    jmethodID certificateMethodId=env->GetStaticMethodID(certificateFactoryClass,"getInstance","(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x509Jstring=env->NewStringUTF("X.509");
    jobject certFactory=env->CallStaticObjectMethod(certificateFactoryClass,certificateMethodId,x509Jstring);
    jmethodID certificateFactoryMethodId=env->GetMethodID(certificateFactoryClass,"generateCertificate",("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
    jobject x509Cert=env->CallObjectMethod(certFactory,certificateFactoryMethodId,byteArrayInputObject);
    jclass x509CertClass=env->GetObjectClass(x509Cert);
    jmethodID x509CertMethodId=env->GetMethodID(x509CertClass,"getEncoded","()[B");
    jbyteArray certByteArray=(jbyteArray)env->CallObjectMethod(x509Cert,x509CertMethodId);
    //获取MessageDigest
    jclass messageDigestClass=env->FindClass("java/security/MessageDigest");
    jmethodID getInstanceMethodId=env->GetStaticMethodID(messageDigestClass,"getInstance","(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring md5Jstring=env->NewStringUTF("MD5");
    jobject md5Digest=env->CallStaticObjectMethod(messageDigestClass,getInstanceMethodId,md5Jstring);
    getInstanceMethodId=env->GetMethodID(messageDigestClass,"digest","([B)[B");
    jbyteArray md5ByteArray=(jbyteArray)env->CallObjectMethod(md5Digest,getInstanceMethodId,certByteArray);
    return md5ByteArray;
}

/**
 * 获取16进制的字符串
 * @param env
 * @param md5ByteArray
 * @return
 */
const char * getHexMd5(JNIEnv* env,jbyteArray md5ByteArray){
    //转换成16进制字符串
    jsize arraySize=env->GetArrayLength(md5ByteArray);
    jbyte* md5 =env->GetByteArrayElements(md5ByteArray,NULL);
    char hexMd5[arraySize*2+1];
    char HexCode[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    for (int i = 0;i<arraySize;++i) {
        hexMd5[2*i]=HexCode[((unsigned char)md5[i])/16];
        hexMd5[2*i+1]=HexCode[((unsigned char)md5[i])%16];
    }
    hexMd5[arraySize*2]='\0';
    const char* result = hexMd5;
    return result;
}

/**
 * 该方法实现的是上面的java方法
 * @param env
 * @return
 */
const char* getSignValidString(JNIEnv* env){
    try{
        jclass appClass = env->FindClass("com/linnan/app/App");
        jobject context = getContext(env,appClass);
        jstring packageName = getPackageName(env,context,appClass);
        jbyteArray inputSignature = getSignatureByteArray(env,context,appClass,packageName);
        jbyteArray md5ByteArray=getCertByteArray(env,inputSignature);
        return getHexMd5(env,md5ByteArray);
    }catch (...){//出任何异常，直接让通过校验
        return md5Strs[0];
    }
}

/**
 * 直接退出应用程序
 * @param env
 * @param flag
 */
void exitApplication(JNIEnv *env, jint flag){
    jclass temp_clazz = NULL;
    jmethodID mid_static_method;
    // 1、从classpath路径下搜索ClassMethod这个类，并返回该类的Class对象
    temp_clazz =env->FindClass("java/lang/System");
    mid_static_method = env->GetStaticMethodID(temp_clazz,"exit","(I)V");
    env->CallStaticVoidMethod(temp_clazz,mid_static_method,flag);
    env->DeleteLocalRef(temp_clazz);
}

extern "C"
JNIEXPORT jboolean JNICALL Java_com_linnan_app_SecreKey_isPassVerify(JNIEnv* env,jobject) {
    //获取签名的MD5值
    const char *valideStr = getSignValidString(env);
//    LOGE("获取到的签名MD5值：%s",valideStr);
    //迭代判断是否是预定于的MD5值，在预定义值里就通过校验
    for(const char* md5Str : md5Strs){
        if (strcmp(md5Str,valideStr) == 0){
            return true;
        }
    }
    //校验不通过，退出应用
    exitApplication(env,0);
    return false;
}

