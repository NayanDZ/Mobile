# Mobile📱 App Security Testing

### 📋 [Introduction to the Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/overview/0x03-overview)
1. [Mobile App Taxonomy](https://mobile-security.gitbook.io/mobile-security-testing-guide/overview/0x04a-mobile-app-taxonomy)
2. [Android Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05a-platform-overview)
3. [iOS Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/ios-testing-guide/0x06a-platform-overview)

## How Android Application tested?
### ***1. [Static Source Code Analysis](https://owasp.org/www-community/Source_Code_Analysis_Tools):***
  - Checkmarx - Static Source Code Scanner that also scans source code for Android and iOS.
  - Fortify - Static source code scanner that also scans source code for Android and iOS.
  - Veracode - Static Analysis of iOS and Android binary

### ***2. Static Analysis:***
  - [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework): AndroBugs Framework is an efficient Android vulnerability scanner that helps developers or hackers find potential security vulnerabilities in Android applications. No need to install on Windows.
  
    $ androbugs.py -f [APK file] 
 
### ***3. Reverse Engineering (Decompiling)***
  - [APKTool](https://github.com/iBotPeaches/Apktool): A tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications.
    Disassembling Android apk file:
                  
        apktool d [APK file]
    
    Rebuilding decoded resources back to binary APK/JAR with certificate signing
	   
        apktool b <modified folder>
        
        keytool -genkey -v -keystore keys/test.keystore -alias Test -keyalg RSA -keysize 1024 -sigalg SHA1withRSA -validity 10000
        jarsigner -keystore keys/test.keystore dist/test.apk -sigalg SHA1withRSA -digestalg SHA1 Test
  
  - [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer): is an Advanced Lightweight Java/Android Decompiler and Reverse Engineering Suite. BCV comes with 6 decompilers, 3 disassemblers, 2 assemblers, 2 APK converters, advanced searching, debugging.

        

### ***4. Dynamic and Runtime Analysis***
  - **[Drozer](https://github.com/FSecureLABS/drozer)**: allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps’ IPC endpoints and the underlying OS.
  
  - **Android Debug Bridge:** adb is a versatile command-line tool that lets you communicate with a device. adb is a debugger targeting the Android platform’s Dalvik virtual machine intended for reverse engineers and developers
    - adb devices – It is show connected device ```$ adb devices ``` 
    - adb install – Install an apk file into an Emulated/Connected Device : ``` $ adb install [APK file] ```
    - adb pull – It is used to fetch some data from Emulated device (remote) to local host (local).
    - adb push – It is used to push some data from local host (local) to Emulated Device (remote).
    - Adb shell – Adb provides shell on an emulator or connected device ``` adb shell ```
      - Identifying application process using adb shell: ``` adb shell ps | grep -i "App keyword" ```
      - Accessing the application using adb in order to identify loaded classes: ``` adb shell -p <process number> ```

    #### Some Important notes
    
     ***Android Package (APK)*** is the default extension for the Android applications, which is just an archive file that contains all the necessary files and folders of the application.
  
     - All applications (apk files) in device can be found in ``` /data/app ``` directory.
     - All Data of the application in the device can be found in ```/data/data``` directory.
     - Standard permissions granted to the shell can be found in: ``` root@android: /system/etc/permissions # cat platform.xml ```
 
 
     ***Hacks via ADB:*** We usually open our android device by unlocking various gesture pattern or password key.
      If you remove ***gesture.Key*** or ***password.Key*** which located at ```data/system``` you can bypass that lock.
 
### ***5. Manual Testing:***  
    
   **1.** Setup proxy using ``Burp Suite`` tool and intercept traffic.
 
   **2.** If Application is SSL Pinned then we require to bypass SSL pinning of that application.
 
   - ***SSL Pinning bypass using Frida:***
   
      **Step-1:** Install Frida

             > pip install frida 
	
      **Step-2** Install Frida Tools

	     > pip install frida-tools

      **Step-3** [Download frida-server files](https://github.com/frida/frida/releases) (android-x86 or android-arm) according your device architecture
	      
      **Step-4** Push frida-server file into the device (i.e emulator or physical device)

             > adb push frida-server-12.7.24-android-x86 /data/local/tmp (Copy all 4 frida server in device)

      **Step-5** Give 777 (read, Write, execute) permission of frida-server file.

	     > adb shell
             > cd /data/local/tmp
             > chmod 777 frida-server-12.7.24-android-x86

      **Step-6** Start Firda Server
      
	     > adb shell
	     > cd /data/local/tmp
	     > ls -all (for list all the Files/Permission in present directory)
             > ./frida-server-12.7.24-android-x86 (execute frida-server)

      **Step-7** create frida-ssl2.js file
       ```
	     Java.perform(function()
	     {
               var array_list = Java.use("java.util.ArrayList");
               var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
               ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) 
	       {
                // console.log('Bypassing SSL Pinning');
                var k = array_list.$new();
                return k;
               }
             }, 0);
       ```
       **Step-7** Check all running process in Device or Emulator  
	
	     > frida-ps -U
       
       **Step-9** Hook application package 

	     > frida -U -l frida-ssl-2.js --no-paus -f com.iifl.insurance

       **Step-10** Now you can intercept the request using Burp Suite 😸


  	
