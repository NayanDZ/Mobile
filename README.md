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
