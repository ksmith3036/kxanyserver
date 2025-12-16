pushd %0\..

pushd lib
call ..\gradlew jar war
popd

@echo Create source code for obfuscation
if not exist lib_obf md lib_obf
copy lib\* lib_obf /y
xcopy lib\src lib_obf\src /s /i /y

@REM Obfuscate strings
java -Xss8M StringObfuscator.java lib\src\main\java lib_obf\src\main\java
pushd lib_obf
call ..\gradlew jar war
popd

pushd ..\proguard-7.8.1
set PROGUARD_HOME=%CD%
popd
echo on
@REM java -jar "%PROGUARD_HOME%\lib\proguardgui.jar" proguardconfig.conf
java -jar "%PROGUARD_HOME%\lib\proguard.jar" @proguardconfig.conf

rd /s /q lib_obf\build\classes\java\main\org

7z.exe x lib_obf\build\libs\lib_proguard.jar -y -olib_obf\build\classes\java\main
7z.exe x lib_obf\build\libs\ROOT.war -y -oROOT
del /q ROOT\WEB-INF\classes\org\kx\*.class
xcopy /y /r lib_obf\build\classes\java\main\org\kx\*.class ROOT\WEB-INF\classes\org\kx
cd ROOT
..\7z.exe d ..\lib_obf\build\libs\ROOT.war WEB-INF\classes\org\kx\*.class
..\7z.exe u ..\lib_obf\build\libs\ROOT.war -r
cd ..

del lib_obf\build\libs\lib_obf.jar
rd /s /q ROOT

@echo Please use the class files found in lib_obf\build\classes\java\main, lib_obf\build\libs\ROOT.war or lib_obf\build\libs\lib_proguard.jar

pause
@REM For verifying 
if exist ..\vineflower-1.11.2.jar java -jar ..\vineflower-1.11.2.jar lib_obf\build\libs\lib_proguard.jar guard_out    

popd

pause
@REM javac -cp lib\build\libs\ROOT.war;..\servlet-api.jar -d guard_encr_out guard_encrypt\*.java guard_encrypt\org\kx\*.java

@REM javac -cp cp\*;..\servlet-api.jar -d guard_encr_out -sourcepath guard_encrypt guard_encrypt\org\kx\KxServlet.java