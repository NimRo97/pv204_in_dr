REM uninstall previously loaded applet 
java -jar gp.jar -uninstall PV204Applet.cap

REM load new version
java -jar gp.jar -install PV204Applet.cap -verbose -d

REM list available applets 
java -jar gp.jar -l


