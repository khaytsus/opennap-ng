@Echo off
@echo Makeing windoze stuff
@copy ..\Copying Copying
@unix2dos Copying
@copy ..\doc\examples\sample.config config
@unix2dos config
@copy ..\doc\examples\sample.motd motd
@unix2dos motd
c:\Progra~1\nsis\makensis.exe opennap-ng 
