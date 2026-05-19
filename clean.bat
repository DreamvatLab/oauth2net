REM del /s /ah /f *.suo
REM del /s /f *.user
REM del /s /f *.cache
REM del /s /f *.keep
REM del /s /ah StyleCop.Cache

rd /s /q bin obj ClientBin _Resharper.* _Upgrade* TestResults

del dirs.txt
dir /s /b /ad bin > dirs.txt
dir /s /b /ad obj >> dirs.txt
dir /s /b /ad ClientBin >> dirs.txt
dir /s /b /ad _Resharper.* >> dirs.txt
dir /s /b /ad _Upgrade* >> dirs.txt
dir /s /b /ad TestResults >> dirs.txt

for /f "delims=;" %%i in (dirs.txt) DO rd /s /q "%%i"
del dirs.txt

del dist\*.json
del dist\*.dll
del dist\*.pdb
del dist\*.xml
del dist\*.pri
del dist\*.mdb
del dist\*.nupkg