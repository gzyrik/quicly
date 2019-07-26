call "%VS140COMNTOOLS%vsvars32.bat"
set PATH=C:\Program Files (x86)\Windows Kits\8.1\bin\x86;C:\nasm;C:\Perl64\bin;%PATH%
rem perl Configure VC-WIN32
nmake
pause