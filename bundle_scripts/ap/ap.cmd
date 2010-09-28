SET NOR_PATCH=nor.diff.xml
SET KC_PATCH=kc.sb.diff.xml
SET NOR_CONFIDENCE=75
SET KC_CONFIDENCE=80
SET KC_EXTRA_ARGS=-2:#1
SET BASEPATH=%~dp0
SET WORKDIR=%BASEPATH%\..

SET PATCHCMD=c:\tools\ConsoleApplication1.exe patch

for %%f in (kernelcache.release.*.dec) do %PATCHCMD% %%f %%f.ap "%BASEPATH%\%KC_PATCH%" -c %KC_CONFIDENCE% %KC_EXTRA_ARGS%

for %%f in (*.dfu.dec LLB*.img3.dec iBoot*img3.dec) do %PATCHCMD% %%f %%f.ap "%BASEPATH%\%NOR_PATCH%" -c %NOR_CONFIDENCE%
