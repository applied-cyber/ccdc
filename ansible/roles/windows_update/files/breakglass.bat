SET duration=120
IF NOT "%1"=="" (SET duration=%1)
for /F "skip=3 tokens=1,2,3* delims= " %%G in ('netsh interface show interface') DO ( netsh interface set interface "%%J" disabled )
ping -n %duration% localhost
for /F "skip=3 tokens=1,2,3* delims= " %%G in ('netsh interface show interface') DO ( netsh interface set interface "%%J" enabled )
