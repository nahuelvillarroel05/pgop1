# Instalar PGOPCore 0.1.0a12.post3

La configuración probada usa Windows 10 x64 build 19045, un disco NTFS local y Python 3.14 x64. `py -3.14 --version` comprueba la disponibilidad del intérprete.

1. En [main](https://github.com/nahuelvillarroel05/pgop1/tree/main), usá **Code → Download ZIP** y extraé la descarga. También podés usar un clon.
2. Copiá completa [0.1.0a12.post3](../releases/windows/0.1.0a12.post3/) a una carpeta local independiente de tus proyectos y de instalaciones anteriores.
3. Abrí **pgop-panel.cmd** desde la copia.

La primera apertura prepara su propio entorno con la wheel del núcleo y las nueve wheels de presentación. El lanzador comprueba el lock y los archivos locales. Las aperturas siguientes verifican y reutilizan el entorno.

## Terminal y automatización

Desde la copia del kit, en PowerShell:

```powershell
.\pgop-panel.cmd --version
.\pgop-panel.cmd --plain
.\pgop-panel.cmd --json doctor
.\pgop-panel.cmd context --help
```

En CMD usá los mismos comandos con `pgop-panel.cmd` como primer término. [Referencia CLI](CLI.md)

Para automatizar con el núcleo, en un entorno virtual aparte, instalá la wheel con Python 3.14 y `pip install --no-index --no-deps RUTA_A_LA_WHEEL`. Usá el `pgop` de ese entorno. Context Engine Local funciona también con esa wheel sola.

## Verificar o recuperar la copia

El [manifiesto del kit](../releases/windows/0.1.0a12.post3/MANIFEST_SHA256.json) identifica los archivos distribuidos. El [recibo de versión](../RELEASE_RECEIPT.json) fija el hash de la wheel y del ZIP original.

Si detecta un entorno incompleto o alterado, copiá el kit verificado a un directorio nuevo. Conservá proyectos, informes y contextos en carpetas separadas. La instalación se circunscribe a la carpeta copiada. Linux, otros builds de Windows y ubicaciones de red quedan fuera de la configuración probada.
