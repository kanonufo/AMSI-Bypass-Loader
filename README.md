# AMSI Bypass Loader

Este proyecto proporciona un cargador de DLL diseñado para cargar dinámicamente una DLL en memoria y facilitar el bypass de AMSI en entornos de análisis de malware y seguridad en Windows.

## Descripción de la técnica

El código proporcionado implementa un cargador de DLL que permite cargar una DLL en memoria y ejecutarla en un proceso en ejecución en el sistema operativo Windows. Las principales técnicas utilizadas incluyen:

- **Resolución de estructuras PE**: Define y utiliza estructuras como `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, etc., para analizar y extraer información de los headers de archivos PE, permitiendo la carga adecuada de la DLL en memoria.

- **Carga de la DLL en memoria**: La función `loadDLLToMemory` carga el contenido de una DLL desde el disco en memoria, permitiendo su ejecución sin necesidad de escribir en el disco.

- **Resolución de importaciones**: La función `resolveImports` analiza la tabla de importaciones de la DLL cargada en memoria y resuelve las importaciones dinámicas necesarias para el funcionamiento correcto de la DLL.

- **Ejecución de DllMain**: La función `callDllMain` ejecuta la función `DllMain` de la DLL cargada en memoria, permitiendo la inicialización y configuración adicional necesaria.

En resumen, este proyecto proporciona la infraestructura básica para cargar y ejecutar dinámicamente una DLL en memoria en entornos Windows, facilitando su uso en diversas aplicaciones como análisis de malware, desarrollo de extensiones de software y pruebas de seguridad.

## Instrucciones de uso

1. **Clonar el repositorio:**

   ```bash
   git clone https://github.com/tu-usuario/amsi-bypass-loader.git
2.Preparar la DLL maliciosa:

Coloque su DLL maliciosa en la misma ubicación que el archivo main.go.
Asegúrese de que la DLL esté diseñada para realizar un bypass de AMSI y que contenga los hooks necesarios para interceptar y modificar las llamadas a las funciones de AMSI.
Compilar y ejecutar el código:

3.Compile y ejecute el código utilizando Go:
 go run main.go
Pruebas y refinamiento:

4.Realice pruebas exhaustivas para asegurarse de que su DLL maliciosa esté funcionando correctamente y que AMSI no detecte la actividad maliciosa.
Refine los hooks según sea necesario para evitar la detección de AMSI de manera efectiva.

## Recursos adicionales

- [Documentación de AMSI en Microsoft Docs](https://docs.microsoft.com/es-es/windows/win32/amsi/antimalware-scan-interface-portal)
- [Técnicas de bypass de AMSI en Black Hat](https://www.blackhat.com/us-20/briefings/schedule/index.html#how-to-bypass-amsi-and-make-your-own-antimalware-4fun-20668)
## Recursos adicionales sobre carga dinámica de DLL en memoria

- [Dynamic-Link Library Redirection](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection)
  Documentación oficial de Microsoft sobre la redirección de bibliotecas de vínculos dinámicos.

- [DLL Injection](https://en.wikipedia.org/wiki/DLL_injection)
  Página de Wikipedia que explica los conceptos básicos de la inyección de DLL en procesos.

- [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)
  Repositorio de GitHub que proporciona código para realizar inyección de DLL reflectiva.

- [Cargar una DLL en la memoria](https://web.archive.org/web/20180531174752/https://www.codeproject.com/Articles/20084/Load-a-DLL-into-a-process-and-call-a-function-expor)
  Un artículo de CodeProject que describe cómo cargar una DLL en la memoria y llamar a funciones exportadas.

- [Efectos secundarios de la inyección de DLL](https://attack.mitre.org/techniques/T1055/002/)
  Página de MITRE ATT&CK que detalla los efectos secundarios y detección de la inyección de DLL.

Estos recursos proporcionan información adicional sobre técnicas avanzadas, métodos y consideraciones relacionadas con la carga dinámica de DLLs en memoria en entornos Windows.

## Notas

- Este proyecto se proporciona con fines educativos y de investigación. Úselo bajo su propia responsabilidad.
- Asegúrese de tener los permisos adecuados antes de realizar pruebas en sistemas o entornos de producción.
- Consulte las leyes y regulaciones locales antes de utilizar este software en entornos en los que pueda haber restricciones legales.
- **Nota importante:** Por sí solo, este cargador de DLL no realiza el bypass de AMSI. Se requiere una DLL maliciosa diseñada específicamente para eludir la detección de AMSI. Este proyecto solo proporciona la infraestructura para cargar y ejecutar dicha DLL en memoria.
