# Opciones al crear un nuevo IOC en IOCe 2.2.0

Cuando inicias un nuevo IOC en **IOCe 2.2.0** (mediante **Archivo > Nuevo**), el programa te permite definir un documento IOC con metadatos y una lista de indicadores. A continuación, se describen las categorías y los tipos de términos/indicadores que puedes configurar en el **Editor de términos**, junto con las opciones para trabajar con un IOC ya importado.

## 1. Metadatos del IOC
Estas opciones describen el IOC en sí, proporcionando contexto sobre su propósito y origen. Se configuran al inicio de la creación del IOC o en una sección de propiedades generales.

- **ID del IOC**:
  - Un identificador único para el IOC (normalmente un GUID, generado automáticamente por IOCe).
  - Ejemplo: `ioc-123e4567-e89b-12d3-a456-426614174000`.

- **Nombre del IOC**:
  - Un nombre descriptivo para el IOC.
  - Ejemplo: `Trojan_XYZ_2025`.

- **Descripción**:
  - Un campo de texto libre para describir la amenaza o el propósito del IOC.
  - Ejemplo: `Indicadores de un troyano detectado en servidores de Europa`.

- **Autor**:
  - El nombre o la organización que creó el IOC.
  - Ejemplo: `Equipo de Ciberseguridad ACME`.

- **Fecha de creación**:
  - La fecha en que se creó el IOC (puede ser automática o editable).
  - Ejemplo: `2025-05-09`.

- **Fecha de última modificación**:
  - Actualizada automáticamente al editar el IOC.

- **Palabras clave (Keywords)**:
  - Etiquetas para clasificar el IOC.
  - Ejemplo: `malware`, `trojan`, `phishing`.

- **Nivel de confidencialidad**:
  - Define quién puede acceder al IOC (si el sistema lo soporta).
  - Opciones típicas: `Público`, `Privado`, `Restringido`.

- **Enlaces (References)**:
  - URLs o referencias a fuentes externas relacionadas con la amenaza.
  - Ejemplo: `https://otx.alienvault.com/pulse/12345`.

## 2. Indicadores (Términos del IOC)
Los indicadores son los elementos clave que describen la amenaza. En el **Editor de términos** de IOCe, puedes añadir múltiples indicadores, cada uno con un tipo, valor y condiciones. A continuación, se enumeran los tipos de indicadores más comunes que soporta IOCe (basados en el estándar OpenIOC):

### a. Indicadores relacionados con archivos
- **FileHash-MD5**:
  - Hash MD5 de un archivo malicioso.
  - Ejemplo: `d41d8cd98f00b204e9800998ecf8427e`.
- **FileHash-SHA1**:
  - Hash SHA1 de un archivo.
  - Ejemplo: `da39a3ee5e6b4b0d3255bfef95601890afd80709`.
- **FileHash-SHA256**:
  - Hash SHA256 de un archivo.
  - Ejemplo: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- **FileName**:
  - Nombre del archivo sospechoso.
  - Ejemplo: `malware.exe`.
- **FileSize**:
  - Tamaño del archivo en bytes.
  - Ejemplo: `102400` (100 KB).
- **FilePath**:
  - Ruta donde se encuentra el archivo.
  - Ejemplo: `C:\Windows\Temp\malware.exe`.
- **FileType**:
  - Tipo de archivo (basado en su firma o extensión).
  - Ejemplo: `PE` (ejecutable de Windows), `PDF`, `DOC`.
- **FilePEVersion**:
  - Versión del archivo ejecutable (para archivos PE).
  - Ejemplo: `1.0.0.1`.
- **FilePECompanyName**:
  - Nombre de la empresa en los metadatos del archivo PE.
  - Ejemplo: `Unknown`.

### b. Indicadores relacionados con la red
- **IPv4Address**:
  - Dirección IPv4 maliciosa.
  - Ejemplo: `192.168.1.100`.
- **IPv6Address**:
  - Dirección IPv6 maliciosa.
  - Ejemplo: `2001:0db8:85a3:0000:0000:8a2e:0370:7334`.
- **Domain**:
  - Nombre de dominio asociado a una amenaza.
  - Ejemplo: `malicious.com`.
- **URL**:
  - URL específica relacionada con la amenaza.
  - Ejemplo: `http://malicious.com/download.php`.
- **Port**:
  - Puerto de red usado por la amenaza.
  - Ejemplo: `8080`.
- **NetworkProtocol**:
  - Protocolo de red involucrado.
  - Ejemplo: `TCP`, `UDP`, `HTTP`.
- **DNSQuery**:
  - Consulta DNS sospechosa.
  - Ejemplo: `malicious.com`.

### c. Indicadores relacionados con el sistema
- **RegistryKey**:
  - Clave de registro de Windows asociada a la amenaza.
  - Ejemplo: `HKLM\Software\Malware`.
- **RegistryValue**:
  - Valor específico en una clave de registro.
  - Ejemplo: `Run=malware.exe`.
- **ProcessName**:
  - Nombre del proceso malicioso.
  - Ejemplo: `svchost.exe`.
- **ProcessPID**:
  - ID del proceso (PID) asociado.
  - Ejemplo: `1234`.
- **ServiceName**:
  - Nombre de un servicio de Windows malicioso.
  - Ejemplo: `MalwareService`.
- **Mutex**:
  - Nombre de un mutex creado por el malware.
  - Ejemplo: `Global\MalwareMutex`.

### d. Indicadores relacionados con el comportamiento
- **YARA Rule**:
  - Regla YARA para detectar patrones en archivos o memoria.
  - Ejemplo: `rule malware { strings: $a = "malware" condition: $a }`.
- **Snort Rule**:
  - Regla Snort para detectar tráfico de red sospechoso.
  - Ejemplo: `alert tcp any any -> any 80 (msg:"Malware"; content:"malware";)`.
- **BehaviorDescription**:
  - Descripción de un comportamiento malicioso.
  - Ejemplo: `Crea un archivo en C:\Temp`.

### e. Indicadores genéricos
- **EmailAddress**:
  - Dirección de correo usada en phishing u otras amenazas.
  - Ejemplo: `attacker@malicious.com`.
- **PhoneNumber**:
  - Número de teléfono asociado a una estafa.
  - Ejemplo: `+1234567890`.
- **Text**:
  - Campo de texto genérico para cualquier indicador no estructurado.
  - Ejemplo: `Código de error: 0x80070057`.

## 3. Condiciones y operadores lógicos
Para cada indicador, puedes definir condiciones que especifican cómo se debe interpretar el valor. Estas opciones suelen estar disponibles en el **Editor de términos** al añadir un indicador:

- **Condiciones**:
  - `is`: El valor coincide exactamente.
  - `contains`: El valor contiene el texto especificado.
  - `starts with`: El valor comienza con el texto.
  - `ends with`: El valor termina con el texto.
  - `greater than`: Para valores numéricos (como FileSize o Port).
  - `less than`: Para valores numéricos.
  - `matches`: Coincide con una expresión regular.
  - Ejemplo: Para un indicador `FileName`, puedes establecer `contains "malware"`.

- **Operadores lógicos**:
  - `AND`: Todos los indicadores deben coincidir para que el IOC sea válido.
  - `OR`: Al menos uno de los indicadores debe coincidir.
  - `NOT`: Excluye un indicador específico.
  - Ejemplo: `(FileHash-MD5 is "abc123") AND (IPv4Address is "192.168.1.1")`.

## 4. Opciones de estructura del IOC
IOCe permite organizar los indicadores en una estructura jerárquica para definir relaciones complejas:

- **Agrupar indicadores**:
  - Crea grupos de indicadores con operadores lógicos (AND/OR).
  - Ejemplo: Un grupo para "Archivos" y otro para "Red".
- **Indicadores anidados**:
  - Define subindicadores dentro de un indicador principal.
  - Ejemplo: Un indicador `ProcessName` puede incluir un subindicador `Mutex`.

## 5. Opciones de guardado y exportación
Una vez configurado el IOC, puedes guardarlo o exportarlo con estas opciones:

- **Formato de archivo**:
  - `OpenIOC`: Formato estándar para IOCe (XML).
  - `XML genérico`: Para compatibilidad con otras herramientas.
- **Ubicación**:
  - Guarda el archivo en tu sistema (por ejemplo, `C:\IOCs\my_ioc.ioc`).
- **Codificación**:
  - UTF-8 (predeterminada) u otra codificación compatible.

## 6. Opciones avanzadas (si están disponibles)
Dependiendo de la implementación de IOCe 2.2.0, podrías encontrar estas funciones adicionales:

- **Plantillas**:
  - Usar plantillas predefinidas para tipos comunes de amenazas (por ejemplo, ransomware, phishing).
- **Validación**:
  - Verificar que el IOC cumple con el estándar OpenIOC antes de guardarlo.
- **Importar términos**:
  - Cargar una lista de términos desde un archivo externo (como CSV) para agilizar la creación.
- **Personalización del Editor de términos**:
  - Añadir nuevos tipos de indicadores personalizados (por ejemplo, un tipo propio como `CustomMalwareID`).

## 7. Opciones al trabajar con un IOC ya importado
Cuando importas un IOC existente (por ejemplo, desde AlienVault OTX u otra fuente) en IOCe 2.2.0, puedes realizar las siguientes acciones además de las opciones de creación descritas anteriormente:

- **Abrir el IOC**:
  - Ve a **Archivo > Abrir** y selecciona el archivo IOC (en formato OpenIOC o XML).
  - Ejemplo: Cargar `webscanners.ioc` descargado de OTX.

- **Visualizar indicadores**:
  - Usa el **Visor de IOC** para explorar los indicadores y metadatos importados.
  - Ejemplo: Ver hashes, IPs o URLs definidos en el archivo.

- **Editar metadatos**:
  - Modifica campos como **Nombre**, **Descripción**, **Autor** o **Palabras clave** para adaptarlos a tus necesidades.
  - Ejemplo: Cambiar la descripción a `Actualizado con datos locales`.

- **Editar indicadores**:
  - Usa el **Editor de términos** para:
    - **Añadir nuevos indicadores**: Agrega indicadores adicionales (por ejemplo, una nueva IP detectada).
    - **Modificar indicadores existentes**: Cambia valores, condiciones o tipos (por ejemplo, actualizar un hash MD5).
    - **Eliminar indicadores**: Quita indicadores irrelevantes.
  - Ejemplo: Añadir un indicador `Domain` con valor `newmalicious.com`.

- **Ajustar la lógica**:
  - Modifica los operadores lógicos (AND/OR/NOT) o la estructura jerárquica de los indicadores.
  - Ejemplo: Cambiar un grupo de `(IPv4Address OR Domain)` a `(IPv4Address AND Domain)`.

- **Validar el IOC**:
  - Verifica que el IOC importado y editado cumpla con el estándar OpenIOC.
  - Ejemplo: Asegurarte de que no haya errores en los formatos de los hashes.

- **Reorganizar indicadores**:
  - Agrupa o reordena indicadores para mejorar la claridad.
  - Ejemplo: Separar indicadores de red y archivos en grupos distintos.

- **Exportar el IOC modificado**:
  - Guarda los cambios como un nuevo archivo IOC.
  - Opciones:
    - **Formato**: OpenIOC o XML.
    - **Ubicación**: Por ejemplo, `C:\IOCs\updated_ioc.ioc`.
  - Ejemplo: Exportar el IOC editado para compartirlo con un SIEM.

- **Importar términos desde otros formatos** (si es compatible):
  - Si el IOC importado está en un formato no nativo (como CSV desde OTX), copia y pega manualmente los valores en el Editor de términos.
  - Ejemplo: Importar una lista de IPs desde un CSV y añadirlas como indicadores `IPv4Address`.

- **Comparar con el original** (si está disponible):
  - Algunas versiones de IOCe podrían permitirte comparar el IOC importado con el editado para rastrear cambios.
  - Ejemplo: Ver qué indicadores se añadieron o eliminaron.

## Cómo usar estas opciones en IOCe

### Para un IOC nuevo:
1. **Inicia un nuevo IOC**:
   - Ve a **Archivo > Nuevo**.
   - Define los metadatos (nombre, descripción, autor, etc.).
2. **Añade indicadores**:
   - En el **Editor de términos**, selecciona **Añadir término** (o similar).
   - Elige el tipo de indicador (por ejemplo, `FileHash-MD5`).
   - Ingresa el valor (por ejemplo, `d41d8cd98f00b204e9800998ecf8427e`).
   - Define la condición (por ejemplo, `is`).
   - Repite para cada indicador necesario.
3. **Organiza la lógica**:
   - Usa operadores lógicos (AND/OR) para conectar indicadores.
   - Agrupa indicadores relacionados si es necesario.
4. **Guarda el IOC**:
   - Ve a **Archivo > Guardar**.
   - Elige el formato (OpenIOC o XML) y la ubicación.

### Para un IOC importado:
1. **Abre el IOC**:
   - Ve a **Archivo > Abrir** y selecciona el archivo IOC.
2. **Revisa y edita**:
   - Explora los metadatos y indicadores en el **Visor de IOC**.
   - Modifica metadatos o indicadores en el **Editor de términos** según sea necesario.
3. **Ajusta la lógica**:
   - Cambia operadores lógicos o la estructura de los indicadores.
4. **Guarda los cambios**:
   - Ve a **Archivo > Guardar** o **Guardar como** para crear una nueva versión del IOC.

## Ejemplo práctico
Supongamos que quieres crear un IOC para un troyano basado en datos de OTX, o editar uno importado:

### Creación de un IOC nuevo:
- **Metadatos**:
  - Nombre: `Trojan_XYZ_2025`.
  - Descripción: `Indicadores de un troyano detectado en servidores`.
  - Autor: `Analista123`.
- **Indicadores**:
  - Tipo: `FileHash-SHA256`, Valor: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, Condición: `is`.
  - Tipo: `IPv4Address`, Valor: `192.168.1.100`, Condición: `is`.
  - Tipo: `URL`, Valor: `http://malicious.com/trojan`, Condición: `is`.
- **Lógica**: `(FileHash-SHA256 is "...") OR (IPv4Address is "192.168.1.100")`.
- **Guardado**: Como `trojan_xyz.ioc` en formato OpenIOC.

### Edición de un IOC importado:
- **Abrir**: Carga `webscanners.ioc` desde OTX.
- **Editar metadatos**:
  - Cambia la descripción a `Webscanners detectados en red local`.
  - Añade una palabra clave: `scanner`.
- **Editar indicadores**:
  - Añade un nuevo indicador: Tipo: `Domain`, Valor: `scanner.com`, Condición: `is`.
  - Modifica un indicador existente: Cambia una IP de `192.168.1.100` a `10.0.0.1`.
  - Elimina un indicador obsoleto: Por ejemplo, un hash irrelevante.
- **Ajustar lógica**: Cambia un grupo de `(IPv4Address OR Domain)` a `(IPv4Address AND Domain)`.
- **Exportar**: Guarda como `updated_webscanners.ioc`.

## Notas y limitaciones
- **Versión específica**: La lista anterior asume que IOCe 2.2.0 soporta todos los tipos de indicadores estándar de OpenIOC. Si la versión tiene limitaciones (por ejemplo, no soporta YARA o Snort), algunas opciones podrían no estar disponibles.
- **Interfaz**: Las opciones exactas pueden variar según la interfaz de IOCe. Busca menús como "Añadir término", "Editar indicador" o "Propiedades" en el **Editor de términos**.
- **Compatibilidad con OTX**: Si los IOCs provienen de OTX, asegúrate de que los tipos de indicadores (como `IPv4Address` o `FileHash`) coincidan con los soportados por IOCe. Para formatos no nativos (como CSV), importa manualmente los valores al Editor de términos.
- **Funcionalidad avanzada**: Opciones como plantillas o comparación de IOCs podrían no estar disponibles en IOCe 2.2.0, dependiendo de su implementación.
