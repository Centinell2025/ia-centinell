<div align="center">
  <img src="https://raw.githubusercontent.com/Centinell2025/the-last-evidence-standing/main/branding/BEACON_SEAL.png" alt="Beacon of the Eagle LLC — logotipo corporativo" width="165" />
  <p><strong>BEACON OF THE EAGLE LLC</strong><br/><strong>CENTINELL SUITE DEFENSE</strong></p>
</div>

# ia-centinell


## Arranque local reproducible

Requiere Node.js 22 o posterior y npm. Desde la raíz:

```sh
cd Backend
npm ci
npm test
npm start
```

Abrir http://127.0.0.1:3000. El servidor solo escucha en loopback, no necesita claves
ni base de datos y sirve el dashboard real de la raíz. `PORT` permite otro puerto.
`GET /api/health` informa el modo demo, la memoria volátil y la IA no disponible.
No se sirven el código del backend ni archivos de configuración por HTTP.

## Qué funciona y qué no

- Navegación de 15 secciones, demostraciones visuales, registro local de eventos,
  SHA-256 de texto y de bytes de archivos, comparación con la firma de prueba EICAR.
- File Guardian guarda un hash en memoria y pide volver a seleccionar los archivos
  para comparar su contenido actual. No puede observar cambios del disco por sí solo.
- La interfaz es una demostración local, no un cliente de autenticación empresarial.
  Sus datos se reinician al recargar. La API experimental también usa memoria volátil.
- Dispositivos, red, protección, amenazas, infraestructura y clientes son simulados.
  Los registros de cuarentena no aíslan ni limpian archivos reales.
- IA no disponible: no hay proveedor configurado. No se solicitan claves en el
  navegador ni se envían datos a proveedores. Las rutas de análisis devuelven 503;
  no generan conclusiones ficticias. Configurar una variable no activa un proveedor.
- Un archivo sin coincidencia EICAR no se declara seguro. No es un antivirus.
- No hay persistencia, aislamiento multiempresa ni controles de producción. Esta
  rama es para validar la demostración, no para desplegar o vender como protección activa.

## Verificación

`npm test` ejecuta pruebas HTTP y de DOM con jsdom: arranque, rutas, límites de
archivos servidos, estado de IA, firmas, hashes binarios, navegación, mensajes y
selección de archivos. No sustituye una revisión visual en navegador real.
Los ejemplos y documentos de arquitectura existentes se conservan como referencia;
no todos describen funciones implementadas. No se eliminó ni fusionó ningún repositorio.
