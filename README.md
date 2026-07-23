# 🛡️ SecMonitor — Sistema SIEM de Monitoreo y Gestión de Riesgos

SecMonitor es un sistema **SIEM (Security Information and Event Management)** desarrollado desde cero como proyecto personal, orientado a la detección de patrones de ataque, correlación de incidentes, gestión de riesgos y generación automática de informes (incluyendo mapeo de cumplimiento ISO 27001). Desplegado en la nube con Firebase y Render.

---

## 🚀 Demo en vivo

> [https://secmonitor.onrender.com](https://secmonitor.onrender.com)
> *(el plan gratuito de Render puede tardar ~30s en despertar si lleva tiempo inactivo)*
> *(requiere iniciar sesión — ver sección de Autenticación)*

---

## ✨ Funcionalidades

### 🔐 Autenticación
- Acceso protegido con **Firebase Authentication** (email/contraseña)
- Todas las rutas de la API validan el token de sesión antes de responder
- Menús de acción agrupados de forma intuitiva (Descargar / Simular) en vez de botones sueltos

### 🖥️ Monitoreo en tiempo real
- Detección de patrones de ataque mediante motor de reglas personalizado
- Alertas clasificadas por severidad: **Crítica / Alta / Media / Baja**
- Actualización automática del dashboard cada 15 segundos
- Gráficos de tendencias: eventos por hora y alertas por día por severidad
- Botón para limpiar la vista de alertas sin borrar los datos
- Simulación de ataques con un clic (ataque simple o **secuencia completa de kill chain**)

### 🔗 Correlación multi-evento (Kill Chain Detection)
- Motor de correlación que rastrea el comportamiento de cada IP en una ventana de 30 minutos
- Si una misma IP encadena 2 o más etapas de ataque (ej: **reconocimiento → acceso a credenciales → acceso inicial**), se genera un **incidente crítico** independiente de las alertas individuales
- Detecta específicamente el patrón más peligroso: login exitoso *después* de un intento de fuerza bruta desde la misma IP (fuerte indicio de cuenta comprometida)
- Las alertas de kill chain muestran la secuencia completa de etapas detectadas

### 🔍 Reglas de detección + MITRE ATT&CK

| Regla | Condición | Severidad | Técnica MITRE |
|---|---|---|---|
| Fuerza bruta | >5 intentos fallidos desde la misma IP en 5 min | Alta | T1110 — Brute Force |
| Escaneo de puertos | Conexiones a >10 puertos distintos en 5 min | Media | T1046 — Network Service Discovery |
| Acceso fuera de horario | Login exitoso entre 00:00 y 05:00 | Baja | T1078 — Valid Accounts |
| Múltiples países | Mismo usuario desde >2 países en la misma ventana | Media | T1078.004 — Valid Accounts: Cloud Accounts |
| **Kill Chain** | 2+ etapas de ataque correlacionadas desde la misma IP | **Crítica** | Múltiples técnicas combinadas |

### 🌐 Threat Intelligence y geolocalización
- Integración con **AbuseIPDB**: score de reputación, ISP, país y detección de nodos TOR
- Panel de **consulta manual de IPs** desde el dashboard
- **Geolocalización automática** (ip-api.com) de cada IP atacante
- **Mapa de ataques interactivo** (Leaflet + tiles oscuros) con marcadores por severidad, incluyendo un marcador especial más grande para incidentes de kill chain

### 🛡️ Gestión de Riesgos
- Matriz de riesgos con 4 fases: **Identificación → Análisis → Mitigación → Riesgo Residual**
- Mapa de calor interactivo (5×5) con posicionamiento visual de cada riesgo
- Edición y eliminación de riesgos registrados

### 📄 Informes y exportación de datos
- Plantilla PDF profesional con portada, encabezados y pies de página estandarizados
- **Informe de monitoreo** — eventos, top IPs sospechosas, alertas altas con técnica MITRE, e incidentes de kill chain, por período (24h / 7d / 30d)
- **Informe de gestión de riesgos** — resumen ejecutivo, mapa de calor y detalle de cada riesgo con sus 4 fases
- **Informe de cumplimiento ISO/IEC 27001:2022** — mapeo de 12 controles del Anexo A relevantes a SecMonitor, clasificados en evidencia automática, proceso manual, o fuera de alcance (con disclaimer claro de que no constituye una certificación)
- **Exportación a CSV** de eventos y alertas, con codificación compatible con Excel

---

## 🏗️ Arquitectura

```
[Generador de eventos / Parser de logs]
              ↓
    [API REST — Express (Render)]
         ↓         ↓          ↓
 [Motor reglas] [AbuseIPDB] [GeoIP]
         ↓         ↓          ↓
   [Correlación Kill Chain (30 min)]
              ↓
       [Firestore (Firebase)]
              ↓
   [Firebase Auth — login requerido]
              ↓
[Dashboard Web] → [Mapa de ataques] → [Informes PDF / CSV / ISO 27001]
```

---

## 🛠️ Stack tecnológico

| Componente | Tecnología |
|---|---|
| Backend / API | Node.js + Express |
| Base de datos | Firebase Firestore |
| Autenticación | Firebase Authentication |
| Hosting backend | Render (Web Service) |
| Frontend | HTML + CSS + JavaScript vanilla |
| Gráficos | Chart.js |
| Mapa de ataques | Leaflet.js + CartoDB (tiles oscuros) |
| Threat Intelligence | AbuseIPDB API |
| Geolocalización | ip-api.com |
| Generación PDF | PDFKit |
| Clasificación de amenazas | MITRE ATT&CK Framework |
| Marco de cumplimiento | ISO/IEC 27001:2022 (Anexo A, mapeo propio) |
| Notificaciones | Telegram Bot API (opcional) |
| Simulación de eventos | Generador propio con motor de reglas |

---

## ⚙️ Instalación local

### Requisitos
- Node.js v18+
- Cuenta en [Firebase](https://console.firebase.google.com) con Firestore y Authentication activos
- Cuenta en [Render](https://render.com) (para deploy en la nube)
- API key gratuita de [AbuseIPDB](https://www.abuseipdb.com) (opcional, para threat intelligence)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/joanmanuelibacache/SecMonitor.git
cd SecMonitor

# 2. Instalar dependencias
npm install

# 3. Agregar credenciales de Firebase (Admin SDK)
# Descarga serviceAccountKey.json desde Firebase Console
# (Configuracion del proyecto -> Cuentas de servicio -> Generar nueva clave privada)
# y colocalo en la raiz del proyecto

# 4. Configurar variables de entorno
# Crea un archivo .env en la raiz con:
#   ABUSEIPDB_KEY=tu_clave_aqui
#   TELEGRAM_BOT_TOKEN=tu_token_aqui (opcional)
#   TELEGRAM_CHAT_ID=tu_chat_id_aqui (opcional)

# 5. Configurar Firebase Authentication
# En Firebase Console > Authentication > Sign-in method: habilita Email/Password
# En Authentication > Users: crea tu usuario de acceso al dashboard
# En public/index.html: reemplaza el objeto firebaseConfig con el de tu proyecto

# 6. Iniciar el servidor
node server.js
```

Abre [http://localhost:3000](http://localhost:3000), inicia sesión, y usa el menú **"🧪 Simular"** para generar datos de prueba (ataque simple o secuencia completa de kill chain).

---

## 🧪 Tests

```bash
node test.js
```

Verifica la generación de eventos y la detección correcta de cada patrón de ataque, sin falsos positivos.

---

## 🔭 Roadmap

- [x] Motor de reglas de detección (fuerza bruta, escaneo de puertos, accesos anómalos)
- [x] Backend API REST + persistencia en Firestore
- [x] Dashboard web con alertas en tiempo real
- [x] Generación de informes PDF (monitoreo y riesgos)
- [x] Gestión de riesgos con matriz completa y mapa de calor
- [x] Integración con **AbuseIPDB** para threat intelligence real
- [x] Plantilla visual profesional para los informes PDF
- [x] **Autenticación** con Firebase Auth
- [x] **Mapeo MITRE ATT&CK** por regla de detección
- [x] **Geolocalización de IPs** con mapa de ataques interactivo
- [x] **Correlación multi-evento** (kill chain detection)
- [x] **Exportación a CSV** de eventos y alertas
- [x] **Informe de cumplimiento ISO/IEC 27001:2022**
- [ ] Notificaciones en tiempo real vía bot de Telegram (implementado, pendiente de activar en producción)
- [ ] Migración a logs reales desde entorno de laboratorio (VM aislada)

---

## 👤 Autor

**Joan Manuel Castro**
Técnico en Ciberseguridad | Estudiante de Ingeniería en Informática
[Portafolio](https://joanmanuelibacache.github.io) · [LinkedIn](https://www.linkedin.com/in/joan-ibacache-2202a8415) · [Hack The Box](https://profile.hackthebox.com/profile/019f06dc-0f00-7262-8808-d4a0ca774091)

---

> ⚠️ Este proyecto es de uso educativo y para entorno de laboratorio controlado. No utilizar en sistemas sin autorización explícita. El informe de cumplimiento ISO 27001 documenta soporte técnico de controles puntuales y no constituye una certificación ni un Sistema de Gestión de Seguridad de la Información (SGSI) completo.
