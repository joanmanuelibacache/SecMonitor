# 🛡️ SecMonitor — Sistema SIEM de Monitoreo y Gestión de Riesgos

SecMonitor es un sistema **SIEM (Security Information and Event Management)** desarrollado desde cero como proyecto personal, orientado a la detección de patrones de ataque, gestión de riesgos de seguridad y generación automática de informes. Desplegado en la nube con Firebase y Render.

---

## 🚀 Demo en vivo

> [https://secmonitor.onrender.com](https://secmonitor.onrender.com)
> *(el plan gratuito de Render puede tardar ~30s en despertar si lleva tiempo inactivo)*
> *(requiere iniciar sesión — ver sección de Autenticación)*

---

## ✨ Funcionalidades

### 🔐 Autenticación
- Acceso protegido con **Firebase Authentication** (email/contraseña)
- Todas las rutas de la API validan el token de sesión antes de responder — sin login, no hay acceso a datos
- Botón de simulación de ataques integrado directamente en el dashboard, sin necesidad de comandos externos

### 🖥️ Monitoreo en tiempo real
- Detección de patrones de ataque mediante motor de reglas personalizado
- Alertas clasificadas por severidad: **Alta / Media / Baja**
- Actualización automática del dashboard cada 15 segundos
- Gráficos de tendencias: eventos por hora (últimas 24h) y alertas por día (últimos 7 días)
- Botón para limpiar la vista de alertas sin borrar los datos
- Botón de **simulación de ataques** con un clic para generar tráfico de prueba

### 🔍 Reglas de detección + MITRE ATT&CK

Cada regla está mapeada a su técnica correspondiente del framework **MITRE ATT&CK**, el estándar de la industria para clasificar amenazas:

| Regla | Condición | Severidad | Técnica MITRE |
|---|---|---|---|
| Fuerza bruta | >5 intentos fallidos desde la misma IP en 5 min | Alta | T1110 — Brute Force |
| Escaneo de puertos | Conexiones a >10 puertos distintos en 5 min | Media | T1046 — Network Service Discovery |
| Acceso fuera de horario | Login exitoso entre 00:00 y 05:00 | Baja | T1078 — Valid Accounts |
| Múltiples países | Mismo usuario desde >2 países en la misma ventana | Media | T1078.004 — Valid Accounts: Cloud Accounts |

### 🌐 Threat Intelligence y geolocalización
- Integración con **AbuseIPDB**: cada IP detectada se enriquece con su score de reputación, ISP, país y si es nodo TOR
- Panel de **consulta manual de IPs** — busca cualquier IP directamente desde el dashboard
- **Geolocalización automática** (ip-api.com) de cada IP atacante
- **Mapa de ataques interactivo** (Leaflet + tiles oscuros) con marcadores coloreados por severidad y popups con el detalle de cada alerta

### 🛡️ Gestión de Riesgos
- Matriz de riesgos con proceso completo de 4 fases:
  1. **Identificación** — nombre, descripción, categoría, activos afectados
  2. **Análisis** — puntuación de probabilidad × impacto con previsualización en tiempo real
  3. **Mitigación** — estrategia, responsable, fecha límite y estado
  4. **Riesgo Residual** — cálculo del riesgo remanente tras la mitigación y % de reducción
- Mapa de calor interactivo (5×5) con posicionamiento visual de cada riesgo
- Edición y eliminación de riesgos registrados

### 📄 Informes PDF profesionales
- Plantilla visual con portada, encabezados y pies de página estandarizados
- **Informe de monitoreo** — resumen de eventos, top IPs sospechosas (con datos de AbuseIPDB), alertas altas con su técnica MITRE, por período (24h / 7d / 30d)
- **Informe de gestión de riesgos** — portada, resumen ejecutivo, mapa de calor y detalle completo de cada riesgo con sus 4 fases

---

## 🏗️ Arquitectura

```
[Generador de eventos / Parser de logs]
              ↓
    [API REST — Express (Render)]
         ↓         ↓          ↓
 [Motor reglas] [AbuseIPDB] [GeoIP]
         ↓         ↓          ↓
       [Firestore (Firebase)]
              ↓
   [Firebase Auth — login requerido]
              ↓
   [Dashboard Web] → [Mapa de ataques] → [Informes PDF]
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

# 5. Configurar Firebase Authentication
# En Firebase Console > Authentication > Sign-in method: habilita Email/Password
# En Authentication > Users: crea tu usuario de acceso al dashboard
# En public/index.html: reemplaza el objeto firebaseConfig con el de tu proyecto
# (Configuracion del proyecto > Tus apps > Web app)

# 6. Iniciar el servidor
node server.js
```

Abre [http://localhost:3000](http://localhost:3000), inicia sesión con el usuario creado en el paso 5, y usa el botón **"⚡ Simular ataque"** del dashboard para generar datos de prueba.

---

## 🧪 Tests

El proyecto incluye tests automatizados para verificar el motor de reglas de detección:

```bash
node test.js
```

Verifica 6 casos: generación de eventos, detección correcta de cada patrón de ataque y ausencia de falsos positivos.

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
- [ ] Correlación multi-evento (kill chain detection)
- [ ] Notificaciones en tiempo real vía bot de Telegram
- [ ] Exportación a CSV
- [ ] Migración a logs reales desde entorno de laboratorio (VM aislada)
- [ ] Reportes de cumplimiento (ISO 27001 / SOC 2)

---

## 👤 Autor

**Joan Manuel Castro**
Técnico en Ciberseguridad | Estudiante de Ingeniería en Informática
[Portafolio](https://joanmanuelibacache.github.io) · [LinkedIn](https://www.linkedin.com/in/joan-ibacache-2202a8415) · [Hack The Box](https://profile.hackthebox.com/profile/019f06dc-0f00-7262-8808-d4a0ca774091)

---

> ⚠️ Este proyecto es de uso educativo y para entorno de laboratorio controlado. No utilizar en sistemas sin autorización explícita.