# Simulador de Política de Seguridad - Laboratorio Universitario

## Descripción

Esta implementación de juguete demuestra los conceptos principales de la política de seguridad propuesta para un laboratorio de computación universitaria, incluyendo:

1. **Control de Acceso (DAC/MAC)**
2. **Autenticación con MFA**
3. **Auditoría y Monitoreo**

## 📁 Estructura del Proyecto

```
laboratorio-seguridad/
├── lab_security_system.py    # Simulador principal
├── demo_interactivo.py       # Demo interactivo
├── README.md                 # Documentación
├── .gitignore               # Archivos ignorados por Git
└── .venv/                   # Entorno virtual (ignorado)
```

## Componentes Implementados

### 1. Sistema de Autenticación

- **Política de contraseñas**: Mínimo 12 caracteres, mayúsculas, minúsculas, números y símbolos especiales
- **Autenticación multifactor (MFA)**: Simulado para cuentas administrativas
- **Bloqueo automático**: Después de 5 intentos fallidos
- **Hash seguro**: SHA-512 para almacenamiento de contraseñas

### 2. Control de Acceso

#### DAC (Discretionary Access Control)
- Permisos específicos por usuario y recurso
- Acceso a directorios personales
- Principio de mínimo privilegio

#### MAC (Mandatory Access Control) - Simulación de AppArmor
- Lista de software bloqueado
- Restricciones basadas en roles
- Control de software de sistema

### 3. Sistema de Auditoría

- **Logging centralizado**: Todos los eventos se registran con timestamp
- **Monitoreo en tiempo real**: Alertas para archivos críticos
- **Reportes de seguridad**: Estadísticas y eventos recientes
- **Detección de anomalías**: Identificación de patrones sospechosos

## Usuarios Predefinidos

| Usuario | Contraseña | Rol | MFA | Descripción |
|---------|------------|-----|-----|-------------|
| estudiante1 | Password123! | STUDENT | No | Usuario estudiante básico |
| profesor1 | Prof@Pass456 | PROFESSOR | Sí | Usuario profesor con permisos intermedios |
| admin | Admin$ecure789 | ADMIN | Sí | Administrador con acceso completo |

## Recursos del Sistema

- `/home/estudiante1/` - Directorio personal del estudiante
- `/shared/` - Directorio compartido
- `/etc/passwd` - Archivo crítico del sistema (solo admin)

## Cómo Ejecutar

### 1. Demo Automático
```bash
python lab_security_system.py
```

Este comando ejecuta una demostración completa que muestra:
- Intentos de autenticación exitosos y fallidos
- Verificación de control de acceso
- Funcionamiento de AppArmor (MAC)
- Monitoreo de archivos críticos
- Generación de reportes de auditoría

### 2. Demo Interactivo
```bash
python demo_interactivo.py
```

Este comando abre un menú interactivo donde puedes:
- Probar diferentes combinaciones de usuario/contraseña
- Verificar permisos de acceso a recursos
- Simular ejecución de software
- Crear nuevos usuarios
- Ver reportes de auditoría en tiempo real

## Ejemplos de Uso

### Ejemplo 1: Autenticación Exitosa
```
Usuario: estudiante1
Contraseña: Password123!
Resultado: Autenticación exitosa
```

### Ejemplo 2: Bloqueo por MFA
```
Usuario: admin
Contraseña: Admin$ecure789
Código MFA: (código incorrecto)
Resultado: Código MFA requerido o incorrecto
```

### Ejemplo 3: Control de Acceso DAC
```
Usuario: estudiante1
Recurso: /etc/passwd
Acceso: READ
Resultado: Acceso denegado - permisos insuficientes
```

### Ejemplo 4: AppArmor MAC
```
Usuario: estudiante1
Software: virus.exe
Resultado: Software 'virus.exe' bloqueado por política AppArmor
```

## Conceptos Demostrados

### Autenticación
- ✅ Política de contraseñas seguras
- ✅ Autenticación multifactor
- ✅ Bloqueo automático por intentos fallidos
- ✅ Hash seguro de contraseñas

### Control de Acceso
- ✅ DAC (Control Discrecional)
- ✅ MAC (Control Obligatorio) vía AppArmor
- ✅ Principio de mínimo privilegio
- ✅ Separación de cuentas administrativas

### Auditoría
- ✅ Logging centralizado con timestamps
- ✅ Monitoreo de archivos críticos
- ✅ Alertas SIEM simuladas
- ✅ Reportes de seguridad
- ✅ Retención de logs

## Flujo de Seguridad Demostrado

1. **Usuario intenta autenticarse** → Sistema verifica credenciales y MFA
2. **Usuario solicita acceso a recurso** → Sistema verifica permisos DAC
3. **Usuario intenta ejecutar software** → AppArmor verifica política MAC
4. **Todos los eventos se registran** → Sistema de auditoría genera logs
5. **Acceso a archivos críticos** → SIEM genera alertas en tiempo real

## Extensiones Posibles

Para hacer la implementación más robusta, se podrían agregar:

- Integración con base de datos real
- Encriptación de logs
- Políticas de rotación de contraseñas
- Integración con Active Directory
- Monitoreo de red
- Análisis de comportamiento de usuarios
- Notificaciones por email/SMS

## Notas Técnicas

- **Lenguaje**: Python 3.x
- **Dependencias**: Solo librerías estándar
- **Arquitectura**: Modular y extensible
- **Logs**: En memoria (para demo), fácilmente extensible a archivos
- **Seguridad**: Implementa mejores prácticas para demo educativo

---

*Esta implementación es únicamente para fines educativos y demostración de conceptos de seguridad.*
