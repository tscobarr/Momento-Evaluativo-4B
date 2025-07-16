#!/usr/bin/env python3
"""
Simulador de Política de Seguridad para Laboratorio Universitario
Implementa conceptos de Control de Acceso, Autenticación y Auditoría
"""

import hashlib
import datetime
import json
import os
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class UserRole(Enum):
    STUDENT = "student"
    PROFESSOR = "professor"
    ADMIN = "admin"

class AccessLevel(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"

@dataclass
class User:
    username: str
    password_hash: str
    role: UserRole
    failed_attempts: int = 0
    locked: bool = False
    last_login: Optional[datetime.datetime] = None
    mfa_enabled: bool = False
    home_directory: str = ""

@dataclass
class Resource:
    path: str
    owner: str
    permissions: Dict[str, List[AccessLevel]]
    is_critical: bool = False

@dataclass
class AuditEvent:
    timestamp: datetime.datetime
    user: str
    action: str
    resource: str
    result: str
    details: str

class SecuritySystem:
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.resources: Dict[str, Resource] = {}
        self.audit_log: List[AuditEvent] = []
        self.blocked_software = ["virus.exe", "keylogger.py", "malware.bat"]
        self.critical_files = ["/etc/passwd", "/var/log/", "C:\\Windows\\System32\\"]
        self.setup_default_users()
        self.setup_default_resources()

    def setup_default_users(self):
        """Configurar usuarios por defecto del sistema"""
        # Estudiante
        self.users["estudiante1"] = User(
            username="estudiante1",
            password_hash=self._hash_password("Password123!"),
            role=UserRole.STUDENT,
            mfa_enabled=False,
            home_directory="/home/estudiante1"
        )
        
        # Profesor
        self.users["profesor1"] = User(
            username="profesor1",
            password_hash=self._hash_password("Prof@Pass456"),
            role=UserRole.PROFESSOR,
            mfa_enabled=True,
            home_directory="/home/profesor1"
        )
        
        # Administrador
        self.users["admin"] = User(
            username="admin",
            password_hash=self._hash_password("Admin$ecure789"),
            role=UserRole.ADMIN,
            mfa_enabled=True,
            home_directory="/home/admin"
        )

    def setup_default_resources(self):
        """Configurar recursos por defecto del sistema"""
        # Directorio personal de estudiante
        self.resources["/home/estudiante1"] = Resource(
            path="/home/estudiante1",
            owner="estudiante1",
            permissions={
                "estudiante1": [AccessLevel.READ, AccessLevel.WRITE, AccessLevel.EXECUTE],
                "profesor1": [AccessLevel.READ],
                "admin": [AccessLevel.READ, AccessLevel.WRITE, AccessLevel.EXECUTE, AccessLevel.DELETE]
            }
        )
        
        # Directorio compartido
        self.resources["/shared"] = Resource(
            path="/shared",
            owner="admin",
            permissions={
                "estudiante1": [AccessLevel.READ],
                "profesor1": [AccessLevel.READ, AccessLevel.WRITE],
                "admin": [AccessLevel.READ, AccessLevel.WRITE, AccessLevel.EXECUTE, AccessLevel.DELETE]
            }
        )
        
        # Archivo crítico del sistema
        self.resources["/etc/passwd"] = Resource(
            path="/etc/passwd",
            owner="admin",
            permissions={
                "admin": [AccessLevel.READ, AccessLevel.WRITE]
            },
            is_critical=True
        )

    def _hash_password(self, password: str) -> str:
        """Hashear contraseña usando SHA-512"""
        return hashlib.sha512(password.encode()).hexdigest()

    def _validate_password_policy(self, password: str) -> Tuple[bool, str]:
        """Validar política de contraseñas"""
        if len(password) < 12:
            return False, "La contraseña debe tener al menos 12 caracteres"
        
        if not re.search(r'[A-Z]', password):
            return False, "La contraseña debe contener al menos una mayúscula"
        
        if not re.search(r'[a-z]', password):
            return False, "La contraseña debe contener al menos una minúscula"
        
        if not re.search(r'\d', password):
            return False, "La contraseña debe contener al menos un número"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "La contraseña debe contener al menos un símbolo especial"
        
        return True, "Contraseña válida"

    def _log_event(self, user: str, action: str, resource: str, result: str, details: str = ""):
        """Registrar evento en el log de auditoría"""
        event = AuditEvent(
            timestamp=datetime.datetime.now(),
            user=user,
            action=action,
            resource=resource,
            result=result,
            details=details
        )
        self.audit_log.append(event)
        print(f"[AUDIT] {event.timestamp} - {user} - {action} - {resource} - {result}")

    def authenticate(self, username: str, password: str, mfa_code: Optional[str] = None) -> Tuple[bool, str]:
        """Autenticar usuario (Componente de Autenticación)"""
        if username not in self.users:
            self._log_event(username, "LOGIN_ATTEMPT", "system", "FAILED", "Usuario no existe")
            return False, "Usuario no encontrado"
        
        user = self.users[username]
        
        # Verificar si la cuenta está bloqueada
        if user.locked:
            self._log_event(username, "LOGIN_ATTEMPT", "system", "BLOCKED", "Cuenta bloqueada")
            return False, "Cuenta bloqueada por múltiples intentos fallidos"
        
        # Verificar contraseña
        if user.password_hash != self._hash_password(password):
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked = True
                self._log_event(username, "ACCOUNT_LOCKED", "system", "SUCCESS", "5 intentos fallidos")
            
            self._log_event(username, "LOGIN_ATTEMPT", "system", "FAILED", f"Contraseña incorrecta (intento {user.failed_attempts})")
            return False, "Contraseña incorrecta"
        
        # Verificar MFA si está habilitado
        if user.mfa_enabled:
            if not mfa_code or mfa_code != "123456":  # Código MFA simulado
                self._log_event(username, "MFA_ATTEMPT", "system", "FAILED", "Código MFA incorrecto")
                return False, "Código MFA requerido o incorrecto"
        
        # Login exitoso
        user.failed_attempts = 0
        user.last_login = datetime.datetime.now()
        self._log_event(username, "LOGIN", "system", "SUCCESS", "Autenticación exitosa")
        return True, "Autenticación exitosa"

    def check_access(self, username: str, resource_path: str, access_type: AccessLevel) -> Tuple[bool, str]:
        """Verificar control de acceso (DAC - Discretionary Access Control)"""
        if username not in self.users:
            return False, "Usuario no válido"
        
        user = self.users[username]
        
        # Los administradores tienen acceso completo
        if user.role == UserRole.ADMIN:
            self._log_event(username, f"ACCESS_{access_type.value.upper()}", resource_path, "GRANTED", "Privilegios de admin")
            return True, "Acceso concedido (privilegios de administrador)"
        
        # Verificar permisos específicos del recurso
        if resource_path in self.resources:
            resource = self.resources[resource_path]
            
            if username in resource.permissions:
                if access_type in resource.permissions[username]:
                    self._log_event(username, f"ACCESS_{access_type.value.upper()}", resource_path, "GRANTED", "Permisos DAC")
                    return True, "Acceso concedido"
            
            self._log_event(username, f"ACCESS_{access_type.value.upper()}", resource_path, "DENIED", "Sin permisos DAC")
            return False, "Acceso denegado - permisos insuficientes"
        
        # Verificar acceso a directorio personal
        if resource_path.startswith(user.home_directory):
            self._log_event(username, f"ACCESS_{access_type.value.upper()}", resource_path, "GRANTED", "Directorio personal")
            return True, "Acceso concedido (directorio personal)"
        
        self._log_event(username, f"ACCESS_{access_type.value.upper()}", resource_path, "DENIED", "Recurso no autorizado")
        return False, "Acceso denegado - recurso no autorizado"

    def apparmor_check(self, username: str, software_name: str) -> Tuple[bool, str]:
        """Simular control MAC con AppArmor (Mandatory Access Control)"""
        user = self.users.get(username)
        if not user:
            return False, "Usuario no válido"
        
        # Verificar software bloqueado
        if software_name in self.blocked_software:
            self._log_event(username, "SOFTWARE_EXECUTION", software_name, "BLOCKED", "AppArmor MAC policy")
            return False, f"Software '{software_name}' bloqueado por política AppArmor"
        
        # Solo administradores pueden ejecutar software de sistema
        if software_name.startswith("system_") and user.role != UserRole.ADMIN:
            self._log_event(username, "SOFTWARE_EXECUTION", software_name, "BLOCKED", "Privilegios insuficientes")
            return False, f"Software de sistema requiere privilegios de administrador"
        
        self._log_event(username, "SOFTWARE_EXECUTION", software_name, "ALLOWED", "Política MAC cumplida")
        return True, f"Ejecución de '{software_name}' permitida"

    def monitor_critical_files(self, username: str, file_path: str, action: str) -> bool:
        """Monitorear acceso a archivos críticos"""
        for critical_path in self.critical_files:
            if file_path.startswith(critical_path):
                self._log_event(username, f"CRITICAL_FILE_{action.upper()}", file_path, "DETECTED", "Archivo crítico del sistema")
                print(f"[ALERTA SIEM] Acceso a archivo crítico detectado: {username} -> {file_path}")
                return True
        return False

    def generate_security_report(self) -> str:
        """Generar reporte de seguridad (Componente de Auditoría)"""
        report = []
        report.append("=== REPORTE DE SEGURIDAD DEL LABORATORIO ===")
        report.append(f"Generado: {datetime.datetime.now()}")
        report.append("")
        
        # Estadísticas de usuarios
        report.append("--- USUARIOS ---")
        locked_users = [u.username for u in self.users.values() if u.locked]
        report.append(f"Total de usuarios: {len(self.users)}")
        report.append(f"Usuarios bloqueados: {len(locked_users)} - {locked_users}")
        report.append("")
        
        # Eventos recientes
        report.append("--- EVENTOS RECIENTES (ÚLTIMOS 10) ---")
        recent_events = self.audit_log[-10:] if len(self.audit_log) >= 10 else self.audit_log
        for event in recent_events:
            report.append(f"{event.timestamp} | {event.user} | {event.action} | {event.result}")
        report.append("")
        
        # Alertas de seguridad
        report.append("--- ALERTAS DE SEGURIDAD ---")
        failed_logins = [e for e in self.audit_log if e.action == "LOGIN_ATTEMPT" and e.result == "FAILED"]
        blocked_software = [e for e in self.audit_log if e.action == "SOFTWARE_EXECUTION" and e.result == "BLOCKED"]
        critical_access = [e for e in self.audit_log if "CRITICAL_FILE" in e.action]
        
        report.append(f"Intentos de login fallidos: {len(failed_logins)}")
        report.append(f"Software bloqueado: {len(blocked_software)}")
        report.append(f"Acceso a archivos críticos: {len(critical_access)}")
        
        return "\n".join(report)

def main():
    """Función principal para demostrar el sistema de seguridad"""
    print("=== SIMULADOR DE POLÍTICA DE SEGURIDAD UNIVERSITARIA ===\n")
    
    # Inicializar sistema
    security_system = SecuritySystem()
    
    # Escenarios de demostración
    print("1. DEMOSTRACIÓN DE AUTENTICACIÓN")
    print("-" * 40)
    
    # Intento de login exitoso
    success, msg = security_system.authenticate("estudiante1", "Password123!")
    print(f"Login estudiante1: {msg}")
    
    # Intento de login fallido
    success, msg = security_system.authenticate("estudiante1", "wrong_password")
    print(f"Login con contraseña incorrecta: {msg}")
    
    # Login de admin con MFA
    success, msg = security_system.authenticate("admin", "Admin$ecure789", "123456")
    print(f"Login admin con MFA: {msg}")
    
    print("\n2. DEMOSTRACIÓN DE CONTROL DE ACCESO")
    print("-" * 40)
    
    # Acceso permitido a directorio personal
    success, msg = security_system.check_access("estudiante1", "/home/estudiante1/archivo.txt", AccessLevel.WRITE)
    print(f"Estudiante accede a su directorio: {msg}")
    
    # Acceso denegado a archivo crítico
    success, msg = security_system.check_access("estudiante1", "/etc/passwd", AccessLevel.READ)
    print(f"Estudiante intenta acceder a /etc/passwd: {msg}")
    
    # Acceso de admin a archivo crítico
    success, msg = security_system.check_access("admin", "/etc/passwd", AccessLevel.WRITE)
    print(f"Admin accede a /etc/passwd: {msg}")
    
    print("\n3. DEMOSTRACIÓN DE CONTROL MAC (AppArmor)")
    print("-" * 40)
    
    # Software permitido
    success, msg = security_system.apparmor_check("estudiante1", "firefox")
    print(f"Ejecutar Firefox: {msg}")
    
    # Software bloqueado
    success, msg = security_system.apparmor_check("estudiante1", "virus.exe")
    print(f"Ejecutar virus.exe: {msg}")
    
    # Software de sistema (solo admin)
    success, msg = security_system.apparmor_check("estudiante1", "system_config")
    print(f"Estudiante ejecuta software de sistema: {msg}")
    
    success, msg = security_system.apparmor_check("admin", "system_config")
    print(f"Admin ejecuta software de sistema: {msg}")
    
    print("\n4. MONITOREO DE ARCHIVOS CRÍTICOS")
    print("-" * 40)
    
    # Simular acceso a archivo crítico
    security_system.monitor_critical_files("estudiante1", "/etc/passwd", "read")
    security_system.monitor_critical_files("admin", "/var/log/auth.log", "write")
    
    print("\n5. REPORTE DE AUDITORÍA")
    print("-" * 40)
    print(security_system.generate_security_report())

if __name__ == "__main__":
    main()