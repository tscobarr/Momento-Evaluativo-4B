#!/usr/bin/env python3
"""
Demo Interactivo del Sistema de Seguridad
Permite al usuario experimentar con diferentes escenarios
"""

from main import SecuritySystem, UserRole, AccessLevel
import datetime

def menu_principal():
    """Mostrar menú principal"""
    print("\n=== DEMO INTERACTIVO - POLÍTICA DE SEGURIDAD ===")
    print("1. Probar autenticación")
    print("2. Verificar control de acceso")
    print("3. Probar AppArmor (MAC)")
    print("4. Simular múltiples intentos fallidos")
    print("5. Ver reporte de auditoría")
    print("6. Crear nuevo usuario")
    print("7. Salir")
    return input("\nSelecciona una opción (1-7): ")

def demo_autenticacion(sistema):
    """Demo de autenticación"""
    print("\n--- DEMOSTRACIÓN DE AUTENTICACIÓN ---")
    print("Usuarios disponibles:")
    for username, user in sistema.users.items():
        mfa_status = "MFA habilitado" if user.mfa_enabled else "MFA deshabilitado"
        status = "BLOQUEADO" if user.locked else "ACTIVO"
        print(f"  {username} ({user.role.value}) - {mfa_status} - {status}")
    
    username = input("\nUsuario: ")
    password = input("Contraseña: ")
    
    user = sistema.users.get(username)
    if user and user.mfa_enabled:
        mfa_code = input("Código MFA (usar '123456' para prueba): ")
    else:
        mfa_code = None
    
    success, msg = sistema.authenticate(username, password, mfa_code)
    print(f"\nResultado: {msg}")
    
    if not success and username in sistema.users:
        user = sistema.users[username]
        print(f"Intentos fallidos: {user.failed_attempts}/5")
        if user.locked:
            print("⚠️  CUENTA BLOQUEADA")

def demo_control_acceso(sistema):
    """Demo de control de acceso"""
    print("\n--- DEMOSTRACIÓN DE CONTROL DE ACCESO ---")
    print("Recursos disponibles:")
    for path, resource in sistema.resources.items():
        print(f"  {path} (propietario: {resource.owner})")
    
    username = input("\nUsuario: ")
    resource_path = input("Recurso a acceder: ")
    
    print("\nTipos de acceso:")
    print("1. Lectura (read)")
    print("2. Escritura (write)")
    print("3. Ejecución (execute)")
    print("4. Eliminación (delete)")
    
    access_choice = input("Tipo de acceso (1-4): ")
    access_types = {
        "1": AccessLevel.READ,
        "2": AccessLevel.WRITE,
        "3": AccessLevel.EXECUTE,
        "4": AccessLevel.DELETE
    }
    
    if access_choice in access_types:
        access_type = access_types[access_choice]
        success, msg = sistema.check_access(username, resource_path, access_type)
        print(f"\nResultado: {msg}")
        
        if resource_path in sistema.resources:
            resource = sistema.resources[resource_path]
            if username in resource.permissions:
                print(f"Permisos de {username} en {resource_path}:")
                for perm in resource.permissions[username]:
                    print(f"  - {perm.value}")
    else:
        print("Opción no válida")

def demo_apparmor(sistema):
    """Demo de AppArmor (MAC)"""
    print("\n--- DEMOSTRACIÓN DE APPARMOR (MAC) ---")
    print("Software bloqueado por política:", sistema.blocked_software)
    
    username = input("\nUsuario: ")
    software = input("Software a ejecutar: ")
    
    success, msg = sistema.apparmor_check(username, software)
    print(f"\nResultado: {msg}")

def demo_intentos_fallidos(sistema):
    """Demo de bloqueo por intentos fallidos"""
    print("\n--- SIMULACIÓN DE MÚLTIPLES INTENTOS FALLIDOS ---")
    
    username = input("Usuario para probar: ")
    if username not in sistema.users:
        print("Usuario no existe")
        return
    
    print(f"\nSimulando 6 intentos fallidos para {username}...")
    for i in range(6):
        success, msg = sistema.authenticate(username, "contraseña_incorrecta")
        user = sistema.users[username]
        print(f"Intento {i+1}: {msg} (fallos: {user.failed_attempts})")
        
        if user.locked:
            print("⚠️  CUENTA BLOQUEADA AUTOMÁTICAMENTE")
            break

def crear_usuario(sistema):
    """Crear nuevo usuario"""
    print("\n--- CREAR NUEVO USUARIO ---")
    
    username = input("Nombre de usuario: ")
    if username in sistema.users:
        print("El usuario ya existe")
        return
    
    password = input("Contraseña: ")
    valid, msg = sistema._validate_password_policy(password)
    if not valid:
        print(f"Contraseña no válida: {msg}")
        return
    
    print("\nRoles disponibles:")
    print("1. Estudiante")
    print("2. Profesor")
    print("3. Administrador")
    
    role_choice = input("Seleccionar rol (1-3): ")
    roles = {
        "1": UserRole.STUDENT,
        "2": UserRole.PROFESSOR,
        "3": UserRole.ADMIN
    }
    
    if role_choice not in roles:
        print("Opción no válida")
        return
    
    role = roles[role_choice]
    mfa = input("¿Habilitar MFA? (s/n): ").lower() == 's'
    
    from main import User
    new_user = User(
        username=username,
        password_hash=sistema._hash_password(password),
        role=role,
        mfa_enabled=mfa,
        home_directory=f"/home/{username}"
    )
    
    sistema.users[username] = new_user
    print(f"\n✅ Usuario {username} creado exitosamente")
    
    # Crear recurso de directorio personal
    from main import Resource
    sistema.resources[f"/home/{username}"] = Resource(
        path=f"/home/{username}",
        owner=username,
        permissions={
            username: [AccessLevel.READ, AccessLevel.WRITE, AccessLevel.EXECUTE],
            "admin": [AccessLevel.READ, AccessLevel.WRITE, AccessLevel.EXECUTE, AccessLevel.DELETE]
        }
    )

def main():
    """Función principal del demo interactivo"""
    sistema = SecuritySystem()
    
    while True:
        opcion = menu_principal()
        
        if opcion == "1":
            demo_autenticacion(sistema)
        elif opcion == "2":
            demo_control_acceso(sistema)
        elif opcion == "3":
            demo_apparmor(sistema)
        elif opcion == "4":
            demo_intentos_fallidos(sistema)
        elif opcion == "5":
            print("\n" + sistema.generate_security_report())
        elif opcion == "6":
            crear_usuario(sistema)
        elif opcion == "7":
            print("\n¡Gracias por usar el demo!")
            break
        else:
            print("\nOpción no válida. Intenta de nuevo.")
        
        input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    main()
