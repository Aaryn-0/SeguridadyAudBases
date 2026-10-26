-- =============================================================================
-- Tema: Controles ISO/IEC 27001:2022 para la Confidencialidad en BD (Oracle 19c/21c XE)
-- Autor: Aarón Guevara
-- Archivo: 02_auditoria_usuarios_privilegios.sql
-- Controles Auditados:
--   A.5.15 Control de acceso
--   A.5.16 Gestión de identidad
--   A.5.17 Información de autenticación
--   A.5.18 Derechos de acceso
--   A.8.2  Derechos de acceso privilegiado
--   A.8.5  Autenticación segura
-- =============================================================================

SET PAGESIZE 100
SET LINESIZE 200
SET FEEDBACK ON

PROMPT =========================================================================
PROMPT [PRUEBA PT-01 | Control A.5.16] Auditoría de Ciclo de Vida de Identidades
PROMPT Objetivo: Detectar cuentas por defecto desbloqueadas, sin rotación o huérfanas.
PROMPT Resultado Esperado: Solo cuentas operativas justificadas deben estar OPEN.
PROMPT =========================================================================
SELECT
    username,
    account_status,
    lock_date,
    expiry_date,
    created,
    profile,
    oracle_maintained,
    authentication_type,
    last_login
FROM dba_users
WHERE account_status = 'OPEN'
  AND oracle_maintained = 'N'
ORDER BY created DESC;

-- Verificación de cuentas mantenidas por Oracle que deberían estar bloqueadas
SELECT
    username,
    account_status,
    profile,
    last_login
FROM dba_users
WHERE oracle_maintained = 'Y'
  AND account_status = 'OPEN'
  AND username NOT IN ('SYS', 'SYSTEM')
ORDER BY username;

PROMPT =========================================================================
PROMPT [PRUEBA PT-02 | Controles A.5.17 y A.8.5] Auditoría de Políticas de Contraseña
PROMPT Objetivo: Verificar parámetros de bloqueo, complejidad, expiración e inactividad.
PROMPT Resultado Esperado: FAILED_LOGIN_ATTEMPTS <= 5, PASSWORD_LIFE_TIME <= 90,
PROMPT                     PASSWORD_VERIFY_FUNCTION distinto de NULL/UNLIMITED.
PROMPT =========================================================================
SELECT
    profile,
    resource_name,
    resource_type,
    limit
FROM dba_profiles
WHERE resource_name IN (
    'FAILED_LOGIN_ATTEMPTS',
    'PASSWORD_LIFE_TIME',
    'PASSWORD_REUSE_TIME',
    'PASSWORD_REUSE_MAX',
    'PASSWORD_LOCK_TIME',
    'PASSWORD_GRACE_TIME',
    'PASSWORD_VERIFY_FUNCTION',
    'INACTIVE_ACCOUNT_TIME',
    'IDLE_TIME',
    'SESSIONS_PER_USER'
)
ORDER BY profile, resource_name;

PROMPT =========================================================================
PROMPT [PRUEBA PT-03 | Control A.8.2] Auditoría de Privilegios Administrativos Críticos
PROMPT Objetivo: Verificar quién posee privilegios SYSDBA, SYSOPER, SYSKM, SYSBACKUP.
PROMPT Resultado Esperado: Separación de funciones (SoD) y mínimo número de cuentas.
PROMPT =========================================================================
SELECT
    username,
    sysdba,
    sysoper,
    sysasm,
    sysbackup,
    sysdg,
    syskm,
    account_status
FROM v$pwfile_users
ORDER BY username;

PROMPT =========================================================================
PROMPT [PRUEBA PT-04 | Controles A.5.15 y A.8.2] Detección de Privilegios de Sistema "ANY"
PROMPT Objetivo: Identificar usuarios no-sistema con privilegios excesivos (SELECT ANY TABLE,
PROMPT           GRANT ANY PRIVILEGE, ALTER SYSTEM, etc.) que violan el mínimo privilegio.
PROMPT Resultado Esperado: 0 filas para usuarios de aplicación o analistas.
PROMPT =========================================================================
SELECT
    grantee,
    privilege,
    admin_option,
    common
FROM dba_sys_privs
WHERE (privilege LIKE '%ANY%' OR privilege IN ('ALTER SYSTEM', 'ALTER DATABASE', 'BECOME USER', 'EXEMPT ACCESS POLICY'))
  AND grantee NOT IN (
      SELECT username FROM dba_users WHERE oracle_maintained = 'Y'
  )
  AND grantee NOT IN ('DBA', 'DATAPUMP_IMP_FULL_DATABASE', 'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE')
ORDER BY grantee, privilege;

PROMPT =========================================================================
PROMPT [PRUEBA PT-05 | Control A.5.18] Auditoría de Roles Asignados y Rol DBA
PROMPT Objetivo: Verificar la asignación del rol DBA y roles con ADMIN_OPTION.
PROMPT Resultado Esperado: Ningún usuario de aplicación o desarrollo debe poseer el rol DBA.
PROMPT =========================================================================
SELECT
    grantee,
    granted_role,
    admin_option,
    default_role
FROM dba_role_privs
WHERE granted_role IN ('DBA', 'PDB_DBA', 'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE', 'SELECT_CATALOG_ROLE')
  AND grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y')
ORDER BY granted_role, grantee;

PROMPT =========================================================================
PROMPT [PRUEBA PT-06 | Control A.5.15 y A.5.18] Auditoría de Privilegios Otorgados a PUBLIC
PROMPT Objetivo: Detectar paquetes críticos de red/sistema de archivos o tablas de usuario
PROMPT           expuestas al rol implícito PUBLIC (riesgo de exfiltración R-CONF-01).
PROMPT Resultado Esperado: 0 filas para UTL_FILE, UTL_HTTP, UTL_TCP, UTL_SMTP, DBMS_RANDOM.
PROMPT =========================================================================
SELECT
    grantee,
    owner,
    table_name,
    privilege,
    grantable
FROM dba_tab_privs
WHERE grantee = 'PUBLIC'
  AND (
      table_name IN ('UTL_FILE', 'UTL_HTTP', 'UTL_TCP', 'UTL_SMTP', 'DBMS_LOB', 'DBMS_SYS_SQL', 'DBMS_JOB', 'DBMS_SCHEDULER')
      OR owner NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y')
  )
ORDER BY owner, table_name;
