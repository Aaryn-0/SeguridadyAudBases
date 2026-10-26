-- =============================================================================
-- Tema: Controles ISO/IEC 27001:2022 para la Confidencialidad en BD (Oracle 19c/21c XE)
-- Autor: Aarón Guevara
-- Archivo: 04_auditoria_backups_logs_red_eliminacion.sql
-- Controles Auditados:
--   A.5.33 Protección de los registros
--   A.8.10 Eliminación de información
--   A.8.13 Copia de seguridad de la información (Backups cifrados RMAN)
--   A.8.15 Registro (Logging y Unified Auditing)
--   A.8.20 Seguridad de las redes (Listener y Cifrado en Tránsito TLS/ASO)
-- =============================================================================

SET PAGESIZE 100
SET LINESIZE 200
SET FEEDBACK ON

PROMPT =========================================================================
PROMPT [PRUEBA PT-13 | Control A.8.13] Auditoría de Respaldos RMAN y Cifrado de Backups
PROMPT Objetivo: Verificar la configuración de cifrado en RMAN (ENCRYPTION FOR DATABASE ON)
PROMPT           y el historial de respaldos recientes para mitigar robo de backups (R-CONF-03).
PROMPT Resultado Esperado: ENCRYPTION configurada en ON (AES256) y STATUS = 'COMPLETED'.
PROMPT =========================================================================
SELECT
    name,
    value
FROM v$rman_configuration
WHERE name LIKE '%ENCRYPTION%'
   OR name LIKE '%RETENTION%';

SELECT
    session_key,
    input_type,
    status,
    TO_CHAR(start_time, 'YYYY-MM-DD HH24:MI') AS inicio,
    TO_CHAR(end_time, 'YYYY-MM-DD HH24:MI')   AS fin,
    output_device_type,
    ROUND(output_bytes / 1024 / 1024, 2)      AS tamano_mb
FROM v$rman_backup_job_details
ORDER BY start_time DESC
FETCH FIRST 10 ROWS ONLY;

PROMPT =========================================================================
PROMPT [PRUEBA PT-14 | Controles A.5.33 y A.8.15] Estado de Unified Auditing y Políticas
PROMPT Objetivo: Confirmar que Unified Auditing está activo y que existen políticas
PROMPT           habilitadas para acciones privilegiadas y acceso a datos sensibles.
PROMPT Resultado Esperado: Parameter Unified Auditing = TRUE y políticas habilitadas.
PROMPT =========================================================================
SELECT
    parameter,
    value
FROM v$option
WHERE parameter = 'Unified Auditing';

SELECT
    policy_name,
    enabled_option,
    entity_name,
    entity_type,
    success,
    failure
FROM audit_unified_enabled_policies
ORDER BY policy_name;

PROMPT =========================================================================
PROMPT [PRUEBA PT-15 | Controles A.5.33 y A.8.15] Evidencia en UNIFIED_AUDIT_TRAIL
PROMPT Objetivo: Extraer los eventos recientes de acceso o intentos fallidos (ORA-01017,
PROMPT           ORA-00942, SELECT sobre tablas críticas) e inspeccionar la protección
PROMPT           del tablespace SYSAUX donde reside AUDSYS.
PROMPT =========================================================================
SELECT
    TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS fecha_hora,
    dbusername,
    os_username,
    userhost,
    client_program_name,
    action_name,
    object_schema,
    object_name,
    return_code,
    unified_audit_policies
FROM unified_audit_trail
WHERE event_timestamp >= SYSTIMESTAMP - INTERVAL '7' DAY
ORDER BY event_timestamp DESC
FETCH FIRST 25 ROWS ONLY;

-- Verificar que ningún usuario normal tenga privilegios directos sobre tablas internas de AUDSYS (A.5.33)
SELECT
    grantee,
    owner,
    table_name,
    privilege
FROM dba_tab_privs
WHERE owner = 'AUDSYS'
  AND grantee NOT IN ('SYS', 'AUDIT_ADMIN', 'AUDIT_VIEWER');

PROMPT =========================================================================
PROMPT [PRUEBA PT-16 | Control A.8.10] Eliminación Segura de Información y Papelera
PROMPT Objetivo: Verificar que los objetos eliminados con datos sensibles no permanezcan
PROMPT           recuperables en DBA_RECYCLEBIN y auditar el parámetro recyclebin.
PROMPT Resultado Esperado: 0 objetos sensibles en DBA_RECYCLEBIN (uso de DROP ... PURGE).
PROMPT =========================================================================
SELECT
    name,
    value,
    isdefault
FROM v$parameter
WHERE name = 'recyclebin';

SELECT
    owner,
    original_name,
    object_name,
    type,
    droptime,
    can_undrop
FROM dba_recyclebin
ORDER BY droptime DESC;

PROMPT =========================================================================
PROMPT [PRUEBA PT-17 | Control A.8.20] Seguridad de Red y Cifrado en Tránsito (Sesiones)
PROMPT Objetivo: Verificar en tiempo real si las conexiones de los clientes utilizan
PROMPT           cifrado de red (Native Network Encryption AES256 o TLS 1.2/1.3) y
PROMPT           checksumming de integridad (SHA256/SHA512).
PROMPT Resultado Esperado: NETWORK_SERVICE_BANNER contiene 'AES256' o 'TLS'.
PROMPT =========================================================================
SELECT
    s.sid,
    s.serial#,
    s.username,
    s.program,
    s.machine,
    sci.authentication_type,
    sci.network_service_banner
FROM v$session s
JOIN v$session_connect_info sci
    ON s.sid = sci.sid
   AND s.serial# = sci.serial#
WHERE s.type = 'USER'
  AND s.username IS NOT NULL
ORDER BY s.sid, sci.network_service_banner;

PROMPT =========================================================================
PROMPT [PRUEBA PT-18 | Tarea DBA #8] Verificación de Parches de Seguridad (CPU/RU)
PROMPT Objetivo: Consultar el historial de parches aplicados en el motor Oracle para
PROMPT           confirmar que no existan vulnerabilidades conocidas sin mitigar.
PROMPT =========================================================================
SELECT
    patch_id,
    patch_type,
    action,
    status,
    TO_CHAR(action_time, 'YYYY-MM-DD HH24:MI') AS fecha_aplicacion,
    description
FROM dba_registry_sqlpatch
ORDER BY action_time DESC;
