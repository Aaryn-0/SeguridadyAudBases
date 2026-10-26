-- =============================================================================
-- Tema: Controles ISO/IEC 27001:2022 para la Confidencialidad en BD (Oracle 19c/21c XE)
-- Autor: Aarón Guevara
-- Archivo: 03_auditoria_cifrado_y_enmascaramiento.sql
-- Controles Auditados:
--   A.5.12 Clasificación de la información
--   A.8.3  Restricción del acceso a la información (TDE + VPD/RLS)
--   A.8.11 Enmascaramiento de datos (Data Redaction / Vistas Enmascaradas)
--   A.8.12 Prevención de fuga de datos (DLP en base de datos)
-- =============================================================================

SET PAGESIZE 100
SET LINESIZE 200
SET FEEDBACK ON

PROMPT =========================================================================
PROMPT [PRUEBA PT-07 | Control A.5.12] Inventario y Clasificación de Datos Sensibles
PROMPT Objetivo: Identificar columnas que almacenan PII o datos sensibles (Ley 8968 CR)
PROMPT           y verificar si cuentan con etiqueta de clasificación en el diccionario.
PROMPT Resultado Esperado: Todas las tablas/columnas críticas clasificadas en ALL_COL_COMMENTS.
PROMPT =========================================================================
SELECT
    c.owner,
    c.table_name,
    c.column_name,
    c.data_type,
    NVL(cc.comments, '[ALERTA: SIN ETIQUETA DE CLASIFICACION A.5.12]') AS clasificacion_iso
FROM dba_tab_columns c
LEFT JOIN dba_col_comments cc
    ON c.owner = cc.owner
   AND c.table_name = cc.table_name
   AND c.column_name = cc.column_name
WHERE c.owner NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y')
  AND REGEXP_LIKE(c.column_name, 'CEDULA|IDENTIFICA|SALARIO|TARJETA|CLAVE|PASSWORD|DIAGNOSTICO|CORREO|TELEFONO|DIRECCION', 'i')
ORDER BY c.owner, c.table_name, c.column_name;

PROMPT =========================================================================
PROMPT [PRUEBA PT-08 | Control A.8.3] Verificación de Billetera Criptográfica (TDE Wallet)
PROMPT Objetivo: Confirmar que el Keystore de Transparent Data Encryption (TDE) está OPEN
PROMPT           y configurado con AUTO_LOGIN seguro para proteger datafiles en reposo.
PROMPT Resultado Esperado: STATUS = 'OPEN' y WALLET_TYPE = 'AUTOLOGIN' o 'PASSWORD'.
PROMPT =========================================================================
SELECT
    wrl_type,
    wrl_parameter,
    status,
    wallet_type,
    wallet_order,
    fully_backed_up,
    con_id
FROM v$encryption_wallet;

PROMPT =========================================================================
PROMPT [PRUEBA PT-09 | Control A.8.3] Auditoría de Tablespaces y Columnas Cifradas (TDE)
PROMPT Objetivo: Verificar qué tablespaces y columnas sensibles se encuentran cifrados
PROMPT           con algoritmos robustos (AES256).
PROMPT Resultado Esperado: Tablespaces de datos de usuario con ENCRYPTED = 'YES'.
PROMPT =========================================================================
SELECT
    tablespace_name,
    status,
    contents,
    encrypted
FROM dba_tablespaces
ORDER BY encrypted DESC, tablespace_name;

SELECT
    owner,
    table_name,
    column_name,
    encryption_alg,
    salt,
    integrity_alg
FROM dba_encrypted_columns
ORDER BY owner, table_name;

PROMPT =========================================================================
PROMPT [PRUEBA PT-10 | Control A.8.3] Verificación de Políticas VPD / Row-Level Security
PROMPT Objetivo: Confirmar la existencia y estado ENABLE = 'YES' de políticas DBMS_RLS
PROMPT           que restringen el acceso a nivel de fila.
PROMPT Resultado Esperado: Políticas activas sobre tablas de clasificación CONFIDENCIAL.
PROMPT =========================================================================
SELECT
    object_owner,
    object_name,
    policy_group,
    policy_name,
    pf_owner,
    package,
    function,
    sel,
    ins,
    upd,
    del,
    enable
FROM dba_policies
ORDER BY object_owner, object_name;

PROMPT =========================================================================
PROMPT [PRUEBA PT-11 | Control A.8.11] Verificación de Políticas de Data Redaction
PROMPT Objetivo: Auditar las políticas de enmascaramiento dinámico activas y columnas
PROMPT           protegidas contra exposición a usuarios no autorizados o entornos DEV/TEST.
PROMPT Resultado Esperado: ENABLE = 'YES' en REDACTION_POLICIES para columnas PII.
PROMPT =========================================================================
SELECT
    object_owner,
    object_name,
    policy_name,
    expression,
    enable
FROM redaction_policies
ORDER BY object_owner, object_name;

SELECT
    object_owner,
    object_name,
    column_name,
    function_type,
    regexp_pattern,
    regexp_replace_string
FROM redaction_columns
ORDER BY object_owner, object_name, column_name;

PROMPT =========================================================================
PROMPT [PRUEBA PT-12 | Control A.8.12] Prevención de Fuga de Datos (DLP en BD)
PROMPT Objetivo: Auditar vectores de exfiltración desde el motor (Directory Objects,
PROMPT           Database Links públicos/privados y parámetros de sistema riesgosos).
PROMPT Resultado Esperado: Sin DB Links públicos ni permisos de escritura en DIRECTORIOS
PROMPT                     para cuentas de aplicación.
PROMPT =========================================================================
-- 1. Revisión de Database Links (posible canal de exfiltración hacia bases externas)
SELECT
    owner,
    db_link,
    username,
    host,
    created
FROM dba_db_links
ORDER BY owner, db_link;

-- 2. Revisión de permisos sobre objetos DIRECTORY (lectura/escritura en SO vía UTL_FILE/Data Pump)
SELECT
    d.directory_name,
    d.directory_path,
    p.grantee,
    p.privilege,
    p.grantable
FROM dba_directories d
JOIN dba_tab_privs p
    ON d.directory_name = p.table_name
WHERE p.grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y')
ORDER BY d.directory_name, p.grantee;
