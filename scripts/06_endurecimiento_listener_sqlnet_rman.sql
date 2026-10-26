-- =============================================================================
-- Tema: Controles ISO/IEC 27001:2022 para la Confidencialidad en BD (Oracle 19c/21c XE)
-- Autor: Aarón Guevara
-- Archivo: 06_endurecimiento_listener_sqlnet_rman.sql
-- Propósito: Configuraciones de referencia auditables para:
--   - Tarea DBA #4: Transparent Data Encryption (TDE Keystore)
--   - Tarea DBA #6: Respaldos Cifrados en RMAN (Control A.8.13)
--   - Tarea DBA #9: Endurecimiento de Listener y Red TLS/NNE (Control A.8.20)
--   - Tarea DBA #10: Eliminación Segura y Sanitización de Clones DEV/TEST (A.8.10 / A.8.11)
-- =============================================================================

-- =============================================================================
-- SECCIÓN A: COMANDOS SQLPLUS PARA CONFIGURAR TDE (TRANSPARENT DATA ENCRYPTION)
-- (Ejecutar conectado como SYSDBA / SYSKM)
-- =============================================================================
/*
-- 1. Configurar la ruta del Keystore en spfile
ALTER SYSTEM SET WALLET_ROOT = '/opt/oracle/admin/XE/wallet' SCOPE=SPFILE;
SHUTDOWN IMMEDIATE;
STARTUP;

ALTER SYSTEM SET TDE_CONFIGURATION = "KEYSTORE_CONFIGURATION=FILE" SCOPE=BOTH;

-- 2. Crear y abrir el Keystore protegido por contraseña + Auto-Login (Control A.8.3)
ADMINISTER KEY MANAGEMENT CREATE KEYSTORE '/opt/oracle/admin/XE/wallet/tde' IDENTIFIED BY "KeySt0re#UNA2026!";
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "KeySt0re#UNA2026!" CONTAINER=ALL;
ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "KeySt0re#UNA2026!" WITH BACKUP CONTAINER=ALL;
ADMINISTER KEY MANAGEMENT CREATE AUTO_LOGIN KEYSTORE FROM KEYSTORE '/opt/oracle/admin/XE/wallet/tde' IDENTIFIED BY "KeySt0re#UNA2026!";

-- 3. Crear Tablespace Cifrado con AES256 para activos críticos (Ley 8968)
CREATE TABLESPACE TBS_CONFIDENCIAL_ENC
    DATAFILE '/opt/oracle/oradata/XE/XEPDB1/tbs_confidencial_enc01.dbf' SIZE 100M AUTOEXTEND ON
    ENCRYPTION USING 'AES256'
    DEFAULT STORAGE (ENCRYPT);
*/

-- =============================================================================
-- SECCIÓN B: PARÁMETROS AUDITABLES EN $ORACLE_HOME/network/admin/sqlnet.ora
-- (Control A.8.20 - Cifrado en Tránsito y Valid Node Checking)
-- =============================================================================
/*
# --- Cifrado Nativo de Red (Native Network Encryption - NNE) ---
SQLNET.ENCRYPTION_SERVER = REQUIRED
SQLNET.ENCRYPTION_CLIENT = REQUIRED
SQLNET.ENCRYPTION_TYPES_SERVER = (AES256)
SQLNET.ENCRYPTION_TYPES_CLIENT = (AES256)

# --- Integridad Criptográfica de Paquetes contra Man-in-the-Middle ---
SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED
SQLNET.CRYPTO_CHECKSUM_CLIENT = REQUIRED
SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER = (SHA512, SHA256)
SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT = (SHA512, SHA256)

# --- Configuración TLS 1.2 / 1.3 ---
SSL_VERSION = 1.2
SSL_CLIENT_AUTHENTICATION = FALSE
WALLET_LOCATION = (SOURCE = (METHOD = FILE) (METHOD_DATA = (DIRECTORY = /opt/oracle/admin/XE/wallet)))

# --- Valid Node Checking (Firewall de Capa de Sesión en BD) ---
TCP.VALIDNODE_CHECKING = YES
TCP.INVITED_NODES = (10.10.20.15, 10.10.20.16, 127.0.0.1)

# --- Restricción de Versiones de Autenticación Antiguas (Control A.8.5) ---
SQLNET.ALLOWED_LOGON_VERSION_SERVER = 12a
SQLNET.ALLOWED_LOGON_VERSION_CLIENT = 12a
SQLNET.INBOUND_CONNECT_TIMEOUT = 60
*/

-- =============================================================================
-- SECCIÓN C: PARÁMETROS AUDITABLES EN $ORACLE_HOME/network/admin/listener.ora
-- (Control A.8.20 - Protección del Listener)
-- =============================================================================
/*
LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCPS)(HOST = db-una-prod.local)(PORT = 2484))
    )
  )

# Evitar modificaciones en tiempo de ejecución no autorizadas y registro dinámico malicioso
ADMIN_RESTRICTIONS_LISTENER = ON
SECURE_REGISTER_LISTENER = (TCPS, IPC)
LOGGING_LISTENER = ON
*/

-- =============================================================================
-- SECCIÓN D: COMANDOS RMAN PARA RESPALDOS CIFRADOS (Control A.8.13)
-- (Ejecutar desde utilidad rman target /)
-- =============================================================================
/*
CONFIGURE ENCRYPTION FOR DATABASE ON;
CONFIGURE ENCRYPTION ALGORITHM 'AES256';
CONFIGURE RETENTION POLICY TO RECOVERY WINDOW OF 30 DAYS;
CONFIGURE CONTROLFILE AUTOBACKUP ON;

-- Respaldo completo cifrado en modo transparente + contraseña dual
SET ENCRYPTION ON IDENTIFIED BY "B4ckup#UNA2026!" ONLY;
BACKUP AS COMPRESSED BACKUPSET DATABASE PLUS ARCHIVELOG DELETE INPUT;
LIST BACKUP SUMMARY;
*/

-- =============================================================================
-- SECCIÓN E: ELIMINACIÓN SEGURA Y SANITIZACIÓN DE CLONES DEV/TEST (A.8.10 y A.8.11)
-- =============================================================================
-- 1. Purga definitiva de objetos eliminados para impedir recuperación vía Flashback Drop
PURGE DBA_RECYCLEBIN;

-- 2. Procedimiento de sanitización post-clonación para entornos DEV/TEST (Tarea DBA #12)
CREATE OR REPLACE PROCEDURE USR_CUSTODIO_DATOS.PRC_SANITIZAR_CLON_DEV_TEST AS
    v_db_name VARCHAR2(30);
BEGIN
    SELECT sys_context('USERENV', 'DB_NAME') INTO v_db_name FROM dual;

    -- Medida de seguridad: Impedir ejecución accidental en Producción
    IF UPPER(v_db_name) LIKE '%PROD%' THEN
        RAISE_APPLICATION_ERROR(-20001, 'ABORTADO: No se permite ejecutar sanitización destructiva en PRODUCCIÓN.');
    END IF;

    -- Enmascaramiento irreversible (In-Place Masking) para copias DEV/TEST (Control A.8.11)
    UPDATE USR_CUSTODIO_DATOS.PACIENTES_CONFIDENCIAL
    SET CEDULA_IDENTIDAD    = '9-0000-' || LPAD(ID_PACIENTE, 4, '0'),
        NOMBRE_COMPLETO     = 'PACIENTE_PRUEBA_' || ID_PACIENTE,
        CORREO_ELECTRONICO  = 'paciente' || ID_PACIENTE || '@dev.una.ac.cr',
        TELEFONO            = '0000-0000',
        DIAGNOSTICO_CLINICO = 'DATO_SINTETICO_ENTORNO_PRUEBAS',
        SALARIO_MENSUAL_CRC = ROUND(DBMS_RANDOM.VALUE(350000, 1500000), -3);

    COMMIT;
    -- Compactar bloques para sobrescribir espacio libre y purgar papelera (Control A.8.10)
    EXECUTE IMMEDIATE 'ALTER TABLE USR_CUSTODIO_DATOS.PACIENTES_CONFIDENCIAL ENABLE ROW MOVEMENT';
    EXECUTE IMMEDIATE 'ALTER TABLE USR_CUSTODIO_DATOS.PACIENTES_CONFIDENCIAL SHRINK SPACE CASCADE';
    EXECUTE IMMEDIATE 'PURGE RECYCLEBIN';
END;
/
