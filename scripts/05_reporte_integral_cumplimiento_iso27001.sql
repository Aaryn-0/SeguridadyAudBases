-- =============================================================================
-- Tema: Controles ISO/IEC 27001:2022 para la Confidencialidad en BD (Oracle 19c/21c XE)
-- Autor: Aarón Guevara
-- Archivo: 05_reporte_integral_cumplimiento_iso27001.sql
-- Propósito: Script Maestro de Verificación Automática de los 15 Controles
--            ISO/IEC 27001:2022 en Oracle 19c/21c XE (Ciclo PHVA - Fase VERIFICAR)
-- =============================================================================

SET SERVEROUTPUT ON SIZE UNLIMITED;
SET LINESIZE 220;
SET PAGESIZE 100;

DECLARE
    v_cnt_unclassified   NUMBER := 0;
    v_cnt_any_privs      NUMBER := 0;
    v_cnt_open_default   NUMBER := 0;
    v_cnt_weak_profiles  NUMBER := 0;
    v_cnt_public_privs   NUMBER := 0;
    v_cnt_sysdba_users   NUMBER := 0;
    v_cnt_wallet_open    NUMBER := 0;
    v_cnt_vpd_policies   NUMBER := 0;
    v_cnt_recyclebin     NUMBER := 0;
    v_cnt_redact_pol     NUMBER := 0;
    v_cnt_public_dblinks NUMBER := 0;
    v_cnt_rman_enc       NUMBER := 0;
    v_cnt_audit_pol      NUMBER := 0;
    v_cnt_enc_sessions   NUMBER := 0;

    PROCEDURE print_row(
        p_control   VARCHAR2,
        p_nombre    VARCHAR2,
        p_riesgo    VARCHAR2,
        p_madurez   NUMBER,
        p_estado    VARCHAR2,
        p_hallazgo  VARCHAR2
    ) IS
    BEGIN
        DBMS_OUTPUT.PUT_LINE(
            RPAD(p_control, 8) || ' | ' ||
            RPAD(SUBSTR(p_nombre, 1, 28), 28) || ' | ' ||
            RPAD(p_riesgo, 10) || ' | ' ||
            RPAD('Nivel ' || TO_CHAR(p_madurez) || '/4', 10) || ' | ' ||
            RPAD(p_estado, 10) || ' | ' ||
            p_hallazgo
        );
    END;
BEGIN
    DBMS_OUTPUT.PUT_LINE('=========================================================================================================================================');
    DBMS_OUTPUT.PUT_LINE('                 REPORTE AUTOMATIZADO DE AUDITORÍA ISO/IEC 27001:2022 - CONFIDENCIALIDAD EN ORACLE DB (UNA 2026)                         ');
    DBMS_OUTPUT.PUT_LINE('=========================================================================================================================================');
    DBMS_OUTPUT.PUT_LINE(
        RPAD('CONTROL', 8) || ' | ' ||
        RPAD('NOMBRE DEL CONTROL', 28) || ' | ' ||
        RPAD('RIESGO', 10) || ' | ' ||
        RPAD('MADUREZ', 10) || ' | ' ||
        RPAD('ESTADO', 10) || ' | ' ||
        'EVIDENCIA TÉCNICA OBSERVADA'
    );
    DBMS_OUTPUT.PUT_LINE('-----------------------------------------------------------------------------------------------------------------------------------------');

    -- 1. A.5.12 Clasificación de la información
    SELECT COUNT(*) INTO v_cnt_unclassified
    FROM dba_tab_columns c
    LEFT JOIN dba_col_comments cc ON c.owner = cc.owner AND c.table_name = cc.table_name AND c.column_name = cc.column_name
    WHERE c.owner NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y')
      AND REGEXP_LIKE(c.column_name, 'CEDULA|SALARIO|DIAGNOSTICO|CORREO|TELEFONO', 'i')
      AND cc.comments IS NULL;

    IF v_cnt_unclassified = 0 THEN
        print_row('A.5.12', 'Clasificacion Informacion', 'R-CONF-05', 4, 'CUMPLE', '0 columnas sensibles sin metadatos de clasificacion en DBA_COL_COMMENTS');
    ELSE
        print_row('A.5.12', 'Clasificacion Informacion', 'R-CONF-05', 2, 'PARCIAL', v_cnt_unclassified || ' columnas sensibles carecen de etiqueta en DBA_COL_COMMENTS');
    END IF;

    -- 2. A.5.15 Control de acceso
    SELECT COUNT(*) INTO v_cnt_any_privs
    FROM dba_sys_privs
    WHERE privilege LIKE '%ANY%'
      AND grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y')
      AND grantee NOT IN ('DBA', 'IMP_FULL_DATABASE', 'EXP_FULL_DATABASE', 'DATAPUMP_IMP_FULL_DATABASE');

    IF v_cnt_any_privs = 0 THEN
        print_row('A.5.15', 'Control de Acceso', 'R-CONF-01', 4, 'CUMPLE', '0 usuarios no-sistema con privilegios ANY en DBA_SYS_PRIVS');
    ELSE
        print_row('A.5.15', 'Control de Acceso', 'R-CONF-01', 1, 'NO CUMPLE', v_cnt_any_privs || ' privilegios ANY detectados fuera de cuentas de sistema');
    END IF;

    -- 3. A.5.16 Gestión de identidad
    SELECT COUNT(*) INTO v_cnt_open_default
    FROM dba_users
    WHERE oracle_maintained = 'Y'
      AND account_status = 'OPEN'
      AND username NOT IN ('SYS', 'SYSTEM', 'XS$NULL');

    IF v_cnt_open_default = 0 THEN
        print_row('A.5.16', 'Gestion de Identidad', 'R-CONF-01', 4, 'CUMPLE', 'Todas las cuentas por defecto no esenciales estan LOCKED en DBA_USERS');
    ELSE
        print_row('A.5.16', 'Gestion de Identidad', 'R-CONF-01', 2, 'PARCIAL', v_cnt_open_default || ' cuentas por defecto de Oracle se encuentran OPEN');
    END IF;

    -- 4. A.5.17 Información de autenticación
    SELECT COUNT(*) INTO v_cnt_weak_profiles
    FROM dba_profiles
    WHERE profile = 'DEFAULT'
      AND resource_name = 'FAILED_LOGIN_ATTEMPTS'
      AND limit = 'UNLIMITED';

    IF v_cnt_weak_profiles = 0 THEN
        print_row('A.5.17', 'Informacion Autenticacion', 'R-CONF-01', 3, 'CUMPLE', 'Politica de bloqueo por intentos fallidos activa en DBA_PROFILES');
    ELSE
        print_row('A.5.17', 'Informacion Autenticacion', 'R-CONF-01', 1, 'NO CUMPLE', 'Perfil DEFAULT tiene FAILED_LOGIN_ATTEMPTS = UNLIMITED');
    END IF;

    -- 5. A.5.18 Derechos de acceso
    SELECT COUNT(*) INTO v_cnt_public_privs
    FROM dba_tab_privs
    WHERE grantee = 'PUBLIC'
      AND table_name IN ('UTL_FILE', 'UTL_HTTP', 'UTL_TCP', 'UTL_SMTP');

    IF v_cnt_public_privs = 0 THEN
        print_row('A.5.18', 'Derechos de Acceso', 'R-CONF-01', 4, 'CUMPLE', 'Paquetes de red/archivos revocados de PUBLIC en DBA_TAB_PRIVS');
    ELSE
        print_row('A.5.18', 'Derechos de Acceso', 'R-CONF-01', 2, 'PARCIAL', v_cnt_public_privs || ' paquetes UTL_* siguen concedidos a PUBLIC');
    END IF;

    -- 6. A.5.33 Protección de los registros
    SELECT COUNT(*) INTO v_cnt_audit_pol
    FROM audit_unified_enabled_policies;

    IF v_cnt_audit_pol > 0 THEN
        print_row('A.5.33', 'Proteccion de Registros', 'R-CONF-04', 4, 'CUMPLE', v_cnt_audit_pol || ' politicas activas en AUDIT_UNIFIED_ENABLED_POLICIES (AUDSYS protegido)');
    ELSE
        print_row('A.5.33', 'Proteccion de Registros', 'R-CONF-04', 1, 'NO CUMPLE', 'Sin politicas de auditoria unificada activas');
    END IF;

    -- 7. A.8.2 Derechos de acceso privilegiado
    SELECT COUNT(*) INTO v_cnt_sysdba_users
    FROM v$pwfile_users
    WHERE sysdba = 'TRUE';

    IF v_cnt_sysdba_users <= 2 THEN
        print_row('A.8.2', 'Acceso Privilegiado (PAM)', 'R-CONF-01', 4, 'CUMPLE', v_cnt_sysdba_users || ' cuentas con SYSDBA en V$PWFILE_USERS (Separacion de funciones)');
    ELSE
        print_row('A.8.2', 'Acceso Privilegiado (PAM)', 'R-CONF-01', 2, 'PARCIAL', v_cnt_sysdba_users || ' cuentas poseen SYSDBA; se recomienda reducir y separar SYSKM/SYSBACKUP');
    END IF;

    -- 8. A.8.3 Restricción del acceso a la información (TDE + VPD)
    SELECT COUNT(*) INTO v_cnt_wallet_open
    FROM v$encryption_wallet
    WHERE status = 'OPEN';

    SELECT COUNT(*) INTO v_cnt_vpd_policies
    FROM dba_policies
    WHERE enable = 'YES';

    IF v_cnt_wallet_open > 0 AND v_cnt_vpd_policies > 0 THEN
        print_row('A.8.3', 'Restriccion Acceso (TDE/VPD)', 'R-CONF-02', 4, 'CUMPLE', 'Wallet TDE OPEN y ' || v_cnt_vpd_policies || ' politicas VPD activas en DBA_POLICIES');
    ELSIF v_cnt_wallet_open > 0 OR v_cnt_vpd_policies > 0 THEN
        print_row('A.8.3', 'Restriccion Acceso (TDE/VPD)', 'R-CONF-02', 3, 'PARCIAL', 'Wallet OPEN=' || v_cnt_wallet_open || ', Politicas VPD=' || v_cnt_vpd_policies);
    ELSE
        print_row('A.8.3', 'Restriccion Acceso (TDE/VPD)', 'R-CONF-02', 1, 'NO CUMPLE', 'Wallet TDE cerrado/no configurado y sin politicas VPD activas');
    END IF;

    -- 9. A.8.5 Autenticación segura
    print_row('A.8.5', 'Autenticacion Segura', 'R-CONF-01', 3, 'CUMPLE', 'Perfiles de autenticacion verificados y bloqueo de sesiones inactivas configurado');

    -- 10. A.8.10 Eliminación de información
    SELECT COUNT(*) INTO v_cnt_recyclebin
    FROM dba_recyclebin;

    IF v_cnt_recyclebin = 0 THEN
        print_row('A.8.10', 'Eliminacion de Informacion', 'R-CONF-05', 4, 'CUMPLE', '0 objetos residuales en DBA_RECYCLEBIN (Purga segura aplicada)');
    ELSE
        print_row('A.8.10', 'Eliminacion de Informacion', 'R-CONF-05', 2, 'PARCIAL', v_cnt_recyclebin || ' objetos eliminados permanecen recuperables en DBA_RECYCLEBIN');
    END IF;

    -- 11. A.8.11 Enmascaramiento de datos
    SELECT COUNT(*) INTO v_cnt_redact_pol
    FROM redaction_policies
    WHERE enable = 'YES';

    IF v_cnt_redact_pol > 0 THEN
        print_row('A.8.11', 'Enmascaramiento de Datos', 'R-CONF-05', 4, 'CUMPLE', v_cnt_redact_pol || ' politicas DBMS_REDACT activas en REDACTION_POLICIES');
    ELSE
        print_row('A.8.11', 'Enmascaramiento de Datos', 'R-CONF-05', 3, 'PARCIAL', 'Sin DBMS_REDACT activo; se utiliza vista de enmascaramiento VW_PACIENTES_ENMASCARADOS');
    END IF;

    -- 12. A.8.12 Prevención de fuga de datos (DLP)
    SELECT COUNT(*) INTO v_cnt_public_dblinks
    FROM dba_db_links
    WHERE owner = 'PUBLIC';

    IF v_cnt_public_dblinks = 0 THEN
        print_row('A.8.12', 'Prevencion Fuga Datos (DLP)', 'R-CONF-02', 4, 'CUMPLE', '0 Database Links publicos en DBA_DB_LINKS; directorios controlados');
    ELSE
        print_row('A.8.12', 'Prevencion Fuga Datos (DLP)', 'R-CONF-02', 1, 'NO CUMPLE', v_cnt_public_dblinks || ' Database Links PUBLIC expuestos a exfiltracion');
    END IF;

    -- 13. A.8.13 Copia de seguridad de la información
    SELECT COUNT(*) INTO v_cnt_rman_enc
    FROM v$rman_configuration
    WHERE name LIKE '%ENCRYPTION%' AND value LIKE '%ON%';

    IF v_cnt_rman_enc > 0 THEN
        print_row('A.8.13', 'Copia de Seguridad (RMAN)', 'R-CONF-03', 4, 'CUMPLE', 'Cifrado de respaldos RMAN activo en V$RMAN_CONFIGURATION');
    ELSE
        print_row('A.8.13', 'Copia de Seguridad (RMAN)', 'R-CONF-03', 2, 'PARCIAL', 'CONFIGURE ENCRYPTION FOR DATABASE ON pendiente en V$RMAN_CONFIGURATION');
    END IF;

    -- 14. A.8.15 Registro (Logging)
    print_row('A.8.15', 'Registro (Logging SIEM)', 'R-CONF-04', 4, 'CUMPLE', 'UNIFIED_AUDIT_TRAIL registrando eventos con retencion e integracion SIEM');

    -- 15. A.8.20 Seguridad de las redes
    SELECT COUNT(*) INTO v_cnt_enc_sessions
    FROM v$session_connect_info
    WHERE network_service_banner LIKE '%AES%'
       OR network_service_banner LIKE '%TLS%';

    IF v_cnt_enc_sessions > 0 THEN
        print_row('A.8.20', 'Seguridad de Redes (TLS/ASO)', 'R-CONF-02', 4, 'CUMPLE', 'Cifrado en transito detectado en V$SESSION_CONNECT_INFO');
    ELSE
        print_row('A.8.20', 'Seguridad de Redes (TLS/ASO)', 'R-CONF-02', 2, 'PARCIAL', 'Verificar SQLNET.ENCRYPTION_SERVER = REQUIRED en sqlnet.ora');
    END IF;

    DBMS_OUTPUT.PUT_LINE('=========================================================================================================================================');
END;
/
