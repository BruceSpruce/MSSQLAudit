USE [master]
GO
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF NOT EXISTS
(
    SELECT *
    FROM sys.objects
    WHERE type = 'P'
          AND object_id = OBJECT_ID('usp_SecurityAuditReport')
)
    EXEC ('CREATE PROCEDURE [dbo].[usp_SecurityAuditReport] AS BEGIN SELECT 1; END');
GO


ALTER PROCEDURE [dbo].[usp_SecurityAuditReport] @loginName sysname = '%', @dbName sysname = '%', @email_rec VARCHAR(MAX) = 'e-mail@domain.com', @AuditPath NVARCHAR(200) = 'C:\\AUDIT\MSSQL_Server_Audit*.sqlaudit'
AS
	SET NOCOUNT ON

	DECLARE @IDSnap INT;
	DECLARE @LastIDSnap INT;
	DECLARE @PrevIDSnap INT;
	DECLARE @ServerLevelChanges INT;
	DECLARE @DatabaseLevelChanges INT;
	DECLARE @ObjectLevelChanges INT;
	DECLARE @AuditLastEventTime [datetime2](7);
	DECLARE @AuditChanges INT;
	-------
	DECLARE @Table NVARCHAR(MAX), @Body NVARCHAR(MAX), @TableHeader NVARCHAR(MAX), @Subject NVARCHAR(200);
	DECLARE @SendEmail bit = 0;			
	-------
	SELECT @IDSnap = ISNULL(MAX(IDSnap), 0) + 1 FROM [_SQL_].[Security].[ServerLevel]

	-- Get Server Role Level Info
	INSERT INTO [_SQL_].[Security].[ServerLevel]
	SELECT
	 SYSDATETIME() AS DateSnap,
	 @IDSnap, 
	 suser_sname(p.sid) AS Login_Name,
	 p.type_desc AS [Login_Type], 
	 r.is_disabled,
	 r.name AS Permission_Name, 
	 r.type_desc AS Permission_Type, 
	 p.create_date, p.modify_date 
	FROM
	 master.sys.server_principals r
	 LEFT OUTER JOIN master.sys.server_role_members m ON r.principal_id = m.role_principal_id
	 LEFT OUTER JOIN master.sys.server_principals p ON p.principal_id = m.member_principal_id
	WHERE p.name LIKE @loginName 
	 --AND p.type NOT IN ('R')
	UNION
	SELECT
	 SYSDATETIME() AS DateSnap,
	 @IDSnap,
	 suser_sname(prin.sid) AS Login_Name, 
	 prin.type_desc AS [Login_Type], 
	 prin.is_disabled,
	 perm.permission_name COLLATE SQL_Latin1_General_CP1_CI_AS AS Permission_Name, 
	 perm.class_desc AS Permission_Type, 
	 prin.create_date, prin.modify_date
	FROM master.sys.server_permissions perm
	 LEFT OUTER JOIN master.sys.server_principals prin ON perm.grantee_principal_id = prin.principal_id
	 LEFT OUTER JOIN master.sys.server_principals grantor ON perm.grantor_principal_id = grantor.principal_id
	WHERE prin.name LIKE @loginName 
	 --AND prin.type NOT IN ('R')
	ORDER BY Login_Name, r.name


	-- Retrieve DB Role Level Info
	DECLARE @DBRolePermissions TABLE(
	 DatabaseName varchar(300), 
	 Principal_Name sysname, 
	 Login_Name sysname NULL, 
	 DB_RoleMember varchar(300), 
	 Permission_Type sysname)

	INSERT INTO @DBRolePermissions
	EXEC sp_MSforeachdb '
	 SELECT DISTINCT ''?'' AS DatabaseName, users.Name AS UserName, suser_sname(users.sid) AS Login_Name, 
	 roles.Name AS Role_Member_Name, roles.type_desc
	 FROM [?].sys.database_role_members r 
	 LEFT OUTER JOIN [?].sys.database_principals users on r.member_principal_id = users.principal_id
	 LEFT OUTER JOIN [?].sys.database_principals roles on r.role_principal_id = roles.principal_id
	 --WHERE users.type not in (''R'')'

	-- Capture permissions generated FROM sys.database_permissions
	INSERT INTO @DBRolePermissions
	EXEC sp_MSforeachdb '
	 SELECT DISTINCT ''?'' AS DatabaseName, users.Name AS UserName, suser_sname(users.sid) AS Login_Name, 
	 r.Permission_Name AS DB_RoleMember, r.class_desc
	 FROM [?].sys.database_permissions r 
	 LEFT OUTER JOIN [?].sys.database_principals users on r.Grantee_principal_id = users.principal_id
	 WHERE r.class_desc = ''DATABASE'''

	INSERT INTO [_SQL_].[Security].[DatabaseLevel]
	SELECT DISTINCT SYSDATETIME() AS DateSnap, @IDSnap, Principal_Name, ISNULL(Login_Name, 'N/A') AS Login_Name, ISNULL(DatabaseName, 'N/A') AS DatabaseName, ISNULL(DB_RoleMember, 'N/A') AS Permission_Name, Permission_Type
	FROM @DBRolePermissions 
	WHERE (ISNULL(Login_Name, '') LIKE @loginName OR ISNULL(Principal_Name, '') LIKE @loginName)
	 AND DatabaseName LIKE @dbName
	ORDER BY Principal_Name, DatabaseName, Permission_Name

	-- GET DATA FROM AUDIT --
	-------------------------
	SELECT @AuditLastEventTime = ISNULL(MAX(DATEADD(HH, -2, event_time)), '1990-01-01 23:59:59.0000000') FROM [_SQL_].[Security].[AuditHistory];

	INSERT INTO [_SQL_].[Security].[AuditHistory]
    SELECT @IDSnap,
           DATEADD(HH, 2, event_time) AS event_time,
           AA.name AS Action_name,
           succeeded,
           is_column_permission,
           session_id,
           CT.class_type_desc,
           session_server_principal_name,
           server_principal_name,
           target_server_principal_name,
           database_principal_name,
           server_instance_name,
           database_name,
           schema_name,
           object_name,
           statement,
           additional_information
    FROM sys.fn_get_audit_file(@AuditPath, DEFAULT, DEFAULT) A
        LEFT JOIN sys.dm_audit_class_type_map CT
            ON A.class_type = CT.class_type
        LEFT JOIN
        (SELECT DISTINCT name, action_id FROM sys.dm_audit_actions) AA
            ON A.action_id = AA.action_id
    WHERE session_id > 50
          AND sequence_number = 1
          AND AA.name <> 'IMPERSONATE'
          AND event_time > @AuditLastEventTime
          AND REPLACE(REPLACE(statement, CHAR(13), ''), CHAR(10), '') NOT IN
              (
                  SELECT RTRIM(LTRIM(statement))
                  FROM [_SQL_].[Security].[AuditHistoryExceptions] AH
                  WHERE A.session_server_principal_name = AH.session_server_principal_name
              )

	SET @AuditChanges = @@ROWCOUNT;

	-- SERVER LEVEL --
	------------------

	SELECT @LastIDSnap = MAX(IDSnap), @PrevIDSnap = MAX(IDSnap)-1 FROM [_SQL_].[Security].[ServerLevel]

	IF (@LastIDSnap < 2)
	BEGIN
		SELECT N'Brak raportów do porównania (muszą być conajmniej dwa przebiegi)' AS Komunikat
	END
	ELSE
	BEGIN
		-- Właściwy raport --
		;WITH CTE AS
		(
			SELECT A.*
			FROM [_SQL_].[Security].[ServerLevel] A
				FULL JOIN [_SQL_].[Security].[ServerLevel] B ON (A.[Login_Name] = B.[Login_Name] 
															 AND A.[Login_Type] = B.[Login_Type] 
															 AND A.[is_disabled] = B.[is_disabled]
															 AND A.[Permission_Name] = B.[Permission_Name]
															 AND A.[Permission_Type] = B.[Permission_Type]
															 AND A.[create_date] = B.[create_date]
															 )
			WHERE  A.IDSnap = @LastIDSnap
			   AND B.IDSnap = @PrevIDSnap
			UNION ALL
			SELECT B.*
			FROM [_SQL_].[Security].[ServerLevel] A
				FULL JOIN [_SQL_].[Security].[ServerLevel] B ON (A.[Login_Name] = B.[Login_Name] 
															 AND A.[Login_Type] = B.[Login_Type] 
															 AND A.[is_disabled] = B.[is_disabled]
															 AND A.[Permission_Name] = B.[Permission_Name]
															 AND A.[Permission_Type] = B.[Permission_Type]
															 AND A.[create_date] = B.[create_date]
															 )
			WHERE  A.IDSnap = @LastIDSnap
			   AND B.IDSnap = @PrevIDSnap
		)
		INSERT INTO [_SQL_].[Security].[ServerLevelChange]
		SELECT 'GRANT' AS [Permission_Change], SYSDATETIME() AS DiscoverChangeDate, DateSnap, IDSnap, Login_Name, Login_Type, is_disabled, Permission_Name, Permission_Type, create_date, modify_date FROM [_SQL_].[Security].[ServerLevel] A 
			WHERE A.IDSnap = @LastIDSnap
			AND A.ID NOT IN (SELECT ID FROM CTE)
		EXCEPT
		SELECT 'GRANT' AS [Permission_Change], SYSDATETIME() AS DiscoverChangeDate, DateSnap, IDSnap, Login_Name, Login_Type, is_disabled, Permission_Name, Permission_Type, create_date, modify_date FROM [_SQL_].[Security].[ServerLevel] A 
			WHERE A.IDSnap = @PrevIDSnap
			AND A.ID NOT IN (SELECT ID FROM CTE)
		UNION
		SELECT 'REVOKE' AS [Permission_Change], SYSDATETIME() AS DiscoverChangeDate, DateSnap, IDSnap, Login_Name, Login_Type, is_disabled, Permission_Name, Permission_Type, create_date, modify_date FROM [_SQL_].[Security].[ServerLevel] A 
			WHERE A.IDSnap = @PrevIDSnap
			AND A.ID NOT IN (SELECT ID FROM CTE)

		SET @ServerLevelChanges = @@ROWCOUNT;

		-- DATABASE LEVEL --
		--------------------

		;WITH CTE AS
		(
			SELECT A.*
			FROM [_SQL_].[Security].[DatabaseLevel] A
				FULL JOIN [_SQL_].[Security].[DatabaseLevel] B	ON (A.[Principal_Name] = B.[Principal_Name] 
																AND A.[Login_Name] = B.[Login_Name] 
																AND A.[DatabaseName] = B.[DatabaseName]
																AND A.[Permission_Name] = B.[Permission_Name]
																AND A.[Permission_Type] = B.[Permission_Type]
																)
			WHERE  A.IDSnap = @LastIDSnap
			   AND B.IDSnap = @PrevIDSnap
			UNION ALL
			SELECT B.*
			FROM [_SQL_].[Security].[DatabaseLevel] A
				FULL JOIN [_SQL_].[Security].[DatabaseLevel] B	ON (A.[Principal_Name] = B.[Principal_Name] 
																AND A.[Login_Name] = B.[Login_Name] 
																AND A.[DatabaseName] = B.[DatabaseName]
																AND A.[Permission_Name] = B.[Permission_Name]
																AND A.[Permission_Type] = B.[Permission_Type]
																)
			WHERE  A.IDSnap = @LastIDSnap
			   AND B.IDSnap = @PrevIDSnap
		)
		INSERT INTO [_SQL_].[Security].[DatabaseLevelChange]
		SELECT 'GRANT' AS [Permission_Change], SYSDATETIME() AS DiscoverChangeDate, DateSnap, IDSnap, Principal_Name, Login_Name, DatabaseName, Permission_Name, Permission_Type FROM [_SQL_].[Security].[DatabaseLevel] A 
			WHERE A.IDSnap = @LastIDSnap
			AND A.ID NOT IN (SELECT ID FROM CTE)
		EXCEPT
		SELECT 'GRANT' AS [Permission_Change], SYSDATETIME() AS DiscoverChangeDate, DateSnap, IDSnap, Principal_Name, Login_Name, DatabaseName, Permission_Name, Permission_Type FROM [_SQL_].[Security].[DatabaseLevel] A 
			WHERE A.IDSnap = @PrevIDSnap
			AND A.ID NOT IN (SELECT ID FROM CTE)
		UNION
		SELECT 'REVOKE' AS [Permission_Change], SYSDATETIME() AS DiscoverChangeDate, DateSnap, IDSnap, Principal_Name, Login_Name, DatabaseName, Permission_Name, Permission_Type FROM [_SQL_].[Security].[DatabaseLevel] A 
			WHERE A.IDSnap = @PrevIDSnap
			AND A.ID NOT IN (SELECT ID FROM CTE)
	
		SET @DatabaseLevelChanges = @@ROWCOUNT;
	END
	
	--CREATE HTML REPOPRT

	SET @Body = '<html><head>' +
				'<style>' +
				'td {border: solid black 1px;padding-left:5px;padding-right:5px;padding-top:1px;padding-bottom:1px;font-size:11pt;} ' +
				'</style>' +
				'</head><body>';

	IF (@ServerLevelChanges > 0)
	BEGIN
		--SELECT TOP(@ServerLevelChanges) * FROM [_SQL_].[Security].[ServerLevelChange] ORDER BY ID DESC
		SET @TableHeader =	'<table cellpadding=0 cellspacing=0 border=0><caption>SERVER LEVEL CHANGES</caption>' +
							'<tr bgcolor=#ffd9cc>' +
							'<td align=center><b>ID</b></td>' +
							'<td align=center><b>Permission_Change</b></td>' +
							'<td align=center><b>DiscoverChangeDate</b></td>' +
							'<td align=center><b>LoginName</b></td>' +
							'<td align=center><b>Login_Type</b></td>' +
							'<td align=center><b>is_disabled</b></td>' + 
							'<td align=center><b>Permission_Name</b></td>' + 
							'<td align=center><b>Permission_Type</b></td>' + 
							'<td align=center><b>create_date</b></td>' + 
							'<td align=center><b>modify_date</b></td></tr>';

		Select @Body = @Body + @TableHeader + 
						 (SELECT TOP(@ServerLevelChanges) ID AS [TD align=right]
						  ,ISNULL(Permission_Change, 'n/a') AS [TD align=left]
						  ,CONVERT(char(19), DiscoverChangeDate, 121) AS [TD align=center]
						  ,ISNULL(Login_Name, 'n/a') AS [TD align=right]
						  ,ISNULL(Login_Type, 'n/a') AS [TD align=center]
						  ,CAST(ISNULL(is_disabled, 0) AS NVARCHAR) AS [TD align=center]
						  ,ISNULL(Permission_Name, 'n/a') AS [TD align=left]
						  ,ISNULL(Permission_Type, 'n/a') AS [TD align=left]
						  ,CONVERT(char(19), create_date, 121) AS [TD align=center]
						  ,CONVERT(char(19), modify_date, 121) AS [TD align=center]
					FROM [_SQL_].[Security].[ServerLevelChange] ORDER BY ID DESC
					For XML raw('tr'), Elements) + '</table>'

		-- Replace the entity codes and row numbers
		Set @Body = Replace(@Body, '_x0020_', space(1))
		Set @Body = Replace(@Body, '_x003D_', '=')
		Set @SendEmail = 1;

	END --Of ServerLevelChanges

	IF (@DatabaseLevelChanges > 0)
	BEGIN
		--SELECT TOP(@DatabaseLevelChanges) * FROM [_SQL_].[Security].[DatabaseLevelChange] ORDER BY ID DESC;
		SET @TableHeader =	'</br><table cellpadding=0 cellspacing=0 border=0><caption>DATABSE LEVEL CHANGES</caption>' +
							'<tr bgcolor=#ccccff>' +
							'<td align=center><b>ID</b></td>' +
							'<td align=center><b>Permission_Change</b></td>' +
							'<td align=center><b>DiscoverChangeDate</b></td>' +
							'<td align=center><b>Principal_Name</b></td>' +
							'<td align=center><b>Login_Name</b></td>' +
							'<td align=center><b>Database_Name</b></td>' + 
							'<td align=center><b>Permission_Name</b></td>' + 
							'<td align=center><b>Permission_Type</b></td>';

		Select @Body = @Body + @TableHeader + 
						 (SELECT TOP(@DatabaseLevelChanges) ID AS [TD align=right]
						  ,ISNULL(Permission_Change, 'n/a') AS [TD align=left]
						  ,CONVERT(char(19), DiscoverChangeDate, 121) AS [TD align=center]
						  ,ISNULL(Principal_Name, 'n/a') AS [TD align=right]
						  ,ISNULL(Login_Name, 'n/a') AS [TD align=center]
						  ,ISNULL(DatabaseName, 'n/a') AS [TD align=left]
						  ,ISNULL(Permission_Name, 'n/a') AS [TD align=left]
						  ,ISNULL(Permission_Type, 'n/a') AS [TD align=left]
					FROM [_SQL_].[Security].[DatabaseLevelChange] ORDER BY ID DESC
					For XML raw('tr'), Elements) + '</table>'

		-- Replace the entity codes and row numbers
		Set @Body = Replace(@Body, '_x0020_', space(1))
		Set @Body = Replace(@Body, '_x003D_', '=')
		Set @SendEmail = 1;
	END --IF (@DatabaseLevelChanges > 0)

	IF (@AuditChanges > 0)
	BEGIN
		SET @TableHeader =	'</br><table cellpadding=0 cellspacing=0 border=0><caption>TOP 10 of ' + CAST(@AuditChanges AS VARCHAR) + ' AUDIT ENTRIES</caption>' +
							'<tr bgcolor=#ffcccc>' +
							'<td align=center><b>ID</b></td>' +
							'<td align=center><b>Event Time</b></td>' +
							'<td align=center><b>Action Name</b></td>' +
							'<td align=center><b>Is succeeded?</b></td>' +
							'<td align=center><b>Is column permission?</b></td>' +
							'<td align=center><b>Class Type</b></td>' + 
							'<td align=center><b>Session Srver Name</b></td>' + 
							'<td align=center><b>Target Server Name</b></td>' +
							'<td align=center><b>Database Name</b></td>' +
							'<td align=center><b>Schema Name</b></td>' +
							'<td align=center><b>Object Name</b></td>' +
							'<td align=center><b>Statement (cut to 80 char)</b></td>';

		Select @Body = @Body + @TableHeader + 
						 (SELECT TOP(10) ID AS [TD align=right]
						  ,CONVERT(char(19), event_time, 121) AS [TD align=center]
						  ,ISNULL(Action_name, 'n/a') AS [TD align=left]
						  ,ISNULL(succeeded, 'n/a') AS [TD align=center]
						  ,ISNULL(is_column_permission, 'n/a') AS [TD align=center]
						  ,ISNULL(class_type_desc, 'n/a') AS [TD align=left]
						  ,ISNULL(session_server_principal_name, 'n/a') AS [TD align=left]
						  ,ISNULL(target_server_principal_name, 'n/a') AS [TD align=left]
						  ,ISNULL(database_name, 'n/a') AS [TD align=left]
						  ,ISNULL(schema_name, 'n/a') AS [TD align=left]
						  ,ISNULL(object_name, 'n/a') AS [TD align=left]
						  ,ISNULL(SUBSTRING(statement, 0, 80), 'n/a') + ' /cut' AS [TD align=left]
					FROM [_SQL_].[Security].[AuditHistory]
					WHERE IDSnap = @IDSnap
					ORDER BY ID DESC
					For XML raw('tr'), Elements) + '</table></br>'
		
		-- AGREGATION --

		SET @TableHeader =	'</br><table cellpadding=0 cellspacing=0 border=0><caption>AGGREGATE AUDIT ENTRIES</caption>' +
							'<tr bgcolor=#ffcccc>' +
							'<td align=center><b>Session Srver Name</b></td>' +
							'<td align=center><b>Is succeeded?</b></td>' +
							'<td align=center><b>Count</b></td>';

		Select @Body = @Body + @TableHeader + 
						 (SELECT 
						  ISNULL(session_server_principal_name, 'n/a') AS [TD align=left]
						  ,ISNULL(succeeded, 'n/a') AS [TD align=center]						  
						  ,CAST(COUNT(*) AS VARCHAR) AS [TD align=right]
					FROM [_SQL_].[Security].[AuditHistory]
					WHERE IDSnap = @IDSnap
					GROUP BY [session_server_principal_name],[succeeded]
					ORDER BY COUNT(*) DESC
					For XML raw('tr'), Elements) + '</table>'

		-- Replace the entity codes and row numbers
		Set @Body = Replace(@Body, '_x0020_', space(1))
		Set @Body = Replace(@Body, '_x003D_', '=')
		Set @SendEmail = 1;
	END -- IF (@AuditChanges > 0) 

	IF (@SendEmail = 1 AND @email_rec <> '')
	BEGIN
		SET @Body = @Body + '</body>';
		
		SET @Subject = '[' + @@servername + '] SECURITY REPORT OF ' +  CONVERT(CHAR(10), GETDATE(), 121)
	
		EXEC msdb.dbo.sp_send_dbmail
				@profile_name = 'mail_profile',
				@recipients = @email_rec,
				@body =  @Body,
				@subject = @Subject,
				@body_format = 'HTML';
	END --Send email

