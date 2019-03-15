USE [_SQL_]
GO
CREATE SCHEMA Security
GO
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [Security].[AuditHistory](
	[ID] [INT] IDENTITY(1,1) NOT NULL,
	[IDSnap] [INT] NOT NULL,
	[event_time] [DATETIME2](7) NOT NULL,
	[Action_name] [NVARCHAR](128) NULL,
	[succeeded] [BIT] NOT NULL,
	[is_column_permission] [BIT] NOT NULL,
	[session_id] [SMALLINT] NOT NULL,
	[class_type_desc] [NVARCHAR](35) NULL,
	[session_server_principal_name] [NVARCHAR](128) NULL,
	[server_principal_name] [NVARCHAR](128) NULL,
	[target_server_principal_name] [NVARCHAR](128) NULL,
	[database_principal_name] [NVARCHAR](128) NULL,
	[server_instance_name] [NVARCHAR](128) NULL,
	[database_name] [NVARCHAR](128) NULL,
	[schema_name] [NVARCHAR](128) NULL,
	[object_name] [NVARCHAR](128) NULL,
	[statement] [NVARCHAR](4000) NULL,
	[additional_information] [NVARCHAR](4000) NULL,
 CONSTRAINT [PK_ID_AuditHistory] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
) ON [PRIMARY]
GO

CREATE NONCLUSTERED INDEX [IX_event_time] ON [Security].[AuditHistory]
(
	[event_time] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
GO

CREATE TABLE [Security].[DatabaseLevel](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[DateSnap] [datetime2](7) NOT NULL,
	[IDSnap] [int] NOT NULL,
	[Principal_Name] [sysname] NOT NULL,
	[Login_Name] [sysname] NULL,
	[DatabaseName] [varchar](300) NULL,
	[Permission_Name] [varchar](300) NULL,
	[Permission_Type] [sysname] NOT NULL,
 CONSTRAINT [PK_ID_DatabaseLevel] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
) ON [PRIMARY]
GO

CREATE TABLE [Security].[DatabaseLevelChange](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Permission_Change] [nvarchar](6) NOT NULL,
	[DiscoverChangeDate] [datetime] NOT NULL,
	[DateSnap] [datetime2](7) NOT NULL,
	[IDSnap] [int] NOT NULL,
	[Principal_Name] [sysname] NOT NULL,
	[Login_Name] [sysname] NULL,
	[DatabaseName] [varchar](300) NULL,
	[Permission_Name] [varchar](300) NULL,
	[Permission_Type] [sysname] NOT NULL,
 CONSTRAINT [PK_ID_DatabaseLevelChange] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
) ON [PRIMARY]
GO

CREATE NONCLUSTERED INDEX [IX_DiscoverChangeDate] ON [Security].[DatabaseLevelChange]
(
	[DiscoverChangeDate] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
GO

CREATE TABLE [Security].[ServerLevel](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[DateSnap] [datetime] NOT NULL,
	[IDSnap] [int] NOT NULL,
	[Login_Name] [nvarchar](128) NULL,
	[Login_Type] [nvarchar](60) NULL,
	[is_disabled] [bit] NULL,
	[Permission_Name] [nvarchar](128) NULL,
	[Permission_Type] [nvarchar](60) NULL,
	[create_date] [datetime] NULL,
	[modify_date] [datetime] NULL,
 CONSTRAINT [PK_ID_ServerLevel] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
) ON [PRIMARY]
GO

CREATE NONCLUSTERED INDEX [IX_SnapDate] ON [Security].[ServerLevel]
(
	[DateSnap] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
GO

CREATE TABLE [Security].[ServerLevelChange](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Permission_Change] [nvarchar](6) NOT NULL,
	[DiscoverChangeDate] [datetime] NOT NULL,
	[DateSnap] [datetime] NOT NULL,
	[IDSnap] [int] NOT NULL,
	[Login_Name] [nvarchar](128) NULL,
	[Login_Type] [nvarchar](60) NULL,
	[is_disabled] [bit] NULL,
	[Permission_Name] [nvarchar](128) NULL,
	[Permission_Type] [nvarchar](60) NULL,
	[create_date] [datetime] NULL,
	[modify_date] [datetime] NULL,
 CONSTRAINT [PK_ID_ServerLevelChange] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
) ON [PRIMARY]
GO

CREATE NONCLUSTERED INDEX [IX_DiscoverChangeDate] ON [Security].[ServerLevelChange]
(
	[DiscoverChangeDate] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
GO

CREATE TABLE [Security].[AuditHistoryExceptions](
	[ID] [INT] IDENTITY(1,1) NOT NULL,
	[session_server_principal_name] [NVARCHAR](128) NULL,
	[statement] [NVARCHAR](4000) NULL,
 CONSTRAINT [PK_ID_AuditHistoryExceptions] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 85) ON [PRIMARY]
) ON [PRIMARY]
GO
