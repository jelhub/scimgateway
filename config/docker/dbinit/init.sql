USE [master];
GO

IF NOT EXISTS (SELECT * FROM sys.sql_logins WHERE name = 'scimgateway')
BEGIN
    CREATE LOGIN [scimgateway] WITH PASSWORD = 'password', CHECK_POLICY = OFF;
    ALTER SERVER ROLE [sysadmin] ADD MEMBER [scimgateway];
END
GO

IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'scimgateway')
BEGIN
    CREATE TABLE [dbo].[scimgateway] (
        [UserID] VARCHAR(50) NOT NULL,
        [Enabled] VARCHAR(50) NULL,
        [Password] VARCHAR(50) NULL,
        [FirstName] VARCHAR(50) NULL,
        [MiddleName] VARCHAR(50) NULL,
        [LastName] VARCHAR(50) NULL,
        [Email] VARCHAR(50) NULL,
        [MobilePhone] VARCHAR(50) NULL,
        CONSTRAINT [PK_scimgateway] PRIMARY KEY ([UserID])
    );
END
GO

