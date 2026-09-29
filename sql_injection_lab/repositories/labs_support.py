from sqlalchemy import text
from sqlalchemy.engine import Engine

LABS_SCHEMA_RECREATE_QUERY = text(
    """
    IF SCHEMA_ID('Labs') IS NULL
        EXEC('CREATE SCHEMA Labs');

    DROP TABLE IF EXISTS Labs.ChatbotAudit;
    DROP TABLE IF EXISTS Labs.AttackLog;
    DROP TABLE IF EXISTS Labs.EmployeeSnapshot;
    DROP TABLE IF EXISTS Labs.ProductSearchSnapshot;

    CREATE TABLE Labs.ProductSearchSnapshot (
        product_id INT NOT NULL PRIMARY KEY,
        name NVARCHAR(255) NOT NULL,
        list_price DECIMAL(18,2) NULL,
        standard_cost DECIMAL(18,2) NULL,
        sell_start_date DATE NULL,
        product_status NVARCHAR(32) NOT NULL
            CONSTRAINT DF_ProductSearchSnapshot_product_status DEFAULT N'Available',
        description NVARCHAR(MAX) NOT NULL,
        created_at DATETIME2 NOT NULL,
        CONSTRAINT CK_ProductSearchSnapshot_product_id_six_digits
            CHECK (product_id BETWEEN 100000 AND 999999),
        CONSTRAINT CK_ProductSearchSnapshot_product_status
            CHECK (product_status IN (N'Available', N'Unavailable', N'Pending release'))
    );

    CREATE TABLE Labs.AttackLog (
        log_id INT IDENTITY(1,1) PRIMARY KEY,
        action_name NVARCHAR(80) NOT NULL,
        injected_text NVARCHAR(4000) NOT NULL,
        note NVARCHAR(300) NOT NULL,
        created_at DATETIME2 NOT NULL DEFAULT GETDATE()
    );

    CREATE TABLE Labs.EmployeeSnapshot (
        BusinessEntityID INT NOT NULL PRIMARY KEY,
        LoginID NVARCHAR(256) NOT NULL,
        SickLeaveHours INT NOT NULL,
        VacationHours INT NOT NULL,
        BirthDate DATE NOT NULL,
        JobTitle NVARCHAR(120) NOT NULL
    );

    CREATE TABLE Labs.ChatbotAudit (
        chat_id INT IDENTITY(1,1) PRIMARY KEY,
        user_message NVARCHAR(2000) NOT NULL,
        assistant_message NVARCHAR(MAX) NOT NULL,
        created_at DATETIME2 NOT NULL DEFAULT GETDATE()
    );
    """
)

LABS_SEED_PRODUCT_SNAPSHOT_QUERY = text(
    """
    ;WITH BestDesc AS (
        SELECT
            pmpdc.ProductModelID,
            pd.Description,
            rn = ROW_NUMBER() OVER (
                PARTITION BY pmpdc.ProductModelID
                ORDER BY
                    CASE WHEN pmpdc.CultureID = 'en' THEN 0 ELSE 1 END,
                    pmpdc.CultureID,
                    pmpdc.ProductDescriptionID
            )
        FROM Production.ProductModelProductDescriptionCulture AS pmpdc
        INNER JOIN Production.ProductDescription AS pd
            ON pd.ProductDescriptionID = pmpdc.ProductDescriptionID
    )
    INSERT INTO Labs.ProductSearchSnapshot (
        product_id,
        name,
        list_price,
        standard_cost,
        sell_start_date,
        product_status,
        description,
        created_at
    )
    SELECT TOP (100)
        100000 + p.ProductID AS product_id,
        p.Name AS name,
        CAST(p.ListPrice AS DECIMAL(18,2)) AS list_price,
        CAST(p.StandardCost AS DECIMAL(18,2)) AS standard_cost,
        CAST(p.SellStartDate AS DATE) AS sell_start_date,
        N'Available' AS product_status,
        COALESCE(d.Description, N'No description') AS description,
        CAST(GETDATE() AS DATETIME2) AS created_at
    FROM Production.Product AS p
    LEFT JOIN BestDesc AS d
        ON d.ProductModelID = p.ProductModelID
       AND d.rn = 1
    WHERE p.FinishedGoodsFlag = 1
    ORDER BY p.Name ASC;
    """
)

LABS_SEED_EXTRA_PRODUCT_SNAPSHOT_QUERY = text(
    """
    INSERT INTO Labs.ProductSearchSnapshot (
        product_id,
        name,
        list_price,
        standard_cost,
        sell_start_date,
        product_status,
        description,
        created_at
    )
    SELECT
        source.product_id,
        source.name,
        source.list_price,
        source.standard_cost,
        source.sell_start_date,
        source.product_status,
        source.description,
        CAST(GETDATE() AS DATETIME2)
    FROM (VALUES
        (800001, N'Archive Road Helmet', 49.99, 21.00, CAST('2018-03-15' AS DATE), N'Unavailable', N'Discontinued helmet kept in the catalog for lab status filtering.'),
        (800002, N'Archive Touring Pedal Set', 34.99, 15.50, CAST('2017-06-10' AS DATE), N'Unavailable', N'Discontinued touring pedals used as an unavailable product sample.'),
        (800003, N'Archive Carbon Bottle Cage', 24.99, 9.80, CAST('2019-01-20' AS DATE), N'Unavailable', N'Retired bottle cage retained for historical product searches.'),
        (800004, N'Archive Winter Glove', 39.99, 17.25, CAST('2016-10-01' AS DATE), N'Unavailable', N'Older winter glove model no longer sold.'),
        (800005, N'Archive City Tire 700x32', 29.99, 13.40, CAST('2015-04-18' AS DATE), N'Unavailable', N'Discontinued city tire for unavailable inventory examples.'),
        (800006, N'Archive Trail Bell', 12.99, 4.20, CAST('2018-08-05' AS DATE), N'Unavailable', N'Retired compact bell used in catalog status demos.'),
        (800007, N'Archive Alloy Seatpost', 44.99, 20.10, CAST('2017-02-12' AS DATE), N'Unavailable', N'Discontinued alloy seatpost for training data variety.'),
        (800008, N'Archive Sport Mirror', 18.99, 7.60, CAST('2016-05-30' AS DATE), N'Unavailable', N'Legacy handlebar mirror no longer available.'),
        (800009, N'Archive Mini Pump', 27.99, 11.75, CAST('2018-11-22' AS DATE), N'Unavailable', N'Discontinued mini pump retained in the lab table.'),
        (800010, N'Archive Frame Bag Small', 54.99, 24.80, CAST('2019-09-14' AS DATE), N'Unavailable', N'Retired small frame bag for unavailable product scenarios.'),
        (800011, N'Archive Commuter Light', 31.99, 13.90, CAST('2017-12-07' AS DATE), N'Unavailable', N'Legacy commuter light no longer sold.'),
        (800012, N'Archive Kids Knee Pad', 22.99, 8.95, CAST('2016-07-19' AS DATE), N'Unavailable', N'Discontinued kids protective pad for status testing.'),
        (800013, N'Preview Aero Road Frame', 899.99, 490.00, CAST('2026-09-01' AS DATE), N'Pending release', N'Upcoming aero frame scheduled for a future catalog launch.'),
        (800014, N'Preview Gravel Pack System', 189.99, 88.00, CAST('2026-10-15' AS DATE), N'Pending release', N'Modular gravel luggage system awaiting premiere.'),
        (800015, N'Preview Smart Tail Light', 74.99, 32.50, CAST('2026-08-20' AS DATE), N'Pending release', N'Connected tail light planned for release later this season.'),
        (800016, N'Preview Endurance Saddle', 119.99, 55.00, CAST('2026-11-05' AS DATE), N'Pending release', N'Upcoming endurance saddle with pressure relief channel.'),
        (800017, N'Preview Trail Hydration Vest', 139.99, 63.00, CAST('2027-02-10' AS DATE), N'Pending release', N'Future trail hydration vest for long off-road rides.'),
        (800018, N'Preview Urban Lock Pro', 99.99, 44.50, CAST('2026-12-01' AS DATE), N'Pending release', N'Upcoming compact lock with reinforced folding links.'),
        (800019, N'Preview Carbon Touring Fork', 349.99, 180.00, CAST('2027-03-18' AS DATE), N'Pending release', N'Future touring fork with cargo mounts and carbon legs.'),
        (800020, N'Preview Race Chain Wax Kit', 59.99, 22.00, CAST('2026-07-30' AS DATE), N'Pending release', N'Chain preparation kit waiting for product premiere.'),
        (800021, N'Preview All-Weather Shoe Cover', 64.99, 25.75, CAST('2026-10-01' AS DATE), N'Pending release', N'Upcoming shoe cover for wet and cold commuting.'),
        (800022, N'Preview Cargo E-Bike Rack', 229.99, 112.00, CAST('2027-01-12' AS DATE), N'Pending release', N'Future heavy-duty rack designed for cargo e-bikes.'),
        (800023, N'Preview Magnetic Tool Roll', 45.99, 18.40, CAST('2026-08-05' AS DATE), N'Pending release', N'Compact tool roll with magnetic fasteners awaiting release.'),
        (800024, N'Preview Performance Bar Tape', 38.99, 14.20, CAST('2026-09-22' AS DATE), N'Pending release', N'Upcoming high-grip bar tape for performance road bikes.'),
        (800025, N'Preview Bikepacking Stove Mount', 84.99, 39.00, CAST('2027-04-08' AS DATE), N'Pending release', N'Future accessory mount for bikepacking kitchen gear.')
    ) AS source (
        product_id,
        name,
        list_price,
        standard_cost,
        sell_start_date,
        product_status,
        description
    );
    """
)

LABS_SEED_EMPLOYEE_SNAPSHOT_QUERY = text(
    """
    INSERT INTO Labs.EmployeeSnapshot (
        BusinessEntityID,
        LoginID,
        SickLeaveHours,
        VacationHours,
        BirthDate,
        JobTitle
    )
    SELECT TOP (100)
        BusinessEntityID,
        LoginID,
        SickLeaveHours,
        VacationHours,
        BirthDate,
        JobTitle
    FROM HumanResources.Employee;
    """
)

LABS_CLEAR_ATTACK_LOG_QUERY = text(
    """
    DELETE FROM Labs.AttackLog;
    """
)


class LabsBootstrapper:
    _ready_database_urls: set[str] = set()

    def __init__(self, engine: Engine):
        self.engine = engine
        self._ready = False

    def ensure_assets(self) -> None:
        if self._ready:
            return

        if self.engine.dialect.name != "mssql":
            # Unit tests use SQLite in-memory engines; skip SQL Server-specific bootstrap there.
            self._ready = True
            return

        database_key = str(self.engine.url)
        if database_key not in self._ready_database_urls:
            with self.engine.begin() as connection:
                connection.execute(LABS_SCHEMA_RECREATE_QUERY)
                connection.execute(LABS_SEED_PRODUCT_SNAPSHOT_QUERY)
                connection.execute(LABS_SEED_EXTRA_PRODUCT_SNAPSHOT_QUERY)
                connection.execute(LABS_SEED_EMPLOYEE_SNAPSHOT_QUERY)
            self._ready_database_urls.add(database_key)

        self._ready = True

    def refresh_snapshots(self) -> None:
        if self.engine.dialect.name != "mssql":
            self._ready = True
            return

        with self.engine.begin() as connection:
            connection.execute(LABS_SCHEMA_RECREATE_QUERY)
            connection.execute(LABS_SEED_PRODUCT_SNAPSHOT_QUERY)
            connection.execute(LABS_SEED_EXTRA_PRODUCT_SNAPSHOT_QUERY)
            connection.execute(LABS_SEED_EMPLOYEE_SNAPSHOT_QUERY)

        self._ready_database_urls.add(str(self.engine.url))
        self._ready = True
