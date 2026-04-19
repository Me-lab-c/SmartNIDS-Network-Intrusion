import pyodbc

conn = pyodbc.connect(
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=MANVITHA\\SQLEXPRESS;"
    "DATABASE=NIDS_DB;"
    "Trusted_Connection=yes;"
)

cursor = conn.cursor()
cursor.execute("SELECT GETDATE()")
row = cursor.fetchone()

print("Connected to MSSQL. Current time:", row[0])

conn.close()
