CREATE TABLE prediction_logs (
    id INT IDENTITY(1,1) PRIMARY KEY,
    timestamp DATETIME DEFAULT GETDATE(),
    input_data NVARCHAR(MAX),
    prediction NVARCHAR(20),
    model_used NVARCHAR(50)
);

ALTER TABLE prediction_logs
ADD severity VARCHAR(20);

ALTER TABLE prediction_logs
ADD attack_pattern VARCHAR(50);



SELECT * FROM prediction_logs;

SELECT TOP 10 prediction FROM prediction_logs ORDER BY id DESC;

