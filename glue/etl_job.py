import sys
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from pyspark.sql.functions import col, trim
from pyspark.sql.types import FloatType

args = getResolvedOptions(sys.argv, ['JOB_NAME'])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

# Read raw CSV from S3
df = spark.read.option("header", "true").option("inferSchema", "false").csv("s3://aws-ids-platform/raw/friday-ddos.csv")

# Trim whitespace from all column names (CICIDS has spaces in headers)
df = df.toDF(*[c.strip() for c in df.columns])

# Drop rows with nulls or infinite values
df = df.dropna()

# Cast all feature columns to float (leave Label as string)
feature_cols = [c for c in df.columns if c != "Label"]
for c in feature_cols:
    df = df.withColumn(c, col(c).cast(FloatType()))

# Drop rows where casting failed (nulls introduced by bad values)
df = df.dropna()

# Write cleaned data to processed folder as CSV
df.write.mode("overwrite").option("header", "true").csv("s3://aws-ids-platform/processed/friday-ddos-clean/")

job.commit()