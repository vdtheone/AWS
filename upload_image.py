import boto3
from dotenv import load_dotenv
import os

load_dotenv()

# Initialize the session with specified credentials
session = boto3.Session(
    aws_access_key_id=os.getenv("aws_access_key_id"),
    aws_secret_access_key=os.getenv("aws_secret_access_key"),
    region_name=os.getenv("aws_default_region"),
)

# Initialize the S3 client using the session
s3 = session.client("s3")


# Specify your bucket name and the local file path of the image you want to upload
bucket_name = "mysampleawsbuckett"


async def upload_image_to_bucket(contents, s3_key):
    try:
        s3.upload_file(contents, bucket_name, s3_key)
        object_key = s3_key
        presigned_url = s3.generate_presigned_url(
            ClientMethod="get_object",  # The operation to perform on the object (e.g., 'get_object', 'put_object')
            Params={
                "Bucket": bucket_name,
                "Key": object_key,
            },  # Parameters for the operation
            ExpiresIn=3600,  # Expiration time for the URL in seconds (e.g., 3600 for 1 hour)
        )
        print(presigned_url)
        return {"message": "Upload Successfully", "url": presigned_url}
    except Exception as e:
        print(str(e))
