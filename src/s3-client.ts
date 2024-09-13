import { S3 } from "@aws-sdk/client-s3";
import { env } from './env';

export const s3Client = new S3({
  endpoint: env.DO_SPACES_ENDPOINT,
  region: env.DO_SPACES_REGION,
  credentials: {
    accessKeyId: env.DO_SPACES_ACCESS_KEY,
    secretAccessKey: env.DO_SPACES_SECRET_KEY,
  }
});

export const BUCKET_NAME = env.DO_SPACES_BUCKET;