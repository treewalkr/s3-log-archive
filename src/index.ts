import { createHash } from "crypto";
import { Elysia, t } from "elysia";
import { Upload } from "@aws-sdk/lib-storage";
import { env } from "./env";
import { s3Client, BUCKET_NAME } from "./s3-client";
import { calculateSignature, verifySignature } from "./lib/signature";

const app = new Elysia()
  .post(
    "/upload-logs",
    async ({ request, body: { title, file }, set }) => {
      const timestamp = request.headers.get("x-timestamp");
      const signature = request.headers.get("x-signature");
      const androidId = request.headers.get("x-device-id");
      const fileHash = request.headers.get("x-file-hash");

      if (!timestamp || !signature || !androidId || !fileHash) {
        set.status = 401;
        console.warn("Missing required headers!");
        return { error: "Unauthorized" };
      }

      const contentType = request.headers.get("content-type") || "";

      if (!file) {
        console.error("No file uploaded");
        set.status = 400;
        return { error: "No file uploaded" };
      }

      let fileBuffer: ArrayBuffer | null = null;
      try {
        fileBuffer = await file.arrayBuffer();
        const calculatedHash = createHash("sha256")
          .update(Buffer.from(fileBuffer))
          .digest("hex");

        if (calculatedHash !== fileHash) {
          console.warn("File hash mismatch!");
          set.status = 400;
          return { error: "File integrity check failed" };
        }

        const calculatedSignature = calculateSignature(
          timestamp,
          contentType,
          androidId,
          fileHash
        );

        if (!verifySignature(signature, calculatedSignature)) {
          console.warn("Signature verification failed!");
          set.status = 401;
          return { error: "Unauthorized" };
        }

        console.debug("Signature verified!");

        const filename = `${androidId}-${file.name}`;

        // Upload to S3
        const upload = new Upload({
          client: s3Client,
          params: {
            Bucket: BUCKET_NAME,
            Key: filename,
            Body: Buffer.from(fileBuffer),
            ACL: "public-read",
            Metadata: {
              "sha256-hash": fileHash,
            },
          },
        });
        const result = await upload.done();

        return {
          message: "File uploaded successfully to S3",
          filename,
          title,
          s3Location: result.Location,
          sha256Hash: fileHash,
        };
      } catch (error) {
        console.error("Error processing or uploading file:", error);
        set.status = 500;
        return { error: "Failed to process or upload file" };
      } finally {
        // Explicitly clear the buffer reference
        if (fileBuffer) {
          fileBuffer = null;
        }
      }
    },
    {
      body: t.Object({
        title: t.String(),
        file: t.File({
          maxSize: "50m",
          type: ["application/zip"],
        }),
      }),
    }
  )
  .listen(env.APP_PORT);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
);
