import { t } from "elysia";
import { TypeCompiler } from "@sinclair/typebox/compiler";

const structure = t.Object({
  DO_SPACES_ENDPOINT: t.String(),
  DO_SPACES_REGION: t.String(),
  DO_SPACES_ACCESS_KEY: t.String(),
  DO_SPACES_SECRET_KEY: t.String(),
  DO_SPACES_BUCKET: t.String(),
  APP_PORT: t.String({ default: "3000" }),
  SECRET_KEY: t.String(),
});

const compiler = TypeCompiler.Compile(structure);

if (!compiler.Check(process.env))
  throw new Error("Invalid environment variables");

export const env = compiler.Decode(process.env);
