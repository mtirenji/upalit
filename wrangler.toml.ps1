@"
name = "upalit-backend"
main = "src/worker.js"
compatibility_date = "2024-01-01"

[vars]
NODE_ENV = "production"

[[r2_buckets]]
binding = "DATA_BUCKET"
bucket_name = "upalit-data"
preview_bucket_name = "upalit-data-preview"

[env.production]
vars = { NODE_ENV = "production" }

[env.preview]
vars = { NODE_ENV = "preview" }
"@ | Out-File -FilePath wrangler.toml -Encoding utf8