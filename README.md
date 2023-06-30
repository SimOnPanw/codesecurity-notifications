# How to use this script

## Authentication

Create an access key from Settings then Access key  
Get the path to console from Compute tab, System, Utilities  

Create a file into home directory .prismacloud/credentials.json with the following structure  

```json
export PRISMA_API_URL="__REDACTED__"
export PRISMA_ACCESS_KEY="__REDACTED__"
export PRISMA_SECRET_KEY="__REDACTED__"
```

## Run the script

```console
python3 code_security.py
```
