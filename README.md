# How to use this script

## Set your environment variables

Create an access key from Settings then Access key  


```
export PRISMA_API_URL="__REDACTED__"
export PRISMA_ACCESS_KEY="__REDACTED__"
export PRISMA_SECRET_KEY="__REDACTED__"
```

## Run the script

```console
python3 add_notifications.py -r repo1 repo2 --severity <SEVERITY> --integration-name <INTEGRATION_NAME>
```
