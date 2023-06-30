__author__ = "Simon Melotte"

import os
import requests
import argparse
import json
from datetime import datetime


def get_code_security_notification(base_url, token):
    try:
        url = f"https://{base_url}/code/api/v1/vcs/settings/scheme?featureType=pcNotifications"
        headers = {"content-type": "application/json; charset=UTF-8",
                   'Authorization': f'Bearer {token}'}
        response = requests.get(url, headers=headers)
        data = response.json()
        for section in data.get("sections", []):
            section.pop("id", None)
            section.pop("name", None)
            section.pop("isEnabled", None)
            section.pop("notificationType", None)
            section.pop("systems", None)
            if "rule" in section and "pcNotificationIntegrations" in section["rule"]:
                for integration in section["rule"]["pcNotificationIntegrations"]:
                    integration.pop("templateId", None)
        return data
    except Exception as e:
        print(f"Error in get_code_security_notification: {e}")
        return None


def set_code_security_notification(base_url, token, existing_notifications):
    try:
        url = f"https://{base_url}/code/api/v1/vcs/settings/scheme"
        headers = {"content-type": "application/json; charset=UTF-8",
                   'Authorization': f'Bearer {token}'}
        parameters = {"scheme": {"pcNotifications": existing_notifications},
                      "type": "pcNotifications"}
        response = requests.post(
            url, headers=headers, data=json.dumps(parameters))
        print(f"Response: {response}")
    except Exception as e:
        print(f"Error in set_code_security_notification: {e}")


def add_section(existing_notifications, repos, severity_level, integration_id, is_default=False):
    try:
        new_section = {
            "repos": repos,
            "rule": {
                "severityLevel": severity_level,
                "excludePolicies": [],
                "securityCategories": [],
                "pcNotificationIntegrations": [
                    {"integrationId": integration_id}
                ]
            },
            "isDefault": is_default
        }
        if existing_notifications and "sections" in existing_notifications:
            existing_notifications["sections"].append(new_section)
        return existing_notifications
    except Exception as e:
        print(f"Error in add_section: {e}")
        return None


def get_prisma_id(base_url, token):
    try:
        url = f"https://{base_url}/license"
        headers = {'x-redlock-auth': token}
        response = requests.get(url, headers=headers)
        data = response.json()
        return data.get("prismaId")
    except Exception as e:
        print(f"Error in get_prisma_id: {e}")
        return None


def get_integration_id(base_url, token, prisma_id, integration_name):
    try:
        url = f"https://{base_url}/api/v1/tenant/{prisma_id}/integration"
        headers = {"content-type": "application/json; charset=UTF-8",
                   'Authorization': 'Bearer ' + token}
        response = requests.get(url, headers=headers)
        data = response.json()
        for integration in data:
            if integration.get("name") == integration_name:
                return integration.get("id")
        # If the integration name is not found, raise an exception
        raise ValueError(
            f"Integration with name {integration_name} not found.")
    except Exception as e:
        # Re-raise the exception to be handled by the caller
        raise Exception(f"Error in get_integration_id: {e}")


def login_saas(base_url, access_key, secret_key):
    try:
        url = f"https://{base_url}/login"
        payload = json.dumps({
            "username": access_key,
            "password": secret_key
        })
        headers = {"content-type": "application/json; charset=UTF-8"}
        response = requests.post(url, headers=headers, data=payload)
        return response.json().get("token")
    except Exception as e:
        print(f"Error in login_saas: {e}")
        return None


def main(repositories, severity_level, integration_name):
    try:
        url = os.environ.get('PRISMA_API_URL')
        identity = os.environ.get('PRISMA_ACCESS_KEY')
        secret = os.environ.get('PRISMA_SECRET_KEY')

        if not url or not identity or not secret:
            print(
                "Error: PRISMA_API_URL, PRISMA_ACCESS_KEY or PRISMA_SECRET_KEY environment variables are not set.")
            return

        token = login_saas(url, identity, secret)

        if token is None:
            print("Error: Unable to authenticate.")
            return

        existing_notifications = get_code_security_notification(url, token)
        
        prisma_id = get_prisma_id(url, token)
        try:
            integration_id = get_integration_id(
                url, token, prisma_id, integration_name)
        except Exception as e:
            print(e)
            return


        existing_notifications = add_section(
            existing_notifications, repositories, severity_level, integration_id, False)
        set_code_security_notification(url, token, existing_notifications)

    except Exception as e:
        print(f"Error in main function: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Configure Prisma Cloud")
    parser.add_argument("-r", "--repositories", nargs='+', required=True,
                        help="List of repositories")
    parser.add_argument("-s", "--severity", required=True, choices=[
                        'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], help="Severity level")
    parser.add_argument("-i", "--integration-name",
                        required=True, help="Integration name")
    args = parser.parse_args()

    main(args.repositories, args.severity, args.integration_name)
