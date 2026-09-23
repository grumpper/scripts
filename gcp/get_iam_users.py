#!/usr/bin/env python3
"""
GCP Human IAM User Inventory

Creates effective_user_access.csv with one row per unique human user that has
IAM access assigned at Organization, Folder, or Project level in the single GCP
organization visible to the current Application Default Credentials.

Direct user grants and Google Group grants are included. Groups are recursively
expanded, including nested groups. Service accounts are excluded.

CSV columns:
    user, group, resource, role

Resources are shown with their type, display name, and identifier where available,
for example: project:Payments Production (my-project-id).

Multiple groups/resources/roles are semicolon-separated.

Dependencies:

    Python:
        pip install google-cloud-asset google-api-python-client google-auth

    Enabled GCP APIs:
        cloudasset.googleapis.com
        cloudresourcemanager.googleapis.com
        cloudidentity.googleapis.com

    Permissions:
        roles/resourcemanager.organizationViewer
        roles/cloudasset.viewer
        roles/serviceusage.serviceUsageConsumer
"""

import csv
import sys
from collections import defaultdict

import google.auth
from google.cloud import asset_v1
from googleapiclient.discovery import build


OUTPUT_FILE = "effective_user_access.csv"
ASSET_TYPES = [
    "cloudresourcemanager.googleapis.com/Organization",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Project",
]


def get_organization(credentials):
    service = build(
        "cloudresourcemanager", "v3",
        credentials=credentials,
        cache_discovery=False,
    )
    orgs = service.organizations().search(pageSize=100).execute(num_retries=3).get(
        "organizations", []
    )

    if len(orgs) != 1:
        raise RuntimeError(
            f"Expected exactly one visible GCP organization, found {len(orgs)}."
        )

    return orgs[0]


def resource_key(resource):
    """Return a stable type:id key for a Resource Manager resource name."""
    resource_id = resource.rsplit("/", 1)[-1]

    for plural, singular in (
            ("/organizations/", "organization"),
            ("/folders/", "folder"),
            ("/projects/", "project"),
    ):
        if plural in resource:
            return f"{singular}:{resource_id}"

    return resource


def get_resource_names(org_name, organization, credentials):
    """Build a type:id -> human-friendly display name map in one asset search."""
    client = asset_v1.AssetServiceClient(credentials=credentials)
    names = {
        resource_key(f"//cloudresourcemanager.googleapis.com/{org_name}"):
            f"organization:{organization.get('displayName', org_name)} "
            f"({org_name.rsplit('/', 1)[-1]})"
    }

    request = asset_v1.SearchAllResourcesRequest(
        scope=org_name,
        asset_types=ASSET_TYPES,
    )

    for result in client.search_all_resources(request=request):
        key = resource_key(result.name)
        resource_type, _, resource_id = key.partition(":")
        display_name = result.display_name

        names[key] = (
            f"{resource_type}:{display_name} ({resource_id})"
            if display_name
            else key
        )

    return names


def get_iam_bindings(org_name, credentials, resource_names):
    client = asset_v1.AssetServiceClient(credentials=credentials)
    request = asset_v1.SearchAllIamPoliciesRequest(
        scope=org_name,
        asset_types=ASSET_TYPES,
    )

    for result in client.search_all_iam_policies(request=request):
        key = resource_key(result.resource)
        resource = resource_names.get(key, key)

        for binding in result.policy.bindings:
            role = binding.role
            if binding.condition and binding.condition.expression:
                role += " [conditional]"

            for member in binding.members:
                yield member, resource, role


def expand_group(service, group_email, cache, ancestry=None):
    """Return all human users in a Google Group, recursively."""
    group_email = group_email.lower()

    if group_email in cache:
        return cache[group_email]

    ancestry = ancestry or set()
    if group_email in ancestry:
        return set()

    group_name = (
        service.groups()
        .lookup(groupKey_id=group_email)
        .execute(num_retries=3)["name"]
    )

    users = set()
    api = service.groups().memberships()
    request = api.list(parent=group_name, view="FULL", pageSize=500)

    while request:
        response = request.execute(num_retries=3)

        for membership in response.get("memberships", []):
            email = membership.get("preferredMemberKey", {}).get("id")
            member_type = membership.get("type")

            if not email:
                continue

            if member_type == "USER":
                users.add(email.lower())
            elif member_type == "GROUP":
                users.update(
                    expand_group(
                        service,
                        email,
                        cache,
                        ancestry | {group_email},
                        )
                )

        request = api.list_next(request, response)

    cache[group_email] = users
    return users


def main():
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    organization = get_organization(credentials)

    print(
        f"Organization: {organization.get('displayName', 'unknown')} "
        f"({organization['name']})"
    )
    print("Resolving Organization, Folder and Project display names...")
    resource_names = get_resource_names(
        organization["name"], organization, credentials
    )

    print("Scanning Organization, Folder and Project IAM...")

    users = defaultdict(lambda: {"groups": set(), "resources": set(), "roles": set()})
    group_bindings = defaultdict(list)

    for member, resource, role in get_iam_bindings(
            organization["name"], credentials, resource_names
    ):
        if member.startswith("user:"):
            email = member.removeprefix("user:").lower()
            users[email]["resources"].add(resource)
            users[email]["roles"].add(role)
        elif member.startswith("group:"):
            group = member.removeprefix("group:").lower()
            group_bindings[group].append((resource, role))

    if group_bindings:
        print(f"Expanding {len(group_bindings)} IAM groups...")
        identity = build(
            "cloudidentity", "v1",
            credentials=credentials,
            cache_discovery=False,
        )
        cache = {}

        for index, group in enumerate(sorted(group_bindings), 1):
            print(f"[{index}/{len(group_bindings)}] {group}")

            for email in expand_group(identity, group, cache):
                users[email]["groups"].add(group)
                for resource, role in group_bindings[group]:
                    users[email]["resources"].add(resource)
                    users[email]["roles"].add(role)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["user", "group", "resource", "role"])
        writer.writeheader()

        for email, data in sorted(users.items()):
            writer.writerow({
                "user": email,
                "group": ";".join(sorted(data["groups"])),
                "resource": ";".join(sorted(data["resources"])),
                "role": ";".join(sorted(data["roles"])),
            })

    print("\n========== SUMMARY ==========")
    print(f"Unique human users: {len(users)}")
    print(f"Report written to: ./{OUTPUT_FILE}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
