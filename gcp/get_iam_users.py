#!/usr/bin/env python3
"""
GCP Human IAM User Inventory
============================

Purpose:
    Create ./effective_user_access.csv containing one row per unique human user
    with IAM access granted at Organization, Folder, or Project level.

How it works:
    - Finds the single visible GCP organization automatically.
    - Searches Organization/Folder/Project IAM policies with Cloud Asset.
    - Adds direct `user:` principals.
    - Expands IAM-bound Google Groups with Cloud Asset Policy Analyzer,
      including nested groups.
    - Deduplicates users and aggregates their groups, resources, and roles.

CSV columns:
    user, group, resource, role

Notes:
    - Lower-level resource IAM (buckets, datasets, secrets, etc.) is excluded.
    - Service accounts and deleted principals are excluded.

Required APIs:
    cloudasset.googleapis.com
    cloudresourcemanager.googleapis.com

Required packages:
    pip install google-cloud-asset google-cloud-resource-manager

Authentication:
    Uses Application Default Credentials automatically (works in Cloud Shell).

Permissions:
    GCP: roles/cloudasset.viewer on the organization, plus organization view.
    Custom roles additionally require iam.roles.get.
    Google Workspace: groups.read is required for group expansion.
"""

import csv
import sys
from collections import defaultdict

from google.cloud import asset_v1, resourcemanager_v3


OUTPUT_FILE = "effective_user_access.csv"
MAX_ROLES_PER_QUERY = 10

ASSET_TYPES = [
    "cloudresourcemanager.googleapis.com/Organization",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Project",
]

RESOURCE_PREFIXES = {
    "//cloudresourcemanager.googleapis.com/organizations/": "organization",
    "//cloudresourcemanager.googleapis.com/folders/": "folder",
    "//cloudresourcemanager.googleapis.com/projects/": "project",
}


def get_organization():
    orgs = list(resourcemanager_v3.OrganizationsClient().search_organizations())
    if len(orgs) != 1:
        raise RuntimeError(
            f"Expected exactly one visible GCP organization, found {len(orgs)}."
        )
    return orgs[0]


def resource_type(full_name):
    for prefix, kind in RESOURCE_PREFIXES.items():
        if full_name.startswith(prefix):
            return kind
    return None


def resource_label(full_name, resource_names):
    if full_name in resource_names:
        return resource_names[full_name]

    kind = resource_type(full_name)
    resource_id = full_name.rsplit("/", 1)[-1]
    return f"{kind}:{resource_id}" if kind else full_name


def get_resource_names(client, organization):
    request = asset_v1.SearchAllResourcesRequest(
        scope=organization.name,
        asset_types=ASSET_TYPES,
    )

    names = {}
    for resource in client.search_all_resources(request=request):
        kind = resource_type(resource.name)
        if not kind:
            continue

        resource_id = resource.name.rsplit("/", 1)[-1]
        names[resource.name] = (
            f"{kind}:{resource.display_name} ({resource_id})"
            if resource.display_name
            else f"{kind}:{resource_id}"
        )

    org_id = organization.name.rsplit("/", 1)[-1]
    org_full_name = f"//cloudresourcemanager.googleapis.com/{organization.name}"
    names.setdefault(
        org_full_name,
        (
            f"organization:{organization.display_name} ({org_id})"
            if organization.display_name
            else f"organization:{org_id}"
        ),
    )
    return names


def new_inventory():
    return defaultdict(lambda: {"groups": set(), "resources": set(), "roles": set()})


def role_label(binding):
    if binding.condition and binding.condition.expression:
        return f"{binding.role} [conditional]"
    return binding.role


def scan_iam(client, organization_name, resource_names):
    """Collect direct users and roles that require Google Group expansion."""
    request = asset_v1.SearchAllIamPoliciesRequest(
        scope=organization_name,
        asset_types=ASSET_TYPES,
    )

    users = new_inventory()
    group_roles = set()
    unsupported_principals = set()

    for result in client.search_all_iam_policies(request=request):
        resource = resource_label(result.resource, resource_names)

        for binding in result.policy.bindings:
            label = role_label(binding)

            for member in binding.members:
                principal = member.lower()

                if principal.startswith("user:"):
                    email = principal.removeprefix("user:")
                    users[email]["resources"].add(resource)
                    users[email]["roles"].add(label)

                elif principal.startswith("group:"):
                    group_roles.add(binding.role)

                elif (
                        principal.startswith("serviceaccount:")
                        or principal.startswith("deleted:")
                ):
                    continue

                else:
                    # domain:, allAuthenticatedUsers, workforce principalSet,
                    # legacy projectOwner/projectEditor principals, etc. cannot
                    # be safely converted into a finite human-user list here.
                    unsupported_principals.add(member)

    if unsupported_principals:
        examples = ", ".join(sorted(unsupported_principals)[:5])
        raise RuntimeError(
            "Cannot guarantee a complete human-user inventory because IAM "
            f"contains unsupported broad principals: {examples}"
        )

    return users, sorted(group_roles)


def batched(values, size):
    for index in range(0, len(values), size):
        yield values[index : index + size]


def analyze_group_roles(client, organization_name, roles):
    """Run Policy Analyzer in batches of at most 10 roles."""
    batches = list(batched(roles, MAX_ROLES_PER_QUERY))

    for number, role_batch in enumerate(batches, start=1):
        if len(batches) > 1:
            print(f"  Policy Analyzer batch {number}/{len(batches)}")

        query = asset_v1.IamPolicyAnalysisQuery(
            scope=organization_name,
            access_selector=asset_v1.IamPolicyAnalysisQuery.AccessSelector(
                roles=role_batch
            ),
            options=asset_v1.IamPolicyAnalysisQuery.Options(
                expand_groups=True,
                output_group_edges=True,
            ),
        )

        response = client.analyze_iam_policy(
            request=asset_v1.AnalyzeIamPolicyRequest(analysis_query=query)
        )
        analysis = response.main_analysis

        if (
                not response.fully_explored
                or not analysis.fully_explored
                or any(not result.fully_explored for result in analysis.analysis_results)
        ):
            causes = "; ".join(
                sorted({e.cause for e in analysis.non_critical_errors if e.cause})
            )
            raise RuntimeError(
                "Policy Analyzer returned an incomplete result"
                + (f": {causes}" if causes else ".")
            )

        yield from analysis.analysis_results


def expanded_users(group, edges):
    """Walk Policy Analyzer group edges and return reachable user principals."""
    found = set()
    seen = set()
    stack = list(edges.get(group, ()))

    while stack:
        principal = stack.pop()
        if principal in seen:
            continue
        seen.add(principal)

        if principal.startswith("user:"):
            found.add(principal)
        elif principal.startswith("group:"):
            stack.extend(edges.get(principal, ()))

    return found


def add_group_users(users, analysis_results, resource_names):
    for result in analysis_results:
        full_resource = result.attached_resource_full_name
        if not resource_type(full_resource):
            continue

        groups = [
            member.lower()
            for member in result.iam_binding.members
            if member.lower().startswith("group:")
        ]
        if not groups:
            continue

        edges = defaultdict(set)
        for edge in result.identity_list.group_edges:
            edges[edge.source_node.lower()].add(edge.target_node.lower())

        resource = resource_label(full_resource, resource_names)
        role = role_label(result.iam_binding)

        for group in groups:
            for principal in expanded_users(group, edges):
                email = principal.removeprefix("user:")
                users[email]["groups"].add(group.removeprefix("group:"))
                users[email]["resources"].add(resource)
                users[email]["roles"].add(role)


def write_csv(users):
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["user", "group", "resource", "role"])
        writer.writeheader()

        for email, data in sorted(users.items()):
            writer.writerow(
                {
                    "user": email,
                    "group": ";".join(sorted(data["groups"])),
                    "resource": ";".join(sorted(data["resources"])),
                    "role": ";".join(sorted(data["roles"])),
                }
            )


def main():
    organization = get_organization()
    client = asset_v1.AssetServiceClient()

    print(f"Organization: {organization.display_name or 'unknown'} ({organization.name})")
    print("Resolving Organization, Folder and Project display names...")
    resource_names = get_resource_names(client, organization)

    print("Scanning Organization, Folder and Project IAM...")
    users, group_roles = scan_iam(client, organization.name, resource_names)

    if group_roles:
        query_count = (len(group_roles) + MAX_ROLES_PER_QUERY - 1) // MAX_ROLES_PER_QUERY
        print(
            f"Expanding Google Groups ({len(group_roles)} group-bound IAM roles, "
            f"{query_count} Policy Analyzer quer{'y' if query_count == 1 else 'ies'})..."
        )
        add_group_users(
            users,
            analyze_group_roles(client, organization.name, group_roles),
            resource_names,
        )

    write_csv(users)

    print(f"Report written to: ./{OUTPUT_FILE}")
    print("\n========== SUMMARY ==========")
    print(f"Unique human users: {len(users)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
