#!/usr/bin/env python3
"""
GCP Human IAM User Inventory

Creates effective_user_access.csv with one row per unique human user that has
an IAM allow-policy binding at Organization, Folder, or Project level.

Google Groups are expanded by Cloud Asset Policy Analyzer, including nested
groups.

CSV columns:
    user, group, resource, role

Multiple groups/resources/roles are semicolon-separated and independently
aggregated. Resource-level IAM below Project and non-human principals are
excluded. Conditional bindings are marked "[conditional]" in the role column.

Required APIs:
    cloudasset.googleapis.com
    cloudresourcemanager.googleapis.com

Required Python packages:
    pip install google-cloud-asset google-cloud-resource-manager

Group expansion requires the Google Workspace `groups.read` privilege and is
capped by Google at 1,000 members per group.
"""

import csv
import sys
from collections import defaultdict

from google.cloud import asset_v1, resourcemanager_v3


OUTPUT_FILE = "effective_user_access.csv"
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
    organizations = list(
        resourcemanager_v3.OrganizationsClient().search_organizations()
    )
    if len(organizations) != 1:
        raise RuntimeError(
            f"Expected exactly one visible GCP organization, found {len(organizations)}."
        )
    return organizations[0]


def resource_type(name):
    return next(
        (kind for prefix, kind in RESOURCE_PREFIXES.items() if name.startswith(prefix)),
        None,
    )


def get_resource_names(client, organization):
    names = {}
    request = asset_v1.SearchAllResourcesRequest(
        scope=organization.name,
        asset_types=ASSET_TYPES,
    )

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
        f"organization:{organization.display_name or org_id} ({org_id})",
    )
    return names


def get_relevant_roles(client, organization_name):
    """Return roles used on Organization, Folder, or Project IAM bindings."""
    request = asset_v1.SearchAllIamPoliciesRequest(
        scope=organization_name,
        asset_types=ASSET_TYPES,
    )

    roles = set()
    for policy in client.search_all_iam_policies(request=request):
        for binding in policy.policy.bindings:
            if binding.role:
                roles.add(binding.role)

    return sorted(roles)


def analyze_iam(client, organization_name, roles):
    """Analyze all relevant IAM roles and expand Google Group membership."""
    query = asset_v1.IamPolicyAnalysisQuery(
        scope=organization_name,
        access_selector=asset_v1.IamPolicyAnalysisQuery.AccessSelector(
            roles=roles,
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

    incomplete = (
            not response.fully_explored
            or not analysis.fully_explored
            or any(not result.fully_explored for result in analysis.analysis_results)
    )
    if incomplete:
        causes = "; ".join(
            error.cause for error in analysis.non_critical_errors if error.cause
        )
        raise RuntimeError(
            "Policy Analyzer returned an incomplete result."
            + (f" Details: {causes}" if causes else "")
        )

    return analysis.analysis_results


def expanded_users(group, edges):
    users = set()
    seen = set()
    stack = list(edges.get(group, ()))

    while stack:
        principal = stack.pop()
        if principal in seen:
            continue
        seen.add(principal)

        if principal.startswith("user:"):
            users.add(principal)
        elif principal.startswith("group:"):
            stack.extend(edges.get(principal, ()))

    return users


def build_inventory(results, resource_names):
    users = defaultdict(
        lambda: {"groups": set(), "resources": set(), "roles": set()}
    )

    for result in results:
        full_resource = result.attached_resource_full_name
        kind = resource_type(full_resource)
        if not kind:
            continue

        resource = resource_names.get(
            full_resource,
            f"{kind}:{full_resource.rsplit('/', 1)[-1]}",
        )
        binding = result.iam_binding
        role = binding.role
        if binding.condition and binding.condition.expression:
            role += " [conditional]"

        for member in binding.members:
            if member.startswith("user:"):
                email = member.removeprefix("user:").lower()
                users[email]["resources"].add(resource)
                users[email]["roles"].add(role)

        edges = defaultdict(set)
        for edge in result.identity_list.group_edges:
            edges[edge.source_node.lower()].add(edge.target_node.lower())

        for member in binding.members:
            if not member.startswith("group:"):
                continue

            group = member.lower()
            group_email = group.removeprefix("group:")

            for principal in expanded_users(group, edges):
                email = principal.removeprefix("user:")
                users[email]["groups"].add(group_email)
                users[email]["resources"].add(resource)
                users[email]["roles"].add(role)

    return users


def write_csv(users):
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file, fieldnames=["user", "group", "resource", "role"]
        )
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
    asset_client = asset_v1.AssetServiceClient()

    print(
        f"Organization: {organization.display_name or 'unknown'} "
        f"({organization.name})"
    )
    print("Resolving Organization, Folder and Project display names...")
    resource_names = get_resource_names(asset_client, organization)

    print("Discovering IAM roles used at Organization, Folder and Project level...")
    roles = get_relevant_roles(asset_client, organization.name)

    if roles:
        print("Analyzing IAM and expanding Google Groups...")
        users = build_inventory(
            analyze_iam(asset_client, organization.name, roles),
            resource_names,
        )
    else:
        users = {}
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
