#!/usr/bin/env python3
"""
oci_iam_extract.py
===================

Extracts IAM-family resources from an OCI tenancy:
    - Users
    - Groups
    - Dynamic Groups
    - Policies (per compartment, since policies are compartment-scoped)

Writes everything to CSV files locally, then uploads the combined CSV
to an Object Storage bucket.

Prerequisites
-------------
    pip install oci

Authentication
---------------
Uses the standard OCI config file (~/.oci/config, profile "DEFAULT") by
default. If running on an OCI compute instance, you can switch to
Instance Principal auth by setting USE_INSTANCE_PRINCIPAL = True below.

Usage
-----
    python3 oci_iam_extract.py

Output
------
    ./oci_iam_export/users.csv
    ./oci_iam_export/groups.csv
    ./oci_iam_export/dynamic_groups.csv
    ./oci_iam_export/policies.csv
    ./oci_iam_export/all_iam_resources.csv   (combined, uploaded to Object Storage)
"""

import csv
import os
import sys
from datetime import datetime

import oci

# --------------------------------------------------------------------------
# CONFIGURATION - EDIT IF NEEDED
# --------------------------------------------------------------------------

TENANCY_OCID = "ocid1.tenancy.oc1..aaaaaaaabu6k373dxjtdouaasv5gsg2ra2eqgftnmy52sf7ozj2wytiwjdyq"

# Root compartment to start walking from (root compartment == tenancy for a
# full-tenancy sweep; you can instead point this at a specific sub-tree)
ROOT_COMPARTMENT_OCID = "ocid1.compartment.oc1..aaaaaaaamcz6yw4hx3ld5tg26amea6gr2lacarkp2jqresgoke6kw5b6ex5q"

# Destination bucket details
OBJECT_STORAGE_NAMESPACE = "idsna7fjvtua"
BUCKET_OCID = "ocid1.bucket.oc1.iad.aaaaaaaavpbbldkt4go6fy2tnb4vum5v6p3ncdljjru25fmfzjykvqesjijq"

# If you already know the bucket name, set it here to skip the resource
# search lookup (faster & avoids needing search service permissions).
KNOWN_BUCKET_NAME = None   # e.g. "my-iam-export-bucket"

# Set True to run from an OCI compute instance using Instance Principal auth
USE_INSTANCE_PRINCIPAL = False

# Local output directory
OUTPUT_DIR = "./oci_iam_export"

# --------------------------------------------------------------------------


def get_signer_and_config():
    """Returns (config, signer) tuple based on chosen auth method."""
    if USE_INSTANCE_PRINCIPAL:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        config = {}
        return config, signer
    else:
        config = oci.config.from_file()  # ~/.oci/config, DEFAULT profile
        return config, None


def make_client(client_cls, config, signer):
    if signer:
        return client_cls(config={}, signer=signer)
    return client_cls(config)


def list_all_compartments(identity_client, tenancy_id, root_compartment_id):
    """
    Lists the target compartment (root_compartment_id) plus every ACTIVE
    compartment nested beneath it, anywhere in the tenancy.

    NOTE: the OCI API only allows compartment_id_in_subtree=True when the
    compartment_id passed in IS the tenancy OCID -- you cannot ask for the
    subtree of an arbitrary sub-compartment directly. So we always fetch
    the full tenancy-wide compartment list first, then locally filter down
    to root_compartment_id and its descendants using each compartment's
    parent (compartment_id) field.
    """
    # 1. Fetch every ACTIVE compartment in the whole tenancy (flat list).
    response = oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        tenancy_id,
        compartment_id_in_subtree=True,
        access_level="ANY",
        lifecycle_state="ACTIVE",
    )

    all_comps = [{
        "id": c.id,
        "parent_id": c.compartment_id,
        "name": c.name,
        "lifecycle_state": c.lifecycle_state,
    } for c in response.data]

    # If the target root IS the tenancy itself, everything qualifies.
    if root_compartment_id == tenancy_id:
        result = [{"id": tenancy_id, "name": "root (tenancy)", "lifecycle_state": "ACTIVE"}]
        result.extend({"id": c["id"], "name": c["name"], "lifecycle_state": c["lifecycle_state"]}
                       for c in all_comps)
        return result

    # 2. Otherwise, build a parent -> children map and BFS from the target
    #    compartment to collect it plus all of its descendants.
    children_by_parent = {}
    by_id = {}
    for c in all_comps:
        by_id[c["id"]] = c
        children_by_parent.setdefault(c["parent_id"], []).append(c)

    # Look up the target compartment's own name (it may not appear in the
    # subtree list if it has no parent chain issues; fetch it directly to
    # be safe).
    try:
        root_comp = identity_client.get_compartment(root_compartment_id).data
        root_name = root_comp.name
    except oci.exceptions.ServiceError:
        root_name = by_id.get(root_compartment_id, {}).get("name", "target-compartment")

    result = [{"id": root_compartment_id, "name": root_name, "lifecycle_state": "ACTIVE"}]

    queue = [root_compartment_id]
    seen = {root_compartment_id}
    while queue:
        current = queue.pop(0)
        for child in children_by_parent.get(current, []):
            if child["id"] not in seen:
                seen.add(child["id"])
                result.append({
                    "id": child["id"],
                    "name": child["name"],
                    "lifecycle_state": child["lifecycle_state"],
                })
                queue.append(child["id"])

    return result


def fetch_users(identity_client, tenancy_id):
    print("Fetching users (tenancy-wide resource)...")
    users = oci.pagination.list_call_get_all_results(
        identity_client.list_users, tenancy_id
    ).data

    rows = []
    for u in users:
        rows.append({
            "resource_type": "User",
            "compartment_id": tenancy_id,
            "compartment_name": "root (tenancy)",
            "id": u.id,
            "name": u.name,
            "description": u.description or "",
            "lifecycle_state": u.lifecycle_state,
            "time_created": u.time_created,
            "email": getattr(u, "email", "") or "",
            "extra": ""
        })
    return rows


def fetch_groups(identity_client, tenancy_id):
    print("Fetching groups (tenancy-wide resource)...")
    groups = oci.pagination.list_call_get_all_results(
        identity_client.list_groups, tenancy_id
    ).data

    rows = []
    for g in groups:
        rows.append({
            "resource_type": "Group",
            "compartment_id": tenancy_id,
            "compartment_name": "root (tenancy)",
            "id": g.id,
            "name": g.name,
            "description": g.description or "",
            "lifecycle_state": g.lifecycle_state,
            "time_created": g.time_created,
            "email": "",
            "extra": ""
        })
    return rows


def fetch_dynamic_groups(identity_client, tenancy_id):
    print("Fetching dynamic groups (tenancy-wide resource)...")
    dgroups = oci.pagination.list_call_get_all_results(
        identity_client.list_dynamic_groups, tenancy_id
    ).data

    rows = []
    for dg in dgroups:
        rows.append({
            "resource_type": "DynamicGroup",
            "compartment_id": tenancy_id,
            "compartment_name": "root (tenancy)",
            "id": dg.id,
            "name": dg.name,
            "description": dg.description or "",
            "lifecycle_state": dg.lifecycle_state,
            "time_created": dg.time_created,
            "email": "",
            "extra": (dg.matching_rule or "").replace("\n", " ")
        })
    return rows


def fetch_policies(identity_client, compartments):
    print("Fetching policies for every compartment (this may take a while)...")
    rows = []
    for comp in compartments:
        try:
            policies = oci.pagination.list_call_get_all_results(
                identity_client.list_policies, comp["id"]
            ).data
        except oci.exceptions.ServiceError as e:
            print(f"  ! Skipping compartment {comp['name']} ({comp['id']}): {e.message}")
            continue

        for p in policies:
            statements = " | ".join(p.statements) if p.statements else ""
            rows.append({
                "resource_type": "Policy",
                "compartment_id": comp["id"],
                "compartment_name": comp["name"],
                "id": p.id,
                "name": p.name,
                "description": p.description or "",
                "lifecycle_state": p.lifecycle_state,
                "time_created": p.time_created,
                "email": "",
                "extra": statements.replace("\n", " ")
            })
    return rows


def write_csv(path, rows, fieldnames):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"  -> wrote {len(rows)} rows to {path}")


def resolve_bucket_name(config, signer, bucket_ocid):
    """
    Resolve a bucket's display name from its OCID using the Resource
    Search service (needed because Object Storage's data-plane APIs
    address buckets by name, not OCID).
    """
    if KNOWN_BUCKET_NAME:
        return KNOWN_BUCKET_NAME

    print("Resolving bucket name from bucket OCID via Resource Search...")
    search_client = make_client(oci.resource_search.ResourceSearchClient, config, signer)
    query = oci.resource_search.models.StructuredSearchDetails(
        query=f"query bucket resources where identifier = '{bucket_ocid}'",
        type="Structured",
    )
    result = search_client.search_resources(query).data
    if not result.items:
        raise RuntimeError(
            f"Could not resolve bucket name for OCID {bucket_ocid}. "
            f"Set KNOWN_BUCKET_NAME manually in the script instead."
        )
    bucket_name = result.items[0].display_name
    print(f"  -> resolved bucket name: {bucket_name}")
    return bucket_name


def upload_to_object_storage(config, signer, namespace, bucket_name, file_path, object_name):
    print(f"Uploading {file_path} to bucket '{bucket_name}' as '{object_name}'...")
    object_storage_client = make_client(oci.object_storage.ObjectStorageClient, config, signer)
    with open(file_path, "rb") as f:
        object_storage_client.put_object(
            namespace_name=namespace,
            bucket_name=bucket_name,
            object_name=object_name,
            put_object_body=f,
        )
    print("  -> upload complete.")


def main():
    config, signer = get_signer_and_config()

    identity_client = make_client(oci.identity.IdentityClient, config, signer)

    # 1. Enumerate compartments (needed for policies, which are compartment-scoped)
    print("Listing all compartments under the tenancy...")
    compartments = list_all_compartments(identity_client, TENANCY_OCID, ROOT_COMPARTMENT_OCID)
    print(f"  -> found {len(compartments)} compartments (including root).")

    # 2. Fetch each IAM resource type
    users_rows = fetch_users(identity_client, TENANCY_OCID)
    groups_rows = fetch_groups(identity_client, TENANCY_OCID)
    dgroups_rows = fetch_dynamic_groups(identity_client, TENANCY_OCID)
    policies_rows = fetch_policies(identity_client, compartments)

    fieldnames = [
        "resource_type", "compartment_id", "compartment_name", "id", "name",
        "description", "lifecycle_state", "time_created", "email", "extra"
    ]

    # 3. Write individual CSVs
    write_csv(os.path.join(OUTPUT_DIR, "users.csv"), users_rows, fieldnames)
    write_csv(os.path.join(OUTPUT_DIR, "groups.csv"), groups_rows, fieldnames)
    write_csv(os.path.join(OUTPUT_DIR, "dynamic_groups.csv"), dgroups_rows, fieldnames)
    write_csv(os.path.join(OUTPUT_DIR, "policies.csv"), policies_rows, fieldnames)

    # 4. Write combined CSV
    all_rows = users_rows + groups_rows + dgroups_rows + policies_rows
    combined_path = os.path.join(OUTPUT_DIR, "all_iam_resources.csv")
    write_csv(combined_path, all_rows, fieldnames)

    # 5. Upload combined CSV to Object Storage
    bucket_name = resolve_bucket_name(config, signer, BUCKET_OCID)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    object_name = f"iam_export/all_iam_resources_{timestamp}.csv"
    upload_to_object_storage(
        config, signer, OBJECT_STORAGE_NAMESPACE, bucket_name, combined_path, object_name
    )

    print("\nDone.")
    print(f"Summary: {len(users_rows)} users, {len(groups_rows)} groups, "
          f"{len(dgroups_rows)} dynamic groups, {len(policies_rows)} policies "
          f"across {len(compartments)} compartments.")


if __name__ == "__main__":
    try:
        main()
    except oci.exceptions.ServiceError as e:
        print(f"OCI Service Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
