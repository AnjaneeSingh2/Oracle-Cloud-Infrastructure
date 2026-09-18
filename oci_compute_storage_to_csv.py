#!/usr/bin/env python3
"""
oci_compute_storage_to_csv.py

Fetches Compute instance data and Storage (Block Volume + Boot Volume) data
from an OCI compartment, writes it to a CSV file, and uploads that CSV to
an Object Storage bucket.

Requirements:
    pip install oci

Auth:
    By default this uses your local OCI CLI config file (~/.oci/config).
    If you run this FROM an OCI compute instance and want it to use the
    instance's own identity instead, pass --auth instance_principal.

Usage:
    python3 oci_compute_storage_to_csv.py \
        --compartment-id ocid1.compartment.oc1..xxxx \
        --namespace idsna7fjvtua \
        --bucket-name my-bucket-name \
        [--region us-ashburn-1] \
        [--auth config|instance_principal] \
        [--output-file oci_inventory.csv]

Note: Object Storage uploads (put_object) require the BUCKET NAME
(and namespace), not the bucket OCID. This script accepts --bucket-name;
if you only have the bucket OCID, pass --bucket-ocid and the script will
resolve the bucket name for you via get_bucket (requires bucket OCID
lookup permission... actually the Object Storage API does not support
lookup-by-OCID directly, so it lists buckets in the compartment and
matches by OCID).
"""

import argparse
import csv
import sys
from datetime import datetime, timezone

try:
    import oci
except ImportError:
    print("ERROR: The 'oci' Python SDK is not installed. Run: pip install oci --break-system-packages")
    sys.exit(1)


def get_oci_config_and_signer(auth_mode: str, profile: str, region: str):
    """Return (config, signer) tuple based on chosen auth mode."""
    if auth_mode == "instance_principal":
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        config = {}
        if region:
            config["region"] = region
        return config, signer
    else:
        config = oci.config.from_file(profile_name=profile)
        if region:
            config["region"] = region
        return config, None


def resolve_bucket_name_from_ocid(object_storage_client, namespace, compartment_id, bucket_ocid):
    """
    Object Storage has no direct get-bucket-by-ocid call. list_buckets only
    returns lightweight BucketSummary objects (name, but no OCID), so we
    list bucket names in the compartment, then call get_bucket on each one
    to read its OCID and find the match.
    """
    summaries = oci.pagination.list_call_get_all_results(
        object_storage_client.list_buckets,
        namespace_name=namespace,
        compartment_id=compartment_id,
    ).data

    for summary in summaries:
        bucket = object_storage_client.get_bucket(
            namespace_name=namespace,
            bucket_name=summary.name,
        ).data
        if bucket.id == bucket_ocid:
            return bucket.name
    return None


def fetch_compute_instances(compute_client, compartment_id, compartment_name):
    """Fetch all compute instances in the compartment (across all lifecycle states)."""
    rows = []
    instances = oci.pagination.list_call_get_all_results(
        compute_client.list_instances,
        compartment_id=compartment_id,
    ).data

    for inst in instances:
        rows.append({
            "resource_type": "compute_instance",
            "compartment_id": compartment_id,
            "compartment_name": compartment_name,
            "name": inst.display_name,
            "ocid": inst.id,
            "availability_domain": inst.availability_domain,
            "fault_domain": inst.fault_domain,
            "shape": inst.shape,
            "lifecycle_state": inst.lifecycle_state,
            "region": inst.region,
            "time_created": inst.time_created.isoformat() if inst.time_created else "",
            "ocpus": getattr(inst.shape_config, "ocpus", "") if inst.shape_config else "",
            "memory_in_gbs": getattr(inst.shape_config, "memory_in_gbs", "") if inst.shape_config else "",
            "image_id": inst.image_id or "",
            "size_in_gbs": "",  # not applicable to compute rows
        })
    return rows


def fetch_block_volumes(block_storage_client, compartment_id, compartment_name):
    """Fetch block volumes in the compartment."""
    rows = []
    volumes = oci.pagination.list_call_get_all_results(
        block_storage_client.list_volumes,
        compartment_id=compartment_id,
    ).data

    for vol in volumes:
        rows.append({
            "resource_type": "block_volume",
            "compartment_id": compartment_id,
            "compartment_name": compartment_name,
            "name": vol.display_name,
            "ocid": vol.id,
            "availability_domain": vol.availability_domain,
            "fault_domain": "",
            "shape": vol.vpus_per_gb if hasattr(vol, "vpus_per_gb") else "",
            "lifecycle_state": vol.lifecycle_state,
            "region": "",
            "time_created": vol.time_created.isoformat() if vol.time_created else "",
            "ocpus": "",
            "memory_in_gbs": "",
            "image_id": "",
            "size_in_gbs": vol.size_in_gbs,
        })
    return rows


def fetch_boot_volumes(block_storage_client, compartment_id, compartment_name, availability_domains):
    """Boot volumes must be listed per-availability-domain."""
    rows = []
    for ad in availability_domains:
        boot_vols = oci.pagination.list_call_get_all_results(
            block_storage_client.list_boot_volumes,
            availability_domain=ad,
            compartment_id=compartment_id,
        ).data

        for bv in boot_vols:
            rows.append({
                "resource_type": "boot_volume",
                "compartment_id": compartment_id,
                "compartment_name": compartment_name,
                "name": bv.display_name,
                "ocid": bv.id,
                "availability_domain": bv.availability_domain,
                "fault_domain": "",
                "shape": "",
                "lifecycle_state": bv.lifecycle_state,
                "region": "",
                "time_created": bv.time_created.isoformat() if bv.time_created else "",
                "ocpus": "",
                "memory_in_gbs": "",
                "image_id": "",
                "size_in_gbs": bv.size_in_gbs,
            })
    return rows


def get_availability_domains(identity_client, compartment_id):
    ads = identity_client.list_availability_domains(compartment_id=compartment_id).data
    return [ad.name for ad in ads]


def get_all_compartments(identity_client, tenancy_id, include_root=True):
    """
    Recursively fetch every ACTIVE compartment under the tenancy (all levels
    of nesting), so a 'tenancy-level' scan covers every compartment, not
    just one. Returns a list of (compartment_id, compartment_name) tuples.
    """
    compartments = []

    if include_root:
        compartments.append((tenancy_id, "root (tenancy)"))

    all_compartments = oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        compartment_id=tenancy_id,
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE",
        lifecycle_state="ACTIVE",
    ).data

    for c in all_compartments:
        compartments.append((c.id, c.name))

    return compartments


def write_csv(rows, output_file):
    fieldnames = [
        "resource_type", "compartment_id", "compartment_name", "name", "ocid",
        "availability_domain", "fault_domain",
        "shape", "lifecycle_state", "region", "time_created",
        "ocpus", "memory_in_gbs", "image_id", "size_in_gbs",
    ]
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"CSV written locally: {output_file} ({len(rows)} rows)")


def upload_to_object_storage(object_storage_client, namespace, bucket_name, file_path, object_name):
    with open(file_path, "rb") as f:
        object_storage_client.put_object(
            namespace_name=namespace,
            bucket_name=bucket_name,
            object_name=object_name,
            put_object_body=f,
        )
    print(f"Uploaded '{file_path}' to bucket '{bucket_name}' as object '{object_name}' (namespace: {namespace})")


def main():
    parser = argparse.ArgumentParser(description="Fetch OCI Compute + Storage data to CSV and upload to Object Storage.")
    parser.add_argument("--tenancy-id", default="ocid1.tenancy.oc1..aaaaaaaabu6k373dxjtdouaasv5gsg2ra2eqgftnmy52sf7ozj2wytiwjdyq",
                        help="Tenancy OCID (used mainly for reference/logging).")
    parser.add_argument("--compartment-id", default="ocid1.compartment.oc1..aaaaaaaamcz6yw4hx3ld5tg26amea6gr2lacarkp2jqresgoke6kw5b6ex5q",
                        help="Compartment OCID to fetch resources from. Only used when --scope single.")
    parser.add_argument("--scope", choices=["single", "tenancy"], default="tenancy",
                        help="'tenancy' (default) scans the tenancy root plus every nested ACTIVE compartment. "
                             "'single' scans only --compartment-id.")
    parser.add_argument("--namespace", default="idsna7fjvtua", help="Object Storage namespace.")
    parser.add_argument("--bucket-ocid", default="ocid1.bucket.oc1.iad.aaaaaaaavpbbldkt4go6fy2tnb4vum5v6p3ncdljjru25fmfzjykvqesjijq",
                        help="Bucket OCID (script will resolve the bucket name from this).")
    parser.add_argument("--bucket-name", default="capacity-metrics-prod",
                        help="Bucket name (skips OCID->name resolution if provided).")
    parser.add_argument("--region", default=None, help="OCI region, e.g. us-ashburn-1. Defaults to config/instance region.")
    parser.add_argument("--auth", choices=["config", "instance_principal"], default="config",
                        help="Authentication method. Use 'instance_principal' if running on an OCI VM.")
    parser.add_argument("--profile", default="DEFAULT", help="Profile name in ~/.oci/config (ignored for instance_principal).")
    parser.add_argument("--output-file", default="oci_inventory.csv", help="Local CSV filename.")
    parser.add_argument("--object-name", default=None,
                        help="Object name to use in the bucket. Defaults to a timestamped name.")
    args = parser.parse_args()

    config, signer = get_oci_config_and_signer(args.auth, args.profile, args.region)

    # Build clients
    if args.auth == "instance_principal":
        compute_client = oci.core.ComputeClient(config={}, signer=signer)
        block_storage_client = oci.core.BlockstorageClient(config={}, signer=signer)
        object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        identity_client = oci.identity.IdentityClient(config={}, signer=signer)
    else:
        compute_client = oci.core.ComputeClient(config)
        block_storage_client = oci.core.BlockstorageClient(config)
        object_storage_client = oci.object_storage.ObjectStorageClient(config)
        identity_client = oci.identity.IdentityClient(config)

    print(f"Tenancy: {args.tenancy_id}")
    print(f"Scope: {args.scope}")
    print(f"Namespace: {args.namespace}")

    # Resolve bucket name if not given directly
    bucket_name = args.bucket_name
    if not bucket_name:
        print("Resolving bucket name from bucket OCID...")
        # Bucket lookup happens against the compartment that owns the bucket,
        # which is why we always use --compartment-id here regardless of scope.
        bucket_name = resolve_bucket_name_from_ocid(
            object_storage_client, args.namespace, args.compartment_id, args.bucket_ocid
        )
        if not bucket_name:
            print("ERROR: Could not resolve bucket name from the given bucket OCID in this compartment. "
                  "Pass --bucket-name explicitly instead.")
            sys.exit(1)
    print(f"Target bucket: {bucket_name}")

    # Availability domains are tenancy-wide (per region), fetch once and reuse.
    print("Fetching availability domains (needed for boot volumes)...")
    ads = get_availability_domains(identity_client, args.tenancy_id)

    # Build the list of compartments to scan.
    if args.scope == "tenancy":
        print("Enumerating all compartments in the tenancy (this may take a moment)...")
        compartments = get_all_compartments(identity_client, args.tenancy_id, include_root=True)
    else:
        compartments = [(args.compartment_id, "specified compartment")]

    print(f"Scanning {len(compartments)} compartment(s)...")

    rows = []
    for comp_id, comp_name in compartments:
        print(f"  -> {comp_name} ({comp_id})")
        try:
            rows += fetch_compute_instances(compute_client, comp_id, comp_name)
            rows += fetch_block_volumes(block_storage_client, comp_id, comp_name)
            rows += fetch_boot_volumes(block_storage_client, comp_id, comp_name, ads)
        except oci.exceptions.ServiceError as e:
            # Common cause: no policy grants access to this compartment. Skip and continue.
            print(f"     WARNING: skipped ({e.status} {e.code}): {e.message}")

    # Write CSV
    write_csv(rows, args.output_file)

    # Upload
    object_name = args.object_name or f"oci_inventory_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    upload_to_object_storage(object_storage_client, args.namespace, bucket_name, args.output_file, object_name)


if __name__ == "__main__":
    main()
