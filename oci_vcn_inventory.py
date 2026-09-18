#!/usr/bin/env python3
"""
OCI Networking Inventory Script
--------------------------------
Fetches VCNs and all related networking resources (subnets, route tables,
security lists, NSGs, gateways, DRGs, IPSec connections, FastConnect
virtual circuits, load balancers, public IPs, etc.), writes them to a CSV,
and uploads the CSV to an Object Storage bucket.

Designed to run directly in OCI Cloud Shell (no API key setup needed -
Cloud Shell auto-configures ~/.oci/config for you).

Usage (in Cloud Shell):
    python3 oci_vcn_inventory.py

Optional environment variables to override defaults below:
    COMPARTMENT_OCID   - root compartment to scan (default set below)
    TENANCY_WIDE       - "true"/"false" - scan the WHOLE tenancy (default true).
                         When true, compartment enumeration starts at the
                         tenancy root instead of COMPARTMENT_OCID, so it
                         also catches sibling compartments and resources
                         created directly in the root compartment.
    INCLUDE_SUBTREE    - "true"/"false" - also scan sub-compartments (default true)
    ALL_REGIONS        - "true"/"false" - scan all subscribed regions (default true)
    BUCKET_NAME        - bucket name, if you already know it (skips auto lookup)
"""

import csv
import io
import ipaddress
import json
import os
import sys
from datetime import datetime

import oci

# ---------------------------------------------------------------------------
# CONFIGURATION - filled in from what you provided
# ---------------------------------------------------------------------------
TENANCY_OCID = "ocid1.tenancy.oc1..aaaaaaaabu6k373dxjtdouaasv5gsg2ra2eqgftnmy52sf7ozj2wytiwjdyq"
COMPARTMENT_OCID = os.environ.get(
    "COMPARTMENT_OCID",
    "ocid1.compartment.oc1..aaaaaaaamcz6yw4hx3ld5tg26amea6gr2lacarkp2jqresgoke6kw5b6ex5q",
)
BUCKET_OCID = "ocid1.bucket.oc1.iad.aaaaaaaavpbbldkt4go6fy2tnb4vum5v6p3ncdljjru25fmfzjykvqesjijq"
NAMESPACE = "idsna7fjvtua"
BUCKET_NAME_OVERRIDE = os.environ.get("BUCKET_NAME")  # optional shortcut

INCLUDE_SUBTREE = os.environ.get("INCLUDE_SUBTREE", "true").lower() == "true"
ALL_REGIONS = os.environ.get("ALL_REGIONS", "true").lower() == "true"
TENANCY_WIDE = os.environ.get("TENANCY_WIDE", "true").lower() == "true"

OUTPUT_PREFIX = "network-inventory"  # "folder" prefix inside the bucket

CSV_COLUMNS = [
    "region",
    "resource_type",
    "display_name",
    "ocid",
    "compartment_id",
    "lifecycle_state",
    "time_created",
    "vcn_id",
    "details",
]

OVERLAP_CSV_COLUMNS = [
    "issue_type",
    "resource_type",
    "cidr_a",
    "resource_a_name",
    "resource_a_ocid",
    "region_a",
    "vcn_id_a",
    "cidr_b",
    "resource_b_name",
    "resource_b_ocid",
    "region_b",
    "vcn_id_b",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_config():
    """Load OCI config - Cloud Shell auto-provides this, no setup needed."""
    config = oci.config.from_file()
    return config


def get_all_compartments(identity_client, root_compartment_id, include_subtree):
    """Return list of compartment IDs to scan (root + optional subtree)."""
    compartments = [root_compartment_id]
    if not include_subtree:
        return compartments

    try:
        response = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            root_compartment_id,
            compartment_id_in_subtree=True,
            lifecycle_state="ACTIVE",
        )
        for c in response.data:
            compartments.append(c.id)
    except oci.exceptions.ServiceError as e:
        print(f"  [warn] Could not list sub-compartments: {e.message}")

    return compartments


def get_subscribed_regions(identity_client, tenancy_id):
    try:
        response = identity_client.list_region_subscriptions(tenancy_id)
        return [r.region_name for r in response.data]
    except oci.exceptions.ServiceError as e:
        print(f"  [warn] Could not list region subscriptions: {e.message}")
        return [get_config()["region"]]


def resolve_bucket_name(object_storage_client, namespace, compartment_id, bucket_ocid):
    """Find the bucket display name from its OCID by scanning list_buckets."""
    if BUCKET_NAME_OVERRIDE:
        return BUCKET_NAME_OVERRIDE

    try:
        response = oci.pagination.list_call_get_all_results(
            object_storage_client.list_buckets,
            namespace_name=namespace,
            compartment_id=compartment_id,
        )
        for b in response.data:
            if getattr(b, "id", None) == bucket_ocid:
                return b.name
    except oci.exceptions.ServiceError as e:
        print(f"  [warn] list_buckets failed: {e.message}")

    # Fallback: try Resource Search
    try:
        search_client = oci.resource_search.ResourceSearchClient(get_config())
        details = oci.resource_search.models.StructuredSearchDetails(
            query=f"query bucket resources where identifier = '{bucket_ocid}'"
        )
        result = search_client.search_resources(details)
        if result.data.items:
            return result.data.items[0].display_name
    except oci.exceptions.ServiceError as e:
        print(f"  [warn] Resource Search failed: {e.message}")

    raise RuntimeError(
        "Could not automatically resolve bucket name from OCID. "
        "Set the BUCKET_NAME environment variable and rerun, e.g.:\n"
        "  export BUCKET_NAME=my-bucket-name"
    )


def safe_list(fn, *args, **kwargs):
    """Call an OCI list_* function with pagination, tolerating errors/unsupported services."""
    try:
        return oci.pagination.list_call_get_all_results(fn, *args, **kwargs).data
    except oci.exceptions.ServiceError as e:
        if e.status in (404, 400) or "not authorized" in (e.message or "").lower():
            return []
        print(f"    [warn] {fn.__name__} failed: {e.message}")
        return []
    except Exception as e:  # noqa: BLE001
        print(f"    [warn] {fn.__name__} failed: {e}")
        return []


def row(region, resource_type, obj, vcn_id=None, extra=None):
    details = {}
    if extra:
        details.update(extra)
    return {
        "region": region,
        "resource_type": resource_type,
        "display_name": getattr(obj, "display_name", None),
        "ocid": getattr(obj, "id", None),
        "compartment_id": getattr(obj, "compartment_id", None),
        "lifecycle_state": getattr(obj, "lifecycle_state", None),
        "time_created": str(getattr(obj, "time_created", "")),
        "vcn_id": vcn_id or getattr(obj, "vcn_id", None),
        "details": json.dumps(details, default=str),
    }


# ---------------------------------------------------------------------------
# Resource collection
# ---------------------------------------------------------------------------
def cidr_record(region, resource_type, obj, cidr, vcn_id=None):
    """Small record used only for CIDR-overlap analysis."""
    return {
        "region": region,
        "resource_type": resource_type,
        "display_name": getattr(obj, "display_name", None),
        "ocid": getattr(obj, "id", None),
        "vcn_id": vcn_id,
        "cidr": cidr,
    }


def collect_region_resources(config, region, compartments):
    rows = []
    cidr_records = []
    cfg = dict(config)
    cfg["region"] = region

    vnet = oci.core.VirtualNetworkClient(cfg)
    lb = oci.load_balancer.LoadBalancerClient(cfg)
    try:
        nlb = oci.network_load_balancer.NetworkLoadBalancerClient(cfg)
    except AttributeError:
        nlb = None  # older SDK versions may not have NLB module

    for comp_id in compartments:
        print(f"  Compartment: {comp_id}")

        # VCNs
        vcns = safe_list(vnet.list_vcns, compartment_id=comp_id)
        for v in vcns:
            rows.append(
                row(region, "VCN", v, extra={"cidr_blocks": getattr(v, "cidr_blocks", None)})
            )
            for cidr in getattr(v, "cidr_blocks", None) or []:
                cidr_records.append(cidr_record(region, "VCN", v, cidr, vcn_id=v.id))

        # Subnets
        for s in safe_list(vnet.list_subnets, compartment_id=comp_id):
            rows.append(
                row(region, "Subnet", s, vcn_id=s.vcn_id, extra={"cidr_block": s.cidr_block})
            )
            if s.cidr_block:
                cidr_records.append(cidr_record(region, "Subnet", s, s.cidr_block, vcn_id=s.vcn_id))

        # Route Tables
        for rt in safe_list(vnet.list_route_tables, compartment_id=comp_id):
            rows.append(
                row(
                    region,
                    "RouteTable",
                    rt,
                    vcn_id=rt.vcn_id,
                    extra={"rules": [r.__dict__ for r in (rt.route_rules or [])]},
                )
            )

        # Security Lists
        for sl in safe_list(vnet.list_security_lists, compartment_id=comp_id):
            rows.append(row(region, "SecurityList", sl, vcn_id=sl.vcn_id))

        # Network Security Groups
        for nsg in safe_list(vnet.list_network_security_groups, compartment_id=comp_id):
            rows.append(row(region, "NetworkSecurityGroup", nsg, vcn_id=nsg.vcn_id))

        # Internet Gateways
        for ig in safe_list(vnet.list_internet_gateways, compartment_id=comp_id):
            rows.append(
                row(
                    region,
                    "InternetGateway",
                    ig,
                    vcn_id=ig.vcn_id,
                    extra={"is_enabled": ig.is_enabled},
                )
            )

        # NAT Gateways
        for nat in safe_list(vnet.list_nat_gateways, compartment_id=comp_id):
            rows.append(
                row(
                    region,
                    "NATGateway",
                    nat,
                    vcn_id=nat.vcn_id,
                    extra={"nat_ip": getattr(nat, "nat_ip", None)},
                )
            )

        # Service Gateways
        for sg in safe_list(vnet.list_service_gateways, compartment_id=comp_id):
            rows.append(row(region, "ServiceGateway", sg, vcn_id=sg.vcn_id))

        # Local Peering Gateways
        for lpg in safe_list(vnet.list_local_peering_gateways, compartment_id=comp_id):
            rows.append(
                row(
                    region,
                    "LocalPeeringGateway",
                    lpg,
                    vcn_id=lpg.vcn_id,
                    extra={"peer_advertised_cidr": getattr(lpg, "peer_advertised_cidr", None)},
                )
            )

        # Remote Peering Connections
        for rpc in safe_list(vnet.list_remote_peering_connections, compartment_id=comp_id):
            rows.append(
                row(region, "RemotePeeringConnection", rpc, vcn_id=getattr(rpc, "drg_id", None))
            )

        # DHCP Options
        for dhcp in safe_list(vnet.list_dhcp_options, compartment_id=comp_id):
            rows.append(row(region, "DHCPOptions", dhcp, vcn_id=dhcp.vcn_id))

        # DRGs
        for drg in safe_list(vnet.list_drgs, compartment_id=comp_id):
            rows.append(row(region, "DRG", drg))

        # DRG Attachments
        for da in safe_list(vnet.list_drg_attachments, compartment_id=comp_id):
            rows.append(
                row(
                    region,
                    "DRGAttachment",
                    da,
                    vcn_id=getattr(da, "vcn_id", None),
                    extra={"drg_id": getattr(da, "drg_id", None)},
                )
            )

        # CPEs
        for cpe in safe_list(vnet.list_cpes, compartment_id=comp_id):
            rows.append(
                row(region, "CPE", cpe, extra={"ip_address": getattr(cpe, "ip_address", None)})
            )

        # IPSec Connections
        for ipsec in safe_list(vnet.list_ip_sec_connections, compartment_id=comp_id):
            rows.append(row(region, "IPSecConnection", ipsec))

        # FastConnect Virtual Circuits
        for vc in safe_list(vnet.list_virtual_circuits, compartment_id=comp_id):
            rows.append(
                row(
                    region,
                    "FastConnectVirtualCircuit",
                    vc,
                    extra={"bandwidth_shape_name": getattr(vc, "bandwidth_shape_name", None)},
                )
            )

        # VLANs
        for vlan in safe_list(vnet.list_vlans, compartment_id=comp_id):
            rows.append(
                row(region, "VLAN", vlan, vcn_id=vlan.vcn_id, extra={"cidr_block": vlan.cidr_block})
            )

        # Public IPs (region-scoped)
        for pip in safe_list(vnet.list_public_ips, compartment_id=comp_id, scope="REGION"):
            rows.append(
                row(
                    region,
                    "PublicIP",
                    pip,
                    extra={
                        "ip_address": getattr(pip, "ip_address", None),
                        "lifetime": getattr(pip, "lifetime", None),
                    },
                )
            )

        # BYOIP Ranges
        for byoip in safe_list(vnet.list_byoip_ranges, compartment_id=comp_id):
            rows.append(
                row(
                    region,
                    "ByoipRange",
                    byoip,
                    extra={"cidr_block": getattr(byoip, "cidr_block", None)},
                )
            )

        # Load Balancers
        for lbi in safe_list(lb.list_load_balancers, compartment_id=comp_id):
            rows.append(
                row(
                    region,
                    "LoadBalancer",
                    lbi,
                    extra={"ip_addresses": [ip.ip_address for ip in (lbi.ip_addresses or [])]},
                )
            )

        # Network Load Balancers
        if nlb:
            for nlbi in safe_list(nlb.list_network_load_balancers, compartment_id=comp_id):
                rows.append(row(region, "NetworkLoadBalancer", nlbi))

    return rows, cidr_records


def analyze_cidr_overlaps(cidr_records):
    """
    Compare CIDR blocks pairwise, within each resource_type group
    (VCN-vs-VCN, Subnet-vs-Subnet), and flag exact duplicates or overlaps
    between DIFFERENT parent VCNs. Subnets within the same VCN are skipped
    since OCI itself prevents overlap there.
    """
    issues = []
    by_type = {}
    for rec in cidr_records:
        by_type.setdefault(rec["resource_type"], []).append(rec)

    for resource_type, records in by_type.items():
        for i in range(len(records)):
            for j in range(i + 1, len(records)):
                a, b = records[i], records[j]

                # Skip comparing a resource to itself, and skip subnets
                # that belong to the same VCN (not a real conflict).
                if a["ocid"] == b["ocid"]:
                    continue
                if resource_type == "Subnet" and a["vcn_id"] == b["vcn_id"]:
                    continue
                if resource_type == "VCN" and a["ocid"] == b["ocid"]:
                    continue

                try:
                    net_a = ipaddress.ip_network(a["cidr"], strict=False)
                    net_b = ipaddress.ip_network(b["cidr"], strict=False)
                except ValueError:
                    continue

                if net_a.overlaps(net_b):
                    issue_type = "EXACT_DUPLICATE" if a["cidr"] == b["cidr"] else "OVERLAP"
                    issues.append(
                        {
                            "issue_type": issue_type,
                            "resource_type": resource_type,
                            "cidr_a": a["cidr"],
                            "resource_a_name": a["display_name"],
                            "resource_a_ocid": a["ocid"],
                            "region_a": a["region"],
                            "vcn_id_a": a["vcn_id"],
                            "cidr_b": b["cidr"],
                            "resource_b_name": b["display_name"],
                            "resource_b_ocid": b["ocid"],
                            "region_b": b["region"],
                            "vcn_id_b": b["vcn_id"],
                        }
                    )

    return issues


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("Loading OCI config (Cloud Shell auto-auth)...")
    config = get_config()

    identity_client = oci.identity.IdentityClient(config)
    object_storage_client = oci.object_storage.ObjectStorageClient(config)

    scan_root = TENANCY_OCID if TENANCY_WIDE else COMPARTMENT_OCID
    print(
        f"Resolving compartments under {scan_root} "
        f"(tenancy_wide={TENANCY_WIDE}, include_subtree={INCLUDE_SUBTREE})..."
    )
    compartments = get_all_compartments(identity_client, scan_root, INCLUDE_SUBTREE)
    print(f"  {len(compartments)} compartment(s) to scan.")

    if ALL_REGIONS:
        regions = get_subscribed_regions(identity_client, TENANCY_OCID)
    else:
        regions = [config["region"]]
    print(f"Regions to scan: {regions}")

    all_rows = []
    all_cidr_records = []
    for region in regions:
        print(f"\nScanning region: {region}")
        rows, cidr_records = collect_region_resources(config, region, compartments)
        all_rows.extend(rows)
        all_cidr_records.extend(cidr_records)

    print(f"\nTotal resources collected: {len(all_rows)}")

    print("\nAnalyzing CIDR blocks for duplicates/overlaps...")
    overlap_issues = analyze_cidr_overlaps(all_cidr_records)
    if overlap_issues:
        exact = sum(1 for i in overlap_issues if i["issue_type"] == "EXACT_DUPLICATE")
        partial = len(overlap_issues) - exact
        print(
            f"  Found {len(overlap_issues)} issue(s): {exact} exact duplicate(s), {partial} partial overlap(s)."
        )
    else:
        print("  No duplicate or overlapping CIDR blocks found.")

    # Write CSV to memory + local file
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    local_filename = f"oci_network_inventory_{timestamp}.csv"

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    writer.writerows(all_rows)
    csv_bytes = buffer.getvalue().encode("utf-8")

    with open(local_filename, "wb") as f:
        f.write(csv_bytes)
    print(f"CSV written locally: {os.path.abspath(local_filename)}")

    # Write overlap-issues CSV (may be empty except header)
    overlap_filename = f"oci_network_cidr_overlaps_{timestamp}.csv"
    overlap_buffer = io.StringIO()
    overlap_writer = csv.DictWriter(overlap_buffer, fieldnames=OVERLAP_CSV_COLUMNS)
    overlap_writer.writeheader()
    overlap_writer.writerows(overlap_issues)
    overlap_csv_bytes = overlap_buffer.getvalue().encode("utf-8")

    with open(overlap_filename, "wb") as f:
        f.write(overlap_csv_bytes)
    print(f"CIDR overlap report written locally: {os.path.abspath(overlap_filename)}")

    # Resolve bucket name and upload
    print("\nResolving bucket name from OCID...")
    bucket_name = resolve_bucket_name(
        object_storage_client, NAMESPACE, COMPARTMENT_OCID, BUCKET_OCID
    )
    print(f"  Bucket name: {bucket_name}")

    object_name = f"{OUTPUT_PREFIX}/{local_filename}"
    print(f"Uploading to oci://{bucket_name}/{object_name} ...")
    object_storage_client.put_object(
        namespace_name=NAMESPACE,
        bucket_name=bucket_name,
        object_name=object_name,
        put_object_body=csv_bytes,
        content_type="text/csv",
    )

    overlap_object_name = f"{OUTPUT_PREFIX}/{overlap_filename}"
    print(f"Uploading to oci://{bucket_name}/{overlap_object_name} ...")
    object_storage_client.put_object(
        namespace_name=NAMESPACE,
        bucket_name=bucket_name,
        object_name=overlap_object_name,
        put_object_body=overlap_csv_bytes,
        content_type="text/csv",
    )

    print("Upload complete.")
    print(f"\nDone. {len(all_rows)} resource rows -> '{object_name}'.")
    print(f"      {len(overlap_issues)} CIDR overlap issue(s) -> '{overlap_object_name}'.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"\nERROR: {exc}", file=sys.stderr)
        sys.exit(1)
