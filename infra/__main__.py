#
# Key change: Everything needed ONLY for the OpenSearch Ingestion (OSI) pipeline
# and its private egress (VPC interface endpoints) is fully isolated behind a
# single config switch: `ingestionEnabled` (bool). Toggle it on/off to create or
# destroy the ingestion stack without touching the rest of your infra.
#
# Usage:
#   pulumi config set ingestionEnabled true    # scale domain up + create OSI
#   pulumi up
#   pulumi config set ingestionEnabled false   # revert domain + destroy OSI
#   pulumi up
#
# Notes:
# - The S3 source is configured for a ONE-TIME scheduled scan (no interval),
#   per AWS docs; it runs once on create, then idles. Tear it down after. (See:
#   "one-time scheduled scan" in AWS OSI S3 source docs.)
# - A dedicated CloudWatch Log Group is created and wired into OSI log publishing.

import json
import textwrap
import pulumi
import pulumi_aws as aws
import pulumi_aws_native as aws_native

# ------------------------
# Config & helpers
# ------------------------
cfg = pulumi.Config()
stack = pulumi.get_stack()
project = pulumi.get_project()

vpc_cidr = cfg.get("vpcCidr") or "10.0.0.0/16"
app_port = int(cfg.get("appPort") or 8000)
reranker_port = int(cfg.get("rerankerPort") or 9000)
domain_name = cfg.get("opensearchDomainName") or "bio-rag-os"
allowed_ssh_cidr = cfg.get("allowedSshCidr")  # None means no SSH ingress
key_name = cfg.get("keyName") or "viewer-frontend-key"  # must exist in region

# NEW: one switch to rule them all
ingestion_enabled = bool(cfg.get_bool("ingestionEnabled") or False)

# Baseline vs ingest-time domain sizing (overridable via Pulumi config)
os_base_instance_type = cfg.get("osBaseInstanceType") or "t3.small.search"
os_base_volume_gib = int(cfg.get("osBaseVolumeGiB") or 30)
os_ingest_instance_type = (
    cfg.get("osIngestInstanceType") or "t3.small.search"
)  # could be r7g.large.search for bigger ingests
os_ingest_volume_gib = int(cfg.get("osIngestVolumeGiB") or 30)
os_instance_count = int(cfg.get("osInstanceCount") or 1)

# Effective sizing based on the switch
os_eff_instance_type = (
    os_ingest_instance_type if ingestion_enabled else os_base_instance_type
)
os_eff_volume_gib = os_ingest_volume_gib if ingestion_enabled else os_base_volume_gib

# Ingest-time pipeline tuning (applies only when OSI exists)
# These are safe, higher-throughput defaults you can override via config.
sink_bulk = int(cfg.get("sinkBulk") or 1)  # bulk request size (docs)
sink_flush_ms = int(cfg.get("sinkFlushMs") or 2000)  # flush timeout (ms)
source_records = int(cfg.get("sourceRecords") or 200)  # S3 batching
source_backoff = cfg.get("sourceBackoff") or "1s"  # S3 backoff
osi_min_ocus = int(cfg.get("osiMinOcus") or 2)
osi_max_ocus = int(cfg.get("osiMaxOcus") or 2)

region = aws.get_region()
identity = aws.get_caller_identity()
azs = aws.get_availability_zones(state="available").names[:1]

# ------------------------
# VPC + Subnets + Routing (Single AZ)
# ------------------------
vpc = aws.ec2.Vpc(
    "vpc",
    cidr_block=vpc_cidr,
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={"Name": f"{project}-{stack}-vpc"},
)

igw = aws.ec2.InternetGateway(
    "igw",
    vpc_id=vpc.id,
    tags={"Name": f"{project}-{stack}-igw"},
)

public_rt = aws.ec2.RouteTable(
    "public-rt",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)],
    tags={"Name": f"{project}-{stack}-public-rt"},
)

private_rt = aws.ec2.RouteTable(
    "private-rt",
    vpc_id=vpc.id,
    tags={"Name": f"{project}-{stack}-private-rt"},
)

public_subnets = []
private_subnets = []
for i, az in enumerate(azs, start=1):
    pub = aws.ec2.Subnet(
        f"public-subnet-{i}",
        vpc_id=vpc.id,
        availability_zone=az,
        cidr_block=f"10.0.{i}.0/24",
        map_public_ip_on_launch=True,
        tags={"Name": f"{project}-{stack}-public-{i}"},
    )
    aws.ec2.RouteTableAssociation(
        f"public-rta-{i}", route_table_id=public_rt.id, subnet_id=pub.id
    )
    public_subnets.append(pub)

    prv = aws.ec2.Subnet(
        f"private-subnet-{i}",
        vpc_id=vpc.id,
        availability_zone=az,
        cidr_block=f"10.0.{i+100}.0/24",
        map_public_ip_on_launch=False,
        tags={"Name": f"{project}-{stack}-private-{i}"},
    )
    aws.ec2.RouteTableAssociation(
        f"private-rta-{i}", route_table_id=private_rt.id, subnet_id=prv.id
    )
    private_subnets.append(prv)

# Free S3 Gateway Endpoint (enables S3 access from private subnets)
aws.ec2.VpcEndpoint(
    "s3-gateway-endpoint",
    vpc_id=vpc.id,
    service_name=f"com.amazonaws.{region.region}.s3",
    vpc_endpoint_type="Gateway",
    route_table_ids=[public_rt.id, private_rt.id],
    tags={"Name": f"{project}-{stack}-s3-endpoint"},
)

# ------------------------
# Security Groups
# ------------------------
app_sg = aws.ec2.SecurityGroup(
    "app-sg",
    vpc_id=vpc.id,
    description="LangChain app SG",
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"]
        )
    ],
    tags={"Name": f"{project}-{stack}-app-sg"},
)
# Public ingress only 80/443
for port in [80, 443]:
    aws.ec2.SecurityGroupRule(
        f"app-ingress-{port}",
        type="ingress",
        security_group_id=app_sg.id,
        protocol="tcp",
        from_port=port,
        to_port=port,
        cidr_blocks=["0.0.0.0/0"],
    )
# Optional SSH to app from your IP
if allowed_ssh_cidr:
    aws.ec2.SecurityGroupRule(
        "app-ssh-ingress",
        type="ingress",
        security_group_id=app_sg.id,
        protocol="tcp",
        from_port=22,
        to_port=22,
        cidr_blocks=[allowed_ssh_cidr],
    )

# Reranker SG (only app can talk to reranker port + SSH from app)
reranker_sg = aws.ec2.SecurityGroup(
    "reranker-sg",
    vpc_id=vpc.id,
    description="Reranker SG",
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"]
        )
    ],
    tags={"Name": f"{project}-{stack}-reranker-sg"},
)
aws.ec2.SecurityGroupRule(
    "reranker-from-app",
    type="ingress",
    security_group_id=reranker_sg.id,
    protocol="tcp",
    from_port=reranker_port,
    to_port=reranker_port,
    source_security_group_id=app_sg.id,
)
aws.ec2.SecurityGroupRule(
    "reranker-ssh-from-app",
    type="ingress",
    security_group_id=reranker_sg.id,
    protocol="tcp",
    from_port=22,
    to_port=22,
    source_security_group_id=app_sg.id,
)

# OpenSearch SG (allow 443 from app + reranker; OSI will be added conditionally)
opensearch_sg = aws.ec2.SecurityGroup(
    "opensearch-sg",
    vpc_id=vpc.id,
    description="OpenSearch VPC SG",
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"]
        )
    ],
    tags={"Name": f"{project}-{stack}-os-sg"},
)


def allow_os_from(name: str, source_sg_id):
    return aws.ec2.SecurityGroupRule(
        name,
        type="ingress",
        security_group_id=opensearch_sg.id,
        protocol="tcp",
        from_port=443,
        to_port=443,
        source_security_group_id=source_sg_id,
    )


allow_os_from("os-from-app-sg", app_sg.id)
allow_os_from("os-from-reranker-sg", reranker_sg.id)

# ------------------------
# S3 Buckets (artifacts + app storage)
# ------------------------
bucket = aws.s3.Bucket(
    "pubmed-bucket",
    bucket=f"{project}-{stack}-pubmed".lower(),
    tags={"Name": f"{project}-{stack}-pubmed"},
)
aws.s3.BucketPublicAccessBlock(
    "pubmed-bucket-pab",
    bucket=bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    restrict_public_buckets=True,
    ignore_public_acls=True,
)
aws.s3.BucketPolicy(
    "pubmed-bucket-policy",
    bucket=bucket.id,
    policy=bucket.id.apply(
        lambda bname: json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyInsecureTransport",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [
                            f"arn:aws:s3:::{bname}",
                            f"arn:aws:s3:::{bname}/*",
                        ],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ],
            }
        )
    ),
)

# Upload your local artifact to the bucket at a predictable key
artifact_key = "reranker/releases/v1/reranker.tar.gz"
# artifact_obj = aws.s3.BucketObjectv2(
#     "reranker-artifact",
#     bucket=bucket.bucket,  # name, not ID
#     key=artifact_key,
#     source=pulumi.FileAsset("artifacts/reranker.tar.gz"),  # ensure this file exists
#     content_type="application/gzip",
#     server_side_encryption="AES256",
# )

# Chainlit storage bucket (S3)
chainlit_bucket = aws.s3.Bucket(
    "chainlit-bucket",
    bucket=f"{project}-{stack}-chainlit".lower(),
    tags={"Name": f"{project}-{stack}-chainlit"},
)
aws.s3.BucketCorsConfiguration(
    "chainlit-bucket-cors",
    bucket=chainlit_bucket.id,
    cors_rules=[
        aws.s3.BucketCorsRuleArgs(
            allowed_methods=["GET", "HEAD"],  # <-- no OPTIONS here
            allowed_origins=[
                "https://app.authservices.cloud",
                "https://api.authservices.cloud",
                "http://34.236.43.171",
                "http://localhost:8000",
                "http://127.0.0.1:8000",
            ],
            allowed_headers=["*"],
            expose_headers=["ETag", "Content-Length", "Content-Type"],
            max_age_seconds=3600,
        )
    ],
)

aws.s3.BucketPublicAccessBlock(
    "chainlit-bucket-pab",
    bucket=chainlit_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    restrict_public_buckets=True,
    ignore_public_acls=True,
)
aws.s3.BucketPolicy(
    "chainlit-bucket-policy",
    bucket=chainlit_bucket.id,
    policy=chainlit_bucket.id.apply(
        lambda bname: json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyInsecureTransport",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [
                            f"arn:aws:s3:::{bname}",
                            f"arn:aws:s3:::{bname}/*",
                        ],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ],
            }
        )
    ),
)

# ------------------------
# Chainlit persistence (DynamoDB)
# ------------------------
chainlit_table = aws.dynamodb.Table(
    "chainlit-table",
    attributes=[
        aws.dynamodb.TableAttributeArgs(name="PK", type="S"),
        aws.dynamodb.TableAttributeArgs(name="SK", type="S"),
        aws.dynamodb.TableAttributeArgs(name="UserThreadPK", type="S"),
        aws.dynamodb.TableAttributeArgs(name="UserThreadSK", type="S"),
    ],
    hash_key="PK",
    range_key="SK",
    billing_mode="PAY_PER_REQUEST",
    global_secondary_indexes=[
        aws.dynamodb.TableGlobalSecondaryIndexArgs(
            name="UserThread",
            hash_key="UserThreadPK",
            range_key="UserThreadSK",
            projection_type="ALL",
        )
    ],
    tags={"Name": f"{project}-{stack}-chainlit"},
)

# ------------------------
# IAM Role & Instance Profile for EC2
# ------------------------
ec2_role = aws.iam.Role(
    "ec2-role",
    assume_role_policy=json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Effect": "Allow",
                }
            ],
        }
    ),
)

aws.iam.RolePolicyAttachment(
    "ec2-ssm",
    role=ec2_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
)
aws.iam.RolePolicyAttachment(
    "ec2-s3-read",
    role=ec2_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
)

# Allow EC2 to call OpenSearch data APIs (for your app)
domain_arn = f"arn:aws:es:{region.region}:{identity.account_id}:domain/{domain_name}"
aws.iam.RolePolicy(
    "ec2-os-http",
    role=ec2_role.id,
    policy=json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "es:ESHttp*",
                    "Resource": f"{domain_arn}/*",
                }
            ],
        }
    ),
)

instance_profile = aws.iam.InstanceProfile("ec2-instance-profile", role=ec2_role.name)

# App EC2 needs RW to Chainlit bucket + DynamoDB table
aws.iam.RolePolicy(
    "ec2-chainlit-s3rw",
    role=ec2_role.id,
    policy=chainlit_bucket.bucket.apply(
        lambda bname: json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ListBucket",
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{bname}"],
                    },
                    {
                        "Sid": "ObjectRW",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                        "Resource": [f"arn:aws:s3:::{bname}/*"],
                    },
                ],
            }
        )
    ),
)

aws.iam.RolePolicy(
    "ec2-chainlit-dynamodb",
    role=ec2_role.id,
    policy=chainlit_table.arn.apply(
        lambda t_arn: json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "RWTable",
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:PutItem",
                            "dynamodb:GetItem",
                            "dynamodb:UpdateItem",
                            "dynamodb:DeleteItem",
                            "dynamodb:BatchWriteItem",
                            "dynamodb:Query",
                            "dynamodb:Scan",
                            "dynamodb:DescribeTable",
                        ],
                        "Resource": [t_arn],
                    },
                    {
                        "Sid": "QueryGSIs",
                        "Effect": "Allow",
                        "Action": ["dynamodb:Query", "dynamodb:Scan"],
                        "Resource": [f"{t_arn}/index/*"],
                    },
                ],
            }
        )
    ),
)

# ------------------------
# AMI
# ------------------------
ami = aws.ec2.get_ami(
    owners=["137112412989"],
    most_recent=True,
    filters=[
        aws.ec2.GetAmiFilterArgs(name="name", values=["al2023-ami-*-x86_64"]),
        aws.ec2.GetAmiFilterArgs(name="architecture", values=["x86_64"]),
        aws.ec2.GetAmiFilterArgs(name="state", values=["available"]),
    ],
)

# ------------------------
# User data
# ------------------------
app_user_data = """#!/bin/bash
set -eux
systemctl enable --now amazon-ssm-agent || true
"""

# Build reranker user_data with the resolved bucket name + object key
reranker_user_data = pulumi.Output.all(
    bucket_name=bucket.bucket, key=artifact_key, port=reranker_port
).apply(
    lambda args: f"""#!/bin/bash
set -euxo pipefail

systemctl enable --now amazon-ssm-agent || true

APP_DIR=/opt/reranker
ARTIFACT_S3=s3://{args['bucket_name']}/{args['key']}

mkdir -p "$APP_DIR"
cd "$APP_DIR"

# Pull artifact and unpack
aws s3 cp "$ARTIFACT_S3" ./reranker.tar.gz
tar -xzf reranker.tar.gz

# Ensure the runtime user can manage the venv & files (systemd User=ec2-user)
chown -R ec2-user:ec2-user "$APP_DIR"

# Fully-offline bootstrap script (idempotent)
mkdir -p "$APP_DIR/bin"
cat >"$APP_DIR/bin/bootstrap.sh" <<'BOOT'
#!/usr/bin/env bash
set -euxo pipefail

APP_DIR=/opt/reranker
STAMP="$APP_DIR/.bootstrapped"
WHEELHOUSE="file://$APP_DIR/wheels-linux"
VENVDIR="$APP_DIR/.venv"

# If already bootstrapped, do nothing
if [[ -f "$STAMP" ]]; then
  exit 0
fi

# Build venv
python3 -m venv "$VENVDIR"

# Offline pip configuration
export PIP_NO_INDEX=1
export PIP_FIND_LINKS="$WHEELHOUSE"
export PIP_ONLY_BINARY=":all:"
export PIP_DISABLE_PIP_VERSION_CHECK=1

# Install strictly from local wheels; no builds, no internet
"$VENVDIR/bin/pip" install --no-index --find-links "$WHEELHOUSE" \\
  --only-binary=:all: --no-build-isolation \\
  -r "$APP_DIR/requirements.txt"

touch "$STAMP"
BOOT
chmod +x "$APP_DIR/bin/bootstrap.sh"

# Systemd service
cat >/etc/systemd/system/reranker.service <<'SERVICE'
[Unit]
Description=Reranker service
After=network-online.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/reranker
ExecStartPre=/bin/bash -lc '/opt/reranker/bin/bootstrap.sh >> /opt/reranker/bootstrap.log 2>&1'
ExecStart=/opt/reranker/.venv/bin/python -m reranker.server --port={args['port']}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now reranker.service
"""
)


# ------------------------
# EC2 Instances
# ------------------------
app_instance = aws.ec2.Instance(
    "app-ec2",
    ami=ami.id,
    instance_type="t3.medium",
    subnet_id=public_subnets[0].id,
    vpc_security_group_ids=[app_sg.id],
    associate_public_ip_address=True,
    iam_instance_profile=instance_profile.name,
    user_data=app_user_data,
    key_name=key_name,
    root_block_device=aws.ec2.InstanceRootBlockDeviceArgs(volume_size=8),
    tags={"Name": f"{project}-{stack}-app"},
)
app_eip = aws.ec2.Eip("app-eip", domain="vpc", instance=app_instance.id)

reranker_instance = aws.ec2.Instance(
    "reranker-ec2",
    ami=ami.id,
    instance_type="g4dn.xlarge",
    subnet_id=private_subnets[0].id,
    vpc_security_group_ids=[reranker_sg.id],
    associate_public_ip_address=False,
    iam_instance_profile=instance_profile.name,
    user_data=reranker_user_data,
    key_name=key_name,  # SSH via jump host (app)
    root_block_device=aws.ec2.InstanceRootBlockDeviceArgs(volume_size=20),
    # opts=pulumi.ResourceOptions(depends_on=[artifact_obj]),
    tags={"Name": f"{project}-{stack}-reranker"},
)

# ------------------------
# (OPTIONAL) OSI/INGESTION — ALL RESOURCES IN THIS SECTION ARE CONTROLLED BY `ingestionEnabled`
# ------------------------
osis_sg = None
osis_role = None
vpce_sts = None
vpce_logs = None
osis_pipeline = None

if ingestion_enabled:
    # SG for OSI ENIs
    osis_sg = aws.ec2.SecurityGroup(
        "osis-sg",
        vpc_id=vpc.id,
        description="OSI pipeline ENIs",
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"]
            )
        ],
        tags={"Name": f"{project}-{stack}-osis-sg"},
    )

    # Allow OSI ENIs to reach Interface VPC endpoints (STS/Logs) attached to this same SG.
    aws.ec2.SecurityGroupRule(
        "osis-sg-self-443",
        type="ingress",
        security_group_id=osis_sg.id,
        protocol="tcp",
        from_port=443,
        to_port=443,
        source_security_group_id=osis_sg.id,
    )

    # Allow OSI -> OpenSearch (443) — keep the original logical name for Pulumi state
    aws.ec2.SecurityGroupRule(
        "os-from-osis",
        type="ingress",
        security_group_id=opensearch_sg.id,
        protocol="tcp",
        from_port=443,
        to_port=443,
        source_security_group_id=osis_sg.id,
    )

    # VPC Interface Endpoints required for private OSI egress
    vpce_sts = aws.ec2.VpcEndpoint(
        "vpce-sts",
        vpc_id=vpc.id,
        service_name=f"com.amazonaws.{region.region}.sts",
        vpc_endpoint_type="Interface",
        subnet_ids=[private_subnets[0].id],
        security_group_ids=[osis_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{project}-{stack}-vpce-sts"},
    )
    # Optional but recommended: CloudWatch Logs so OSI can emit logs without NAT
    vpce_logs = aws.ec2.VpcEndpoint(
        "vpce-logs",
        vpc_id=vpc.id,
        service_name=f"com.amazonaws.{region.region}.logs",
        vpc_endpoint_type="Interface",
        subnet_ids=[private_subnets[0].id],
        security_group_ids=[osis_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{project}-{stack}-vpce-logs"},
    )

    # IAM Role for OpenSearch Ingestion Pipeline
    osis_role = aws.iam.Role(
        "osis-role",
        assume_role_policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "osis-pipelines.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        tags={"Name": f"{project}-{stack}-osis-role"},
    )
    # OSI: allow read from your pubmed bucket prefix
    aws.iam.RolePolicy(
        "osis-s3-read",
        role=osis_role.id,
        policy=bucket.bucket.apply(
            lambda bname: json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:ListBucket"],
                            "Resource": [
                                f"arn:aws:s3:::{bname}",
                                f"arn:aws:s3:::{bname}/datasets/pubmed/*",
                            ],
                        }
                    ],
                }
            )
        ),
    )
    # OSI: allow push into your OpenSearch domain + describe it
    aws.iam.RolePolicy(
        "osis-os-http",
        role=osis_role.id,
        policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["es:ESHttp*"],
                        "Resource": [f"{domain_arn}/*"],
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "es:DescribeDomain",
                            "es:DescribeDomainConfig",
                            "es:ListDomainNames",
                        ],
                        "Resource": ["*"],
                    },
                ],
            }
        ),
    )

# ------------------------
# OpenSearch Domain (exists always; sizing & access depend on `ingestionEnabled`)
# ------------------------
if ingestion_enabled:
    principals_output = pulumi.Output.all(ec2_role.arn, osis_role.arn)
else:
    principals_output = pulumi.Output.all(ec2_role.arn)

access_policy = principals_output.apply(
    lambda arns: json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": arns},
                    "Action": "es:*",
                    "Resource": f"{domain_arn}/*",
                }
            ],
        }
    )
)

os_domain = aws.opensearch.Domain(
    "opensearch",
    domain_name=domain_name,
    engine_version="OpenSearch_3.1",
    cluster_config=aws.opensearch.DomainClusterConfigArgs(
        instance_type=os_eff_instance_type,
        instance_count=os_instance_count,
    ),
    ebs_options=aws.opensearch.DomainEbsOptionsArgs(
        ebs_enabled=True, volume_size=os_eff_volume_gib, volume_type="gp3"
    ),
    vpc_options=aws.opensearch.DomainVpcOptionsArgs(
        security_group_ids=[opensearch_sg.id],
        subnet_ids=[private_subnets[0].id],
    ),
    encrypt_at_rest=aws.opensearch.DomainEncryptAtRestArgs(enabled=True),
    node_to_node_encryption=aws.opensearch.DomainNodeToNodeEncryptionArgs(enabled=True),
    domain_endpoint_options=aws.opensearch.DomainDomainEndpointOptionsArgs(
        enforce_https=True, tls_security_policy="Policy-Min-TLS-1-2-2019-07"
    ),
    access_policies=access_policy,
    tags={"Name": f"{project}-{stack}-os"},
)

# ------------------------
# OSI Pipeline (S3 -> OpenSearch) — created only when ingestion is enabled
# ------------------------
aws_native_provider = aws_native.Provider("aws-native", region=region.region)

if ingestion_enabled:
    # Pre-create CloudWatch Log Group so you control retention/KMS
    pipeline_name = "pubmed-pipeline"

    # ONE-TIME scheduled scan: omit any recurring interval. (Runs once on create.)
    pipeline_config = pulumi.Output.all(
        bucket=bucket.bucket,
        region_str=region.region,
        endpoint=os_domain.endpoint,
        role_arn=osis_role.arn,
    ).apply(
        lambda a: textwrap.dedent(
            f"""
        version: "2"
        pubmed-pipeline:
          source:
            s3:
              codec:
                newline: {{}}
              compression: none
              aws:
                region: "{a['region_str']}"
                sts_role_arn: "{a['role_arn']}"
              scan:
                buckets:
                  - bucket:
                      name: "{a['bucket']}"
                      filter:
                        include_prefix:
                          - "datasets/pubmed/"
              records_to_accumulate: {source_records}
              backoff_time: "{source_backoff}"
          processor:
            - parse_json: {{}}
          sink:
            - opensearch:
                hosts: ["https://{a['endpoint']}"]
                aws:
                  region: "{a['region_str']}"
                  sts_role_arn: "{a['role_arn']}"
                index: "pubmed-abstracts-1p"
                document_id: "${{/PMID}}"
                bulk_size: {sink_bulk}
                flush_timeout: {sink_flush_ms}
                max_retries: 16
        """
        )
    )

    osis_pipeline = aws_native.osis.Pipeline(
        "pubmed-pipeline",
        pipeline_name=pipeline_name,
        min_units=osi_min_ocus,
        max_units=osi_max_ocus,
        pipeline_configuration_body=pipeline_config,
        vpc_options=aws_native.osis.PipelineVpcOptionsArgs(
            subnet_ids=[private_subnets[0].id],
            security_group_ids=[osis_sg.id],
        ),
        log_publishing_options={
            "is_logging_enabled": True,
            "cloud_watch_log_destination": {
                "log_group": f"/aws/vendedlogs/OpenSearchIngestion/{pipeline_name}"
            },
        },
        tags=[{"key": "Name", "value": f"{project}-{stack}-pubmed-pipeline"}],
        opts=pulumi.ResourceOptions(
            provider=aws_native_provider,
            depends_on=[os_domain, vpce_sts, vpce_logs],
        ),
    )

# ------------------------
# Outputs
# ------------------------
pulumi.export("ingestionEnabled", ingestion_enabled)
pulumi.export("vpcId", vpc.id)
pulumi.export("appPublicIp", app_eip.public_ip)
pulumi.export("appUrl", app_eip.public_ip.apply(lambda ip: f"http://{ip}"))
pulumi.export("rerankerPrivateIp", reranker_instance.private_ip)
pulumi.export("s3Bucket", bucket.bucket)
pulumi.export("artifactKey", artifact_key)
pulumi.export("openSearchEndpoint", os_domain.endpoint)
pulumi.export("chainlitBucket", chainlit_bucket.bucket)
pulumi.export("chainlitTable", chainlit_table.name)

# Helpful: expose OSI-specific outputs only if enabled
if ingestion_enabled:
    pulumi.export("osisRoleArn", osis_role.arn)
    pulumi.export("osisSecurityGroupId", osis_sg.id)
    pulumi.export("vpceStsId", vpce_sts.id)
    pulumi.export("vpceLogsId", vpce_logs.id)
    pulumi.export("osisPipelineName", osis_pipeline.pipeline_name)
    pulumi.export(
        "osisLogGroup", f"/aws/vendedlogs/OpenSearchIngestion/{pipeline_name}"
    )

# Always export domain sizing for clarity
pulumi.export("osInstanceType", os_eff_instance_type)
pulumi.export("osInstanceCount", os_instance_count)
pulumi.export("osVolumeSizeGiB", os_eff_volume_gib)
