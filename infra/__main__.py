import json
import pulumi
import pulumi_aws as aws

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

region = aws.get_region()
identity = aws.get_caller_identity()

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

azs = aws.get_availability_zones(state="available").names[:1]

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

# OpenSearch SG (allow 443 from app + reranker only)
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
for name, sg in [("app-sg", app_sg), ("reranker-sg", reranker_sg)]:
    aws.ec2.SecurityGroupRule(
        f"os-from-{name}",
        type="ingress",
        security_group_id=opensearch_sg.id,
        protocol="tcp",
        from_port=443,
        to_port=443,
        source_security_group_id=sg.id,
    )

# ------------------------
# S3 Bucket + Object (artifact uploaded by Pulumi)
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
artifact_obj = aws.s3.BucketObjectv2(
    "reranker-artifact",
    bucket=bucket.bucket,  # name, not ID
    key=artifact_key,
    source=pulumi.FileAsset("artifacts/reranker.tar.gz"),  # <-- ensure this file exists
    content_type="application/gzip",
    server_side_encryption="AES256",
)

# ------------------------
# IAM Role & Profile
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

# ------------------------
# OpenSearch Free Tier
# ------------------------
os_domain = aws.opensearch.Domain(
    "opensearch",
    domain_name=domain_name,
    engine_version="OpenSearch_3.1",
    cluster_config=aws.opensearch.DomainClusterConfigArgs(
        instance_type="t3.small.search", instance_count=1
    ),
    ebs_options=aws.opensearch.DomainEbsOptionsArgs(
        ebs_enabled=True, volume_size=10, volume_type="gp3"
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
    access_policies=ec2_role.arn.apply(
        lambda arn: json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": arn},
                        "Action": "es:*",
                        "Resource": f"{domain_arn}/*",
                    }
                ],
            }
        )
    ),
    tags={"Name": f"{project}-{stack}-os"},
)

# ------------------------
# EC2 AMI
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
# User data (built dynamically so bucket/key are correct)
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

mkdir -p $APP_DIR
cd $APP_DIR

aws s3 cp "$ARTIFACT_S3" ./reranker.tar.gz
tar -xzf reranker.tar.gz

python3 -m venv .venv
source .venv/bin/activate

# Optional: if you included prebuilt wheels and requirements.txt
if [ -f wheels/INDEX ]; then
  pip install --no-index --find-links file://$APP_DIR/wheels -r requirements.txt || true
fi

cat >/etc/systemd/system/reranker.service <<'SERVICE'
[Unit]
Description=Reranker service
After=network-online.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/reranker
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
    user_data=reranker_user_data,  # uses the uploaded S3 object
    key_name=key_name,  # SSH via jump host (app)
    # Ensure instance waits for the artifact to exist (implicit via user_data ref, but be explicit)
    opts=pulumi.ResourceOptions(depends_on=[artifact_obj]),
    tags={"Name": f"{project}-{stack}-reranker"},
)

# ------------------------
# Outputs
# ------------------------
pulumi.export("vpcId", vpc.id)
pulumi.export("appPublicIp", app_eip.public_ip)
pulumi.export("appUrl", app_eip.public_ip.apply(lambda ip: f"http://{ip}"))
pulumi.export("rerankerPrivateIp", reranker_instance.private_ip)
pulumi.export("s3Bucket", bucket.bucket)
pulumi.export("artifactKey", artifact_key)
pulumi.export("openSearchEndpoint", os_domain.endpoint)
