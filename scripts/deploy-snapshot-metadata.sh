#! /bin/bash

# Copyright 2024 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -x

SCRIPT_DIR="$(dirname "${0}")"

# shellcheck disable=SC1091
[ ! -e "${SCRIPT_DIR}"/utils.sh ] || . "${SCRIPT_DIR}"/utils.sh

TEMP_DIR="$(mktemp -d)"
# trap 'rm -rf ${TEMP_DIR}' EXIT

# snapshot metadata CRDs
SNAPSHOT_METADATA_URL="https://raw.githubusercontent.com/kubernetes-csi/external-snapshot-metadata/main"
SNAPSHOT_METADATA_SERVICE="${SNAPSHOT_METADATA_URL}/client/config/crd/cbt.storage.k8s.io_snapshotmetadataservices.yaml"
SNAPSHOT_METADATA_CLUSTER_ROLE="${SNAPSHOT_METADATA_URL}/deploy/snapshot-metadata-cluster-role.yaml"
SNAPSHOT_METADATA_CLUSTER_ROLE_BINDING="${SNAPSHOT_METADATA_URL}/deploy/example/csi-driver/csi-driver-cluster-role-binding.yaml"
SNAPSHOT_METADATA_DRIVER_SERVICE="${SNAPSHOT_METADATA_URL}/deploy/example/csi-driver/csi-driver-service.yaml"

SNAPSHOT_METADATA_CLIENT_CLUSTER_ROLE="${SNAPSHOT_METADATA_URL}/deploy/snapshot-metadata-client-cluster-role.yaml"
SNAPSHOT_METADATA_CLIENT_SA_NAME="cbt-client-sa"

NAMESPACE="default"

function create_or_delete_crds() {
    local action=$1
    temp_snap_meta_svc=${TEMP_DIR}/snapshot-metadata-service.yaml

    curl -o "${temp_snap_meta_svc}" "${SNAPSHOT_METADATA_SERVICE}"
    yq -i '.metadata.annotations["api-approved.kubernetes.io"] = "https://github.com/kubernetes/enhancements/pull/1111"' "${temp_snap_meta_svc}"
    kubectl_retry "${action}" -f "${temp_snap_meta_svc}"
}

function provision_tls_certs() {
    ca_key="${TEMP_DIR}/ca-key.pem"
    ca_cert="${TEMP_DIR}/ca-cert.pem"
    server_req="${TEMP_DIR}/server-req.pem"
    server_ext="${TEMP_DIR}/server-ext.cnf"
    server_key="${TEMP_DIR}/server-key.pem"
    server_cert="${TEMP_DIR}/server-cert.pem"
    # 1. Create extension file
    echo "subjectAltName=DNS:.${NAMESPACE},DNS:csi-snapshot-metadata.${NAMESPACE},DNS:csi-snapshot-metadata.default,IP:0.0.0.0" >"${server_ext}"

    # 2. Generate CA's private key and self-signed certificate
    openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout "${ca_key}" -out "${ca_cert}" -subj "/CN=csi-snapshot-metadata.${NAMESPACE}"
    openssl x509 -in "${ca_cert}" -noout -text

    # 2. Generate web server's private key and certificate signing request (CSR)
    openssl req -newkey rsa:4096 -nodes -keyout "${server_key}" -out "${server_req}" -subj "/CN=csi-snapshot-metadata.${NAMESPACE}"

    # 3. Use CA's private key to sign web server's CSR and get back the signed certificate
    openssl x509 -req -in "${server_req}" -days 60 -CA "${ca_cert}" -CAkey "${ca_key}" -CAcreateserial -out "${server_cert}" -extfile "${server_ext}"
    openssl x509 -in "${server_cert}" -noout -text
}

function create_or_delete_tls_certs() {
    local action=$1
    if [ "${action}" == "delete" ]; then
        kubectl_retry "${action}" secret csi-snapshot-metadata-certs --namespace="${NAMESPACE}"
        return 0
    fi
    kubectl_retry "${action}" secret tls csi-snapshot-metadata-certs \
        --namespace="${NAMESPACE}" \
        --cert="${TEMP_DIR}/server-cert.pem" \
        --key="${TEMP_DIR}/server-key.pem"
}


function create_or_delete_rbacs() {
    local action=$1
    
    temp_file=$(mktemp "${TEMP_DIR}/snapshot-metadata-rolebinding.XXXXXX.yaml")
    curl -o "${temp_file}" "${SNAPSHOT_METADATA_CLUSTER_ROLE_BINDING}"
    namespace=$NAMESPACE yq -i ".subjects[0].namespace = env(namespace)" "${temp_file}"
    yq -i '.subjects[0].name = "csi-hostpathplugin-sa"' "${temp_file}"

    kubectl_retry "${action}" -f "${SNAPSHOT_METADATA_CLUSTER_ROLE}"
    kubectl_retry "${action}" -f "${temp_file}"

}

function create_or_delete_snapshot_metadata_service() {
    local action=$1
    local generated_ca_cert
    if [ -f "${ca_cert}" ]; then
        generated_ca_cert=$(base64 -i -w 0 "${ca_cert}")
    fi
    temp_file=$(mktemp "${TEMP_DIR}/snapshot-metadata-service.XXXXXX.yaml")
    cat <<EOF >"${temp_file}"
apiVersion: cbt.storage.k8s.io/v1alpha1
kind: SnapshotMetadataService
metadata:
  name: hostpath.csi.k8s.io
spec:
    address: "csi-snapshot-metadata.${NAMESPACE}:6443"
    caCert: "${generated_ca_cert}"
    audience: "csi-snapshot-metadata"
EOF
    kubectl_retry "${action}" -f "${temp_file}"
}


function patch_snapshot_metadata_sidecar() {
    kubectl get statefulset csi-hostpathplugin -oyaml > hostplugin.yaml
    yq -i '
        .spec.template.spec.containers += [
            {
                "name": "csi-snapshot-metadata",
                "image": "gcr.io/k8s-staging-sig-storage/csi-snapshot-metadata:main",
                "imagePullPolicy": "IfNotPresent",
                "args": [
                    "--v=5",
                    "--port=50051",
                    "--csi-address=/csi/csi.sock",
                    "--tls-cert=/tmp/certificates/tls.crt",
                    "--tls-key=/tmp/certificates/tls.key"
                ],
                "volumeMounts": [
                    {
                        "mountPath": "/csi",
                        "name": "socket-dir"
                    },
                    {
                        "mountPath": "/tmp/certificates",
                        "name": "csi-snapshot-metadata-certs",
                        "readOnly": true
                    }
                ]
            }
        ] | 
        .spec.template.spec.volumes += [
            {
                "name": "csi-snapshot-metadata-certs",
                "secret": {
                    "secretName": "csi-snapshot-metadata-certs"
                }
            }
        ]
    ' hostplugin.yaml

    # enable snapshot-metadata capability in hostpath plugin
    yq -i '
        .spec.template.spec.containers[] |=
        select(.name == "hostpath") |=
        .args += "--enable-snapshot-metadata=true"
    ' hostplugin.yaml

    # Delete and recreate the csi-hostpathplugin statefulset
    kubectl delete -f hostplugin.yaml
    kubectl create -f hostplugin.yaml
}

function create_or_delete_csi_driver_service() {
    local action=$1
    temp_svc=${TEMP_DIR}/service.yaml
    curl -o "${temp_svc}" "${SNAPSHOT_METADATA_DRIVER_SERVICE}"
    namespace=$NAMESPACE yq -i ".metadata.namespace = env(namespace)" "${temp_svc}"
    yq -i '.spec.selector."app.kubernetes.io/name" = "csi-hostpathplugin"' "${temp_svc}"
    kubectl_retry "${action}" -f "${temp_svc}"
}

function create_or_delete_snapshot_metadata_client_rbacs() {
    local action=$1
    local cluster_role_name="external-snapshot-metadata-client-runner"

    temp_sa=$(mktemp "${TEMP_DIR}/snapshot-metadata-client-sa.XXXXXX.yaml")
    cat <<EOF >"${temp_sa}"
apiVersion: v1
kind: ServiceAccount
metadata:
  name: "${SNAPSHOT_METADATA_CLIENT_SA_NAME}"
  namespace: "${NAMESPACE}"
EOF

    temp_rolebinding=$(mktemp "${TEMP_DIR}/snapshot-metadata-client-rolebinding.XXXXXX.yaml")
    cat <<EOF >"${temp_rolebinding}"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: csi-snapshot-metadata-client-cluster-role
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: "${cluster_role_name}"
subjects:
- kind: ServiceAccount
  name: "${SNAPSHOT_METADATA_CLIENT_SA_NAME}"
  namespace: ${NAMESPACE}
EOF
    
    kubectl_retry "${action}" -f "${SNAPSHOT_METADATA_CLIENT_CLUSTER_ROLE}"
    kubectl_retry "${action}" -f "${temp_sa}"
    kubectl_retry "${action}" -f "${temp_rolebinding}"
}

function deploy_client() {


    temp_pod=$(mktemp "${TEMP_DIR}/snapshot-metadata-client-pod.XXXXXX.yaml")
    cat <<EOF >"${temp_pod}"
apiVersion: v1
kind: Pod
metadata:
  name: cbt-client
spec:
  serviceAccount: "${SNAPSHOT_METADATA_CLIENT_SA_NAME}"
  serviceAccountName: "${SNAPSHOT_METADATA_CLIENT_SA_NAME}"
  containers:
  - command:
    - sh
    - -c
    - tail -f /dev/null
    image: ghcr.io/ipraveenparihar/external-snapshot-metadata:snapshot-metadata-lister
    imagePullPolicy: Always
    name: client
EOF

    create_or_delete_snapshot_metadata_client_rbacs "create"
    kubectl_retry apply -f "${temp_pod}"
    kubectl_retry wait pod/cbt-client --for=condition=Ready --timeout=300s
}

function deploy() {
    create_or_delete_crds "create"
    provision_tls_certs
    create_or_delete_tls_certs "create"
    create_or_delete_rbacs "create"
    create_or_delete_snapshot_metadata_service "create"
    patch_snapshot_metadata_sidecar
    create_or_delete_csi_driver_service "create"

    kubectl_retry get all -n "${NAMESPACE}"
}

function cleanup() {
    create_or_delete_csi_driver_service "delete"
    create_or_delete_snapshot_metadata_service "delete"
    create_or_delete_rbacs "delete"
    create_or_delete_tls_certs "delete"
    create_or_delete_crds "delete"
}

FUNCTION="$1"
shift # remove function arg now that we've recorded it
# call the function with the remainder of the user-provided args
# -e, -E, and -o=pipefail will ensure this script returns a failure if a part of the function fails
$FUNCTION "$@"