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

# shellcheck disable=SC1091

set -e
set -x

SCRIPT_DIR="$(dirname "${0}")"

# shellcheck disable=SC1091
[ ! -e "${SCRIPT_DIR}"/utils.sh ] || . "${SCRIPT_DIR}"/utils.sh

TEMP_DIR="$(mktemp -d)"
# trap 'rm -rf ${TEMP_DIR}' EXIT

# snapshot
SNAPSHOT_VERSION=${SNAPSHOT_VERSION:-"v8.1.0"}
SNAPSHOTTER_URL="https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/${SNAPSHOT_VERSION}"

# snapshot controller
SNAPSHOT_RBAC="${SNAPSHOTTER_URL}/deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml"
SNAPSHOT_CONTROLLER="${SNAPSHOTTER_URL}/deploy/kubernetes/snapshot-controller/setup-snapshot-controller.yaml"

# snapshot CRD
SNAPSHOTCLASS="${SNAPSHOTTER_URL}/client/config/crd/snapshot.storage.k8s.io_volumesnapshotclasses.yaml"
VOLUME_SNAPSHOT_CONTENT="${SNAPSHOTTER_URL}/client/config/crd/snapshot.storage.k8s.io_volumesnapshotcontents.yaml"
VOLUME_SNAPSHOT="${SNAPSHOTTER_URL}/client/config/crd/snapshot.storage.k8s.io_volumesnapshots.yaml"

# snapshot metadata CRDs
SNAPSHOT_METADATA_URL="https://raw.githubusercontent.com/kubernetes-csi/external-snapshot-metadata/main"
SNAPSHOT_METADATA_SERVICE="${SNAPSHOT_METADATA_URL}/client/config/crd/cbt.storage.k8s.io_snapshotmetadataservices.yaml"
SNAPSHOT_METADATA_SERVICE_ACCOUNT="${SNAPSHOT_METADATA_URL}/deploy/example/csi-driver/csi-driver-service-account.yaml"
SNAPSHOT_METADATA_CLUSTER_ROLE="${SNAPSHOT_METADATA_URL}/deploy/example/csi-driver/csi-driver-cluster-role-binding.yaml"
SNAPSHOT_METADATA_DRIVER_SERVICE="${SNAPSHOT_METADATA_URL}/deploy/example/csi-driver/csi-driver-service.yaml"

NAMESPACE="default"

function create_or_delete_crds() {
    local action=$1
    temp_snap_meta_svc=${TEMP_DIR}/snapshot-metadata-service.yaml

    curl -o "${temp_snap_meta_svc}" "${SNAPSHOT_METADATA_SERVICE}"
    yq eval '.metadata.annotations["api-approved.kubernetes.io"] = "https://github.com/kubernetes/enhancements/pull/1111"' -i "${temp_snap_meta_svc}"

    kubectl_retry "${action}" -f "${SNAPSHOTCLASS}"
    kubectl_retry "${action}" -f "${VOLUME_SNAPSHOT_CONTENT}"
    kubectl_retry "${action}" -f "${VOLUME_SNAPSHOT}"
    kubectl_retry "${action}" -f "${temp_snap_meta_svc}"
}

function create_or_delete_snapshot_controller() {
    local action=$1
    temp_rbac=${TEMP_DIR}/snapshot-rbac.yaml
    temp_snap_controller=${TEMP_DIR}/snapshot-controller.yaml

    curl -o "${temp_rbac}" "${SNAPSHOT_RBAC}"
    curl -o "${temp_snap_controller}" "${SNAPSHOT_CONTROLLER}"
    sed -i "s/namespace: kube-system/namespace: ${NAMESPACE}/g" "${temp_rbac}"
    sed -i "s/namespace: kube-system/namespace: ${NAMESPACE}/g" "${temp_snap_controller}"
    sed -i -E "s/(image: registry\.k8s\.io\/sig-storage\/snapshot-controller:).*$/\1$SNAPSHOT_VERSION/g" "${temp_snap_controller}"

    kubectl_retry "${action}" -f "${temp_rbac}"
    kubectl_retry "${action}" -f "${temp_snap_controller}" -n "${NAMESPACE}"

    if [ "${action}" == "delete" ]; then
        return 0
    fi

    pod_ready=$(kubectl get pods -l app.kubernetes.io/name=snapshot-controller -n "${NAMESPACE}" -o jsonpath='{.items[0].status.containerStatuses[0].ready}')
    INC=0
    until [[ "${pod_ready}" == "true" || $INC -gt 20 ]]; do
        sleep 10
        ((++INC))
        pod_ready=$(kubectl get pods -l app.kubernetes.io/name=snapshot-controller -n "${NAMESPACE}" -o jsonpath='{.items[0].status.containerStatuses[0].ready}')
        echo "snapshotter pod status: ${pod_ready}"
    done

    if [ "${pod_ready}" != "true" ]; then
        echo "snapshotter controller creation failed"
        kubectl get pods -l app.kubernetes.io/name=snapshot-controller -n "${NAMESPACE}"
        kubectl describe po -l app.kubernetes.io/name=snapshot-controller -n "${NAMESPACE}"
        exit 1
    fi

    echo "snapshot controller creation successful"
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
    address: csi-snapsot-metadata.csi-driver:6443
    caCert: "${generated_ca_cert}"
    audience: "csi-snapshot-metadata"
EOF
    kubectl_retry "${action}" -f "${temp_file}"
}

function create_or_delete_service_account() {
    local action=$1
    temp_sa=${TEMP_DIR}/service-account.yaml
    curl -o "${temp_sa}" "${SNAPSHOT_METADATA_SERVICE_ACCOUNT}"
    yq -i '.metadata.namespace = "default"' "${temp_sa}"
    kubectl_retry "${action}" -f "${temp_sa}"
}

function create_or_delete_cluster_role() {
    local action=$1
    kubectl_retry "${action}" -f "${SNAPSHOT_METADATA_CLUSTER_ROLE}"
}

function deploy_csi_hostpath_driver() {
    git clone https://github.com/kubernetes-csi/csi-driver-host-path.git ~/csi-driver-host-path
    # BELOW IMAGE is build from PR https://github.com/kubernetes-csi/csi-driver-host-path/pull/569
    # TODO: Replace with official image once it is released.
    HOSTPATHPLUGIN_REGISTRY="quay.io/mpraveen" HOSTPATHPLUGIN_TAG="cbt" ~/csi-driver-host-path/deploy/kubernetes-1.27/deploy.sh
}

function cleanup_csi_hostpath_driver() {
    ~/csi-driver-host-path/deploy/kubernetes-1.27/destroy.sh
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

    kubectl apply -f hostplugin.yaml
}

function create_or_delete_csi_driver_service() {
    local action=$1
    temp_svc=${TEMP_DIR}/service.yaml
    curl -o "${temp_svc}" "${SNAPSHOT_METADATA_DRIVER_SERVICE}"
    yq -i '.metadata.namespace = "default"' "${temp_svc}"
    yq -i '.spec.selector."app.kubernetes.io/name" = "csi-hostpathplugin"' "${temp_svc}"
    kubectl_retry "${action}" -f "${temp_svc}"
}

function deploy() {
    create_or_delete_crds "create"
    create_or_delete_snapshot_controller "create"
    provision_tls_certs
    create_or_delete_tls_certs "create"
    create_or_delete_service_account "create"
    create_or_delete_cluster_role "create"
    create_or_delete_snapshot_metadata_service "create"
    deploy_csi_hostpath_driver
    patch_snapshot_metadata_sidecar
    create_or_delete_csi_driver_service "create"

    kubectl_retry get all -n "${NAMESPACE}"
}

function cleanup() {
    create_or_delete_csi_driver_service "delete"
    cleanup_csi_hostpath_driver
    create_or_delete_snapshot_metadata_service "delete"
    create_or_delete_service_account "delete"
    create_or_delete_cluster_role "delete"
    create_or_delete_tls_certs "delete"
    create_or_delete_snapshot_controller "delete"
    create_or_delete_crds "delete"
}

case "${1:-}" in
deploy)
    deploy
    ;;
cleanup)
    cleanup
    ;;
*)
    echo "Usage: $0 {deploy|cleanup}"
    exit 1
    ;;
esac
