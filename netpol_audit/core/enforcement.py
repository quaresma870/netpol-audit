"""Active enforcement verification: confirms the cluster's CNI
actually enforces NetworkPolicy, not just that NetworkPolicy objects
exist and are well-formed. Some CNIs (and some CNI configurations)
silently accept NetworkPolicy objects without enforcing them at all --
a real, easy-to-miss gap the rest of this tool can't detect, since
everything else here audits the *declared* configuration via the
Kubernetes API, not actual enforced network behavior.

The approach: deploy a real client pod and a real server pod, apply a
deny-all ingress NetworkPolicy selecting the server, then actually try
to connect from the client to the server's pod IP. If the connection
succeeds anyway, the CNI isn't enforcing NetworkPolicy -- a CRITICAL
finding, since every other NetworkPolicy in the cluster is then
silently non-functional regardless of how well-formed it is.

Split the same way as netpol.py/cluster.py: `interpret_probe_result`
is pure and unit tested against fixture data; `run_enforcement_probe`
does the actual pod/policy/exec mechanics against a live cluster and
-- like cluster.py's live-fetching functions -- is only exercised
against a real `kind` cluster in CI, not in local unit tests.
"""

from __future__ import annotations

import random
import string
import time

PROBE_FAILURE_MARKER = "NETPOL_AUDIT_PROBE_BLOCKED"


def interpret_probe_result(connection_blocked: bool) -> dict | None:
    """Pure interpretation of a probe result. Returns a CRITICAL
    finding if a real connection succeeded despite a deny-all ingress
    NetworkPolicy being applied (the CNI isn't enforcing NetworkPolicy
    at all), or None if the connection was correctly blocked."""
    if connection_blocked:
        return None
    return {
        "severity": "CRITICAL",
        "title": "CNI does not enforce NetworkPolicy",
        "target": "cluster",
        "description": (
            "A deny-all ingress NetworkPolicy was applied to a real test pod, and a "
            "real connection from another pod succeeded anyway. This means the "
            "cluster's CNI is not enforcing NetworkPolicy at all -- every "
            "NetworkPolicy in this cluster, no matter how well-formed, is currently "
            "non-functional. (Some CNIs and CNI configurations don't enforce "
            "NetworkPolicy out of the box.)"
        ),
        "remediation": "Install or enable a NetworkPolicy-enforcing CNI (e.g. Calico, "
                        "Cilium, or a kind cluster configured with one) -- the CNI, not "
                        "Kubernetes itself, is responsible for actually enforcing "
                        "NetworkPolicy objects.",
    }


def _random_suffix(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _wait_for_pod_running(v1, namespace: str, name: str, timeout: int):
    deadline = time.time() + timeout
    pod = None
    while time.time() < deadline:
        pod = v1.read_namespaced_pod(name, namespace)
        if pod.status.phase == "Running" and pod.status.pod_ip:
            return pod
        time.sleep(1)
    raise TimeoutError(f"Pod {namespace}/{name} did not become Running with an IP within {timeout}s")


def _cleanup(v1, net_v1, namespace: str, server_name: str, client_name: str, policy_name: str,
             created_namespace: bool) -> None:
    from kubernetes import client as k8s_client

    if created_namespace:
        try:
            v1.delete_namespace(namespace)
        except k8s_client.ApiException:
            pass
        return

    for delete_fn in (
        lambda: net_v1.delete_namespaced_network_policy(policy_name, namespace),
        lambda: v1.delete_namespaced_pod(server_name, namespace),
        lambda: v1.delete_namespaced_pod(client_name, namespace),
    ):
        try:
            delete_fn()
        except k8s_client.ApiException:
            pass


def run_enforcement_probe(namespace: str | None = None, timeout: int = 60, keep: bool = False) -> dict | None:
    """Deploys a real client pod, a real server pod, and a deny-all
    ingress NetworkPolicy selecting the server, in the given namespace
    (a temporary namespace is created and deleted afterward if none is
    given), then actually attempts a connection from the client to the
    server's pod IP. Returns the CRITICAL finding from
    `interpret_probe_result` if the CNI isn't enforcing NetworkPolicy,
    or None if enforcement is confirmed working."""
    from kubernetes import client as k8s_client
    from kubernetes.stream import stream

    v1 = k8s_client.CoreV1Api()
    net_v1 = k8s_client.NetworkingV1Api()

    suffix = _random_suffix()
    created_namespace = namespace is None
    ns = namespace or f"netpol-audit-verify-{suffix}"
    server_name = f"netpol-audit-verify-server-{suffix}"
    client_name = f"netpol-audit-verify-client-{suffix}"
    policy_name = f"netpol-audit-verify-deny-all-{suffix}"
    probe_labels = {"netpol-audit-verify": suffix}

    try:
        if created_namespace:
            v1.create_namespace(k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(name=ns)))

        v1.create_namespaced_pod(ns, k8s_client.V1Pod(
            metadata=k8s_client.V1ObjectMeta(name=server_name, labels={**probe_labels, "role": "server"}),
            spec=k8s_client.V1PodSpec(containers=[k8s_client.V1Container(
                name="server", image="nginx:alpine", ports=[k8s_client.V1ContainerPort(container_port=80)],
            )]),
        ))
        v1.create_namespaced_pod(ns, k8s_client.V1Pod(
            metadata=k8s_client.V1ObjectMeta(name=client_name, labels={**probe_labels, "role": "client"}),
            spec=k8s_client.V1PodSpec(containers=[k8s_client.V1Container(
                name="client", image="busybox", command=["sleep", "3600"],
            )]),
        ))

        server_pod = _wait_for_pod_running(v1, ns, server_name, timeout)
        _wait_for_pod_running(v1, ns, client_name, timeout)
        server_ip = server_pod.status.pod_ip

        net_v1.create_namespaced_network_policy(ns, k8s_client.V1NetworkPolicy(
            metadata=k8s_client.V1ObjectMeta(name=policy_name),
            spec=k8s_client.V1NetworkPolicySpec(
                pod_selector=k8s_client.V1LabelSelector(match_labels={**probe_labels, "role": "server"}),
                policy_types=["Ingress"],
                ingress=[],
            ),
        ))
        # Give the CNI a moment to actually program the policy before probing --
        # irrelevant for a CNI that ignores NetworkPolicy entirely, but a real
        # enforcing CNI can take a few seconds to apply it.
        time.sleep(5)

        probe_cmd = ["sh", "-c", f"wget -q -T 5 -O - http://{server_ip}/ || echo {PROBE_FAILURE_MARKER}"]
        output = stream(
            v1.connect_get_namespaced_pod_exec, client_name, ns,
            command=probe_cmd, stderr=True, stdin=False, stdout=True, tty=False,
        )
        connection_blocked = PROBE_FAILURE_MARKER in output
        return interpret_probe_result(connection_blocked)
    finally:
        if not keep:
            _cleanup(v1, net_v1, ns, server_name, client_name, policy_name, created_namespace)
