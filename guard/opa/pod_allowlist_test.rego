package kubernetes.admission_test

import data.kubernetes.admission

test_allow_happy_path {
	admission.deny == set() with input as {"request": {
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "default",
		"object": {"spec": {
			"serviceAccountName": "banzaicloud",
			"containers": [{"image": "banzaicloud/pipeline"}],
			"nodeSelector": {"failure-domain.beta.kubernetes.io/region": "europe-west1"},
		}},
	}}
}

test_deny_bad_node_selector {
	admission.deny["pod with serviceAccount \"analytics\", image \"banzaicloud/allspark:0.1.2\" is not allowed at the specified location"] with input as 
    {"request": {
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "default",
		"object": {"spec": {
			"serviceAccountName": "analytics",
			"containers": [{"image": "banzaicloud/allspark:0.1.2"}],
			"nodeSelector": {"failure-domain.beta.kubernetes.io/region": "us-west2"},
		}},
	}}
}

test_deny_whitelisted_service_account_with_non_whitelisted_image {
	admission.deny["pod with serviceAccount \"analytics\", image \"banzaicloud/not-allowed-app\" is not allowed"] with input as {"request": {
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "default",
		"object": {"spec": {
			"serviceAccountName": "analytics",
			"containers": [
				{"image": "banzaicloud/allspark:0.1.2"},
				{"image": "banzaicloud/not-allowed-app"},
			],
		}},
	}}
}
