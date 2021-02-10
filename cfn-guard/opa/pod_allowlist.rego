package kubernetes.admission

allowlist = [
	{
		"serviceAccount": "analytics",
		"images": {"banzaicloud/allspark:0.1.2", "banzaicloud/istio-proxyv2:1.7.0-bzc"},
		# possible nodeSelector combinations we allow, the pod can have more nodeSelectors of course
		"nodeSelector": [{"failure-domain.beta.kubernetes.io/region": "europe-west1"}],
		# "nodeSelector": [],
	},
]

deny[msg] {
	input.request.kind.kind == "Pod"
	input.request.operation == "CREATE"

	serviceAccount := input.request.object.spec.serviceAccountName

	# check whether the service account is restricted
	allowlist[a].serviceAccount == serviceAccount

	# check whether pod location is restricted
	count(allowlist[a].nodeSelector[ns]) > 0

	image := input.request.object.spec.containers[_].image
	nodeSelector := object.get(input.request.object.spec, "nodeSelector", [])

	# check whether pod location is allowed
	not podAtLocationAllowed(serviceAccount, nodeSelector)

	msg := sprintf("pod with serviceAccount %q, image %q is not allowed at the specified location", [serviceAccount, image])
}

deny[msg] {
	input.request.kind.kind == "Pod"
	input.request.operation == "CREATE"

	serviceAccount := input.request.object.spec.serviceAccountName

	# check whether the service account is restricted
	allowlist[a].serviceAccount == serviceAccount
	
	image := input.request.object.spec.containers[_].image

	# check whether the pod images allowed to run with the specified service account
	not imageWithServiceAccountAllowed(serviceAccount, image)

	msg := sprintf("pod with serviceAccount %q, image %q is not allowed", [serviceAccount, image])
}

imageWithServiceAccountAllowed(serviceAccount, image) {
	allowlist[a].serviceAccount == serviceAccount
	allowlist[a].images[image]
}

podAtLocationAllowed(serviceAccount, nodeSelector) {
	allowlist[a].serviceAccount == serviceAccount

	# requires that at least one nodeSelector combination matches this image and serviceAccount combination
	selcount := count(allowlist[a].nodeSelector[ns])
	count({k | allowlist[a].nodeSelector[s][k] == nodeSelector[k]}) == selcount
}
