# Guard: Context-Aware Evaluations, `this` and Loops

Guard clauses are evaluated against hierarchical data. The Guard evaluation engine resolves queries against incoming data by following hierarchical data as specified using a [simple dotted notation](QUERY_AND_FILTERING.md). Oftentimes, multiple clauses are needed to evaluate against a map of data or a collection. Guard provides a convenient syntax to write such clauses. The engine is contextually aware and uses the corresponding data associated for evaluations.

The following is a Kubernetes Pod configuration with containers, to which you will apply context-aware evaluations on the configuration:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
spec:
  containers:
    - name: app
      image: 'images.my-company.example/app:v4'
      resources:
        requests:
          memory: 64Mi
          cpu: 0.25
        limits:
          memory: 128Mi
          cpu: 0.5
    - name: log-aggregator
      image: 'images.my-company.example/log-aggregator:v6'
      resources:
        requests:
          memory: 64Mi
          cpu: 0.25
        limits:
          memory: 128Mi
          cpu: 0.75
```

You can author Guard clauses to evaluate this data. When evaluating a `.guard` rules file, the `context` is the entire input document. Let’s look at some sample clauses to validate `limits` enforcement for `containers` specified in a `Pod`:

```
#
# At this level the root document is available for evaluation
#

#
# Our rule evaluates only for apiVersion == v1, and K8s kind is Pod
#
rule ensure_container_limits_are_enforced
    when apiVersion == 'v1'
        kind == 'Pod' 
{
    spec.containers[*] {
        resources.limits {
            #
            # Ensure that cpu attribute is set
            #
            cpu exists
            <<
                Id: K8S_REC_18
                Description: CPU limit must be set for the container
            >> # yes this YAML formatted output messaging

            #
            # Ensure that memory attribute is set
            #
            memory exists
            <<
                Id: K8S_REC_22
                Description: Memory limit must be set for the container
            >>
        }
    }
}
```

## Understanding `context` in Evaluations

At the `rule` block level, the incoming context is the complete document. Evaluations for the `when` condition happen against this incoming root `context` where `apiVersion` and `kind` attributes are located. In the previous example, these conditions evaluate to true. 

Let’s go ahead and traverse the hierarchy in `spec.containers[*]` shown in the example above. Every time we traverse the hierarchy, the `context` value changes accordingly. Once we finish traversing the `spec` block, the `context` now changes to:

```yaml
containers:
  - name: app
    image: 'images.my-company.example/app:v4'
    resources:
      requests:
        memory: 64Mi
        cpu: 0.25
      limits:
        memory: 128Mi
        cpu: 0.5
  - name: log-aggregator
    image: 'images.my-company.example/log-aggregator:v6'
    resources:
      requests:
        memory: 64Mi
        cpu: 0.25
      limits:
        memory: 128Mi
        cpu: 0.75
```

Next, let’s traverse the `containers` attribute; the new context now is:

```yaml
- name: app
  image: 'images.my-company.example/app:v4'
  resources:
    requests:
      memory: 64Mi
      cpu: 0.25
    limits:
      memory: 128Mi
      cpu: 0.5
- name: log-aggregator
  image: 'images.my-company.example/log-aggregator:v6'
  resources:
    requests:
      memory: 64Mi
      cpu: 0.25
    limits:
      memory: 128Mi
      cpu: 0.75
```

## Understanding Loops

You use the expression `[*]` to define a loop for all values contained in the array for the `containers` attribute. The block is evaluated for each element inside `containers` value. In this example rule snippet shown the clauses contained inside the block defines checks to be validated against a container definition. The block of clauses contained inside is evaluated twice, once for each container definition:

```
{
    spec.containers[*] {
       ...
    }
}
```

For each iteration, the `context` value is the value at that the corresponding index.


> **NOTE**: the only index access format supported is `[<integer>]` or `[*]`. Currently, we do not support ranges like `[2..4]`. 


## To Be or Not to be an Array

Often in places where an array is accepted, single values are allowed as well. For example, if there was only one container, the array can be dropped and the input accepted can be:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
spec:
  containers:
    name: app
    image: images.my-company.example/app:v4
    resources:
      requests:
        memory: "64Mi"
        cpu: 0.25
      limits:
        memory: "128Mi"
        cpu: 0.5
```

If an attribute can accept an array, ensure that your rule is using the array form. In this example, you use `containers[*]` and not `containers`. Guard will evaluate correctly when traversing the data when it encounters only the single value form.


> **PRO TIP**: always use the array form when expressing access for a rule clause when an attribute accepts an array. Guard will evaluate correctly even in the case when a single value is used.


### Why use `spec.containers[*]`, not just `spec.containers`?

Guard has the notion of queries that return a collection of resolved values. When you use the form `spec.containers` the resolved values for this query will contain the array referred to by `containers` not the elements inside it. When you use the form `spec.containers[*]` you refer to each individual element contained. Remember to use `[*]` form whenever you intend for each element contained in the array.

## Using `this` for referencing current context value

When you author a Guard rule, the `context` value can be referenced using `this`. Most of the time, `this` is implicit, as it is bound to the context’s value. For example, **`this.`**`apiVersion`**, `this.`**`kind` and **`this.`**`spec` are bound to the root `/` document; **`this.`**`resources` is bound to each value for `containers`, such as `/spec/containers/0/` and `/spec/containers/1`. Similarly, **`this.`**`cpu` and **`this.`**`memory` map to `limits`, specifically `/spec/containers/0/resources/limits` and `/spec/containers/1/resources/limits`. In the next example, you rewrite the rule shown above for the Kubernetes Pod configuration, and you will use `this` explicitly:

```
rule ensure_container_limits_are_enforced
    when this.apiVersion == 'v1'
         this.kind == 'Pod' 
{
    this.spec.containers[*] {
        this.resources.limits {
            #
            # Ensure that cpu attribute is set
            #
            this.cpu exists
            <<
                Id: K8S_REC_18
                Description: CPU limit must be set for the container
            >> # yes this is YAML formatted output messaging

            #
            # Ensure that memory attribute is set
            #
            this.memory exists
            <<
                Id: K8S_REC_22
                Description: Memory limit must be set for the container
            >>
        }
    }
}
```

You do not need to use `this` explicitly, but occasionally the `this` reference can be useful when working with scalars. For example:

```
InputParameters.TcpBlockedPorts[*] {
    this in r[0, 65535) 
    <<
        result: NON_COMPLIANT
        message: TcpBlockedPort not in range (0, 65535)
    >>
}
```

In the previous example, the `this` reference is used to refer to each port number.

## Errors one might Encounter with the Usage of Implicit `this` (especially double loops)

When authoring rules and clauses, there are mistakes that happen when referencing elements from the implicit `this` context value. For example, consider the following input datum that you will evaluate against (this must `PASS`):

```yaml
resourceType: 'AWS::EC2::SecurityGroup'
InputParameters:
  TcpBlockedPorts: [21, 22, 110]
configuration:
  ipPermissions:
  - fromPort: 172
    ipProtocol: tcp
    ipv6Ranges: []
    prefixListIds: []
    toPort: 172
    userIdGroupPairs: []
    ipv4Ranges:
      - cidrIp: "0.0.0.0/0"   
  - fromPort: 89
    ipProtocol: tcp
    ipv6Ranges:
      - cidrIpv6: "::/0"
    prefixListIds: []
    toPort: 109
    userIdGroupPairs: []
    ipv4Ranges:
      - cidrIp: 10.2.0.0/24
```

The following rule when tested against the template above results in an error, as it makes use of an incorrect assumption of leveraging the implicit `this`:

```
rule check_ip_procotol_and_port_range_validity
{
    # 
    # select all ipPermission instances that can be reached by ANY IP address
    # IPv4 or IPv6 and not UDP
    #
    let any_ip_permissions = configuration.ipPermissions[ 
        some ipv4Ranges[*].cidrIp == "0.0.0.0/0" or
        some ipv6Ranges[*].cidrIpv6 == "::/0"

        ipProtocol != 'udp' ]
    
    when %any_ip_permissions !empty
    {
        %any_ip_permissions {
            ipProtocol != '-1' # this here refers to each ipPermission instance
            InputParameters.TcpBlockedPorts[*] {
                fromPort > this or 
                toPort   < this 
                <<
                    result: NON_COMPLIANT
                    message: Blocked TCP port was allowed in range
                >>
            }                
        }
    }
}
```

If you save this rules file `any_ip_ingress_check.guard`, and the data in `ip_ingress.yaml` you can follow along. Let us run this via validate `cfn-guard validate -r any_ip_ingress_check.guard -d ip_ingress.yaml --show-clause-failures`. Here is what you will see in the output

```bash
Clause #2     FAIL(Block[Location[file:any_ip_ingress_check.guard, line:17, column:13]])

              Attempting to retrieve array index or key from map at Path = /configuration/ipPermissions/0, Type was not an array/object map, Remaining Query = InputParameters.TcpBlockedPorts[*]

Clause #3     FAIL(Block[Location[file:any_ip_ingress_check.guard, line:17, column:13]])

              Attempting to retrieve array index or key from map at Path = /configuration/ipPermissions/1, Type was not an array/object map, Remaining Query = InputParameters.TcpBlockedPorts[*]
```

The engine indicates that its attempt to retrieve a property `InputParameters.TcpBlockedPorts[*]` on the value `/configuration/ipPermissions/0`, `/configuration/ipPermissions/1` failed. To understand this better, let us rewrite the rule above using this explicitly referenced.

```
rule check_ip_procotol_and_port_range_validity
{
    # 
    # select all ipPermission instances that can be reached by ANY IP address
    # IPv4 or IPv6 and not UDP
    #
    let any_ip_permissions = this.configuration.ipPermissions[ 
        some ipv4Ranges[*].cidrIp == "0.0.0.0/0" or
        some ipv6Ranges[*].cidrIpv6 == "::/0"

        ipProtocol != 'udp' ]
    
    when %any_ip_permissions !empty
    {
        %any_ip_permissions {
            this.ipProtocol != '-1' # this here refers to each ipPermission instance
            this.InputParameters.TcpBlockedPorts[*] {
                this.fromPort > this or 
                this.toPort   < this 
                <<
                    result: NON_COMPLIANT
                    message: Blocked TCP port was allowed in range
                >>
            }                
        }
    }
}
```

`this` next to `InputParameters` references to each value contained inside variable `any_ip_permissions`. The query assigned to the variable selects `configuration.ipPermissions` values that match. The error indicates that we are attempting to retrieve `InputParamaters` in this context but `InputParameters` was on the root context.

The same is true for the inner block:

```
{
    this.ipProtocol != '-1' # this here refers to each ipPermission instance
    this.InputParameter.TcpBlockedPorts[*] { # ERROR referencing InputParameter off /configuration/ipPermissions[*]
        this.fromPort > this or # ERROR: implicit this refers to values inside /InputParameter/TcpBlockedPorts[*]
        this.toPort   < this 
        <<
            result: NON_COMPLIANT
            message: Blocked TCP port was allowed in range
        >>
    }
}
```

`this` refers to each port value in `[21, 22, 110]`, but we are also using it to refer to `fromPort`, and `toPort`. They both belong to the outer block scope.

### How do you deal with this?

Using variables to explicitly assign and reference them. First `InputParameter.TcpBlockedPorts`, is part of input/root context. We should therefore move this out of the inner block and assign it explicitly: 

```
rule check_ip_procotol_and_port_range_validity
{
     let ports = InputParameters.TcpBlockedPorts[*]
    # ... cut off for illustrating change
}
```

You can then refer to this variable explicitly:

```
rule check_ip_procotol_and_port_range_validity
{
    #
    # Important: it would be an ERROR to just assign InputParameters.TcpBlockedPorts
    # as we need to extract each port inside the array. The difference is the query
    # InputParameters.TcpBlockedPorts returns [[21, 20, 110]] vs. the query 
    # InputParameters.TcpBlockedPorts[*] return [21, 20, 110]. See section 
    # on Queries and Filters for detailed explanation 
    #
    let ports = InputParameters.TcpBlockedPorts[*]

    # 
    # select all ipPermission instances that can be reached by ANY IP address
    # IPv4 or IPv6 and not UDP
    #
    let any_ip_permissions = configuration.ipPermissions[ 
        some ipv4Ranges[*].cidrIp == "0.0.0.0/0" or
        some ipv6Ranges[*].cidrIpv6 == "::/0"

        ipProtocol != 'udp' ]
    
    when %any_ip_permissions !empty
    {
        %any_ip_permissions {
            this.ipProtocol != '-1' # this here refers to each ipPermission instance
            %ports {
                this.fromPort > this or 
                this.toPort   < this 
                <<
                    result: NON_COMPLIANT
                    message: Blocked TCP port was allowed in range
                >>
            }
        }
    }        
}
```

Let’s do the same for inner `this` references within `%ports`: 

This still does not completely fix all errors, the loop inside ports still has an incorrect reference. We need to fix that was well.

```
rule check_ip_procotol_and_port_range_validity
{
    #
    # Important: it would be an ERROR to just assign InputParameters.TcpBlockedPorts
    # as we need to extract each port inside the array. The difference is the query
    # InputParameters.TcpBlockedPorts returns [[21, 20, 110]] vs. the query 
    # InputParameters.TcpBlockedPorts[*] returns [21, 20, 110]. See section 
    # on Queries and Filters for detailed explanation 
    #
    let ports = InputParameters.TcpBlockedPorts[*]

    # 
    # select all ipPermission instances that can be reached by ANY IP address
    # IPv4 or IPv6 and not UDP
    #
    let any_ip_permissions = configuration.ipPermissions[
        #
        # if either ipv4 or ipv6 that allows access from any address
        #
        some ipv4Ranges[*].cidrIp == '0.0.0.0/0' or
        some ipv6Ranges[*].cidrIpv6 == '::/0'

        #
        # the ipProtocol is not UDP
        #
        ipProtocol != 'udp' ]
        
    when %any_ip_permissions !empty
    {
        %any_ip_permissions {
            ipProtocol != '-1'
            <<
              result: NON_COMPLIANT
              check_id: HUB_ID_2334
              message: Any IP Protocol is allowed
            >>

            when fromPort exists 
                 toPort exists 
            {
                let each_any_ip_perm = this
                %ports {
                    this < %each_any_ip_perm.fromPort or
                    this > %each_any_ip_perm.toPort
                    <<
                        result: NON_COMPLIANT
                        check_id: HUB_ID_2340
                        message: Blocked TCP port was allowed in range
                    >>
                }
            }
        }       
    }   
}
```

Let us try another run with this file against the payload `cfn-guard validate -r any_ip_ingress_check.guard -d ip_ingress.yaml --show-clause-failures`, you should see it `PASS`

```bash
Summary Report Overall File Status = PASS
PASS/SKIP rules
check_ip_procotol_and_port_range_validity    PASS
```

Does it work for `FAIL`ure case? Let us give it a try with the following payload change 

```yaml
resourceType: 'AWS::EC2::SecurityGroup'
InputParameters:
  TcpBlockedPorts: [21, 22, 90, 110]
configuration:
  ipPermissions:
    - fromPort: 172
      ipProtocol: tcp
      ipv6Ranges: []
      prefixListIds: []
      toPort: 172
      userIdGroupPairs: []
      ipv4Ranges:
        - cidrIp: "0.0.0.0/0"   
    - fromPort: 89
      ipProtocol: tcp
      ipv6Ranges:
        - cidrIpv6: "::/0"
      prefixListIds: []
      toPort: 109
      userIdGroupPairs: []
      ipv4Ranges:
        - cidrIp: 10.2.0.0/24
```

`90` is within the range from `89 - 109` that has any IPv6 address allowed. Rerun the command `cfn-guard validate -r any_ip_ingress_check.guard -d ip_ingress_FAIL.yaml --show-clause-failures`, you should see 

```bash
Clause #3           FAIL(Clause(Location[file:any_ip_ingress_check.guard, line:43, column:21], Check: _  LESS THAN %each_any_ip_perm.fromPort))
                    Comparing Int((Path("/InputParameters/TcpBlockedPorts/2"), 90)) with Int((Path("/configuration/ipPermissions/1/fromPort"), 89)) failed
                    (DEFAULT: NO_MESSAGE)
Clause #4           FAIL(Clause(Location[file:any_ip_ingress_check.guard, line:44, column:21], Check: _  GREATER THAN %each_any_ip_perm.toPort))
                    Comparing Int((Path("/InputParameters/TcpBlockedPorts/2"), 90)) with Int((Path("/configuration/ipPermissions/1/toPort"), 109)) failed

                                            result: NON_COMPLIANT
                                            check_id: HUB_ID_2340
                                            message: Blocked TCP port was allowed in range
```