# Writing clauses to perform context\-aware evaluations<a name="context-aware-evaluations"></a>

AWS CloudFormation Guard clauses are evaluated against hierarchical data\. The Guard evaluation engine resolves queries against incoming data by following hierarchical data as specified, using a simple dotted notation\. Frequently, multiple clauses are needed to evaluate against a map of data or a collection\. Guard provides a convenient syntax to write such clauses\. The engine is contextually aware and uses the corresponding data associated for evaluations\.

The following is an example of a Kubernetes Pod configuration with containers, to which you can apply context\-aware evaluations\.

```
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

You can author Guard clauses to evaluate this data\. When evaluating a rules file, the context is the entire input document\. Following are example clauses that validate limits enforcement for containers specified in a Pod\.

```
#
# At this level, the root document is available for evaluation
#

#
# Our rule only evaluates for apiVersion == v1 and K8s kind is Pod
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
            >> 

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

## Understanding `context` in evaluations<a name="context"></a>

At the rule\-block level, the incoming context is the complete document\. Evaluations for the `when` condition happen against this incoming root context where the `apiVersion` and `kind` attributes are located\. In the previous example, these conditions evaluate to `true`\.

Now, traverse the hierarchy in `spec.containers[*]` shown in the preceding example\. For each traverse of the hierarchy, the context value changes accordingly\. After the traversal of the `spec` block is finished, the context changes, as shown in the following example\.

```
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

After traversing the `containers` attribute, the context is shown in the following example\.

```
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

## Understanding loops<a name="loops"></a>

You can use the expression `[*]` to define a loop for all values contained in the array for the `containers` attribute\. The block is evaluated for each element inside `containers`\. In the preceding example rule snippet, the clauses contained inside the block define checks to be validated against a container definition\. The block of clauses contained inside is evaluated twice, once for each container definition\.

```
{
    spec.containers[*] {
       ...
    }
}
```

For each iteration, the context value is the value at that corresponding index\.

**Note**  
The only index access format supported is `[<integer>]` or `[*]`\. Currently, Guard does not support ranges like `[2..4]`\.

## Arrays<a name="arrays"></a>

Often in places where an array is accepted, single values are also accepted\. For example, if there is only one container, the array can be dropped and the following input is accepted\.

```
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

If an attribute can accept an array, ensure that your rule uses the array form\. In the preceding example, you use `containers[*]` and not `containers`\. Guard evaluates correctly when traversing the data when it encounters only the single\-value form\.

**Note**  
Always use the array form when expressing access for a rule clause when an attribute accepts an array\. Guard evaluates correctly even in the case that a single value is used\.

## Using the form `spec.containers[*]` instead of `spec.containers`<a name="containers"></a>

Guard queries return a collection of resolved values\. When you use the form `spec.containers`, the resolved values for the query contain the array referred to by `containers`, not the elements inside it\. When you use the form `spec.containers[*]`, you refer to each individual element contained\. Remember to use the `[*]` form whenever you intend to evaluate each element contained in the array\.

## Using `this` to reference the current context value<a name="this"></a>

When you author a Guard rule, you can reference the context value by using `this`\. Often, `this` is implicit because it's bound to the context’s value\. For example, `this.apiVersion`, `this.kind`, and `this.spec` are bound to the root or document\. In contrast, `this.resources` is bound to each value for `containers`, such as `/spec/containers/0/` and `/spec/containers/1`\. Similarly, `this.cpu` and `this.memory` map to limits, specifically `/spec/containers/0/resources/limits` and `/spec/containers/1/resources/limits`\. 

In the next example, the preceding rule for the Kubernetes Pod configuration is rewritten to use `this` explicitly\.

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
            >> 

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

You don't need to use `this` explicitly\. However, the `this` reference can be useful when working with scalars, as shown in the following example\.

```
InputParameters.TcpBlockedPorts[*] {
    this in r[0, 65535) 
    <<
        result: NON_COMPLIANT
        message: TcpBlockedPort not in range (0, 65535)
    >>
}
```

In the previous example, `this` is used to refer to each port number\.

## Potential errors with the usage of implicit `this`<a name="common-errors"></a>

When authoring rules and clauses, there are some common mistakes when referencing elements from the implicit `this` context value\. For example, consider the following input datum to evaluate against \(this must pass\)\.

```
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

When tested against the preceding template, the following rule results in an error because it makes an incorrect assumption of leveraging the implicit `this`\.

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

To walk through this example, save the preceding rules file with the name `any_ip_ingress_check.guard` and the data with the file name `ip_ingress.yaml`\. Then, run the following `validate` command with these files\.

```
cfn-guard validate -r any_ip_ingress_check.guard -d ip_ingress.yaml --show-clause-failures
```

In the following output, the engine indicates that its attempt to retrieve a property `InputParameters.TcpBlockedPorts[*]` on the value `/configuration/ipPermissions/0`, `/configuration/ipPermissions/1` failed\.

```
Clause #2     FAIL(Block[Location[file:any_ip_ingress_check.guard, line:17, column:13]])

              Attempting to retrieve array index or key from map at Path = /configuration/ipPermissions/0, Type was not an array/object map, Remaining Query = InputParameters.TcpBlockedPorts[*]

Clause #3     FAIL(Block[Location[file:any_ip_ingress_check.guard, line:17, column:13]])

              Attempting to retrieve array index or key from map at Path = /configuration/ipPermissions/1, Type was not an array/object map, Remaining Query = InputParameters.TcpBlockedPorts[*]
```

To help understand this result, rewrite the rule using `this` explicitly referenced\.

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

`this.InputParameters` references each value contained inside the variable `any_ip_permissions`\. The query assigned to the variable selects `configuration.ipPermissions` values that match\. The error indicates an attempt to retrieve `InputParamaters` in this context, but `InputParameters` was in the root context\.

The inner block also references variables that are out of scope, as shown in the following example\.

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

`this` refers to each port value in `[21, 22, 110]`, but it also refers to `fromPort` and `toPort`\. They both belong to the outer block scope\.

### Resolving errors with the implicit use of `this`<a name="common-errors-resolution"></a>

Use variables to explicitly assign and reference values\. First, `InputParameter.TcpBlockedPorts` is part of the input \(root\) context\. Move `InputParameter.TcpBlockedPorts` out of the inner block and assign it explicitly, as shown in the following example\.

```
rule check_ip_procotol_and_port_range_validity
{
     let ports = InputParameters.TcpBlockedPorts[*]
    # ... cut off for illustrating change
}
```

Then, refer to this variable explicitly\.

```
rule check_ip_procotol_and_port_range_validity
{
    #
    # Important: Assigning InputParameters.TcpBlockedPorts results in an ERROR. 
    # We need to extract each port inside the array. The difference is the query
    # InputParameters.TcpBlockedPorts returns [[21, 20, 110]] whereas the query 
    # InputParameters.TcpBlockedPorts[*] returns [21, 20, 110]. 
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

Do the same for inner `this` references within `%ports`\.

However, all errors aren't fixed yet because the loop inside `ports` still has an incorrect reference\. The following example shows the removal of the incorrect reference\.

```
rule check_ip_procotol_and_port_range_validity
{
    #
    # Important: Assigning InputParameters.TcpBlockedPorts results in an ERROR. 
    # We need to extract each port inside the array. The difference is the query
    # InputParameters.TcpBlockedPorts returns [[21, 20, 110]] whereas the query 
    # InputParameters.TcpBlockedPorts[*] returns [21, 20, 110].
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

Next, run the `validate` command again\. This time, it passes\.

```
cfn-guard validate -r any_ip_ingress_check.guard -d ip_ingress.yaml --show-clause-failures
```

The following is the output of the `validate` command\.

```
Summary Report Overall File Status = PASS
PASS/SKIP rules
check_ip_procotol_and_port_range_validity    PASS
```

To test this approach for failures, the following example uses a payload change\.

```
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

90 is within the range from 89–109 that has any IPv6 address allowed\. The following is the output of the `validate` command after running it again\.

```
Clause #3           FAIL(Clause(Location[file:any_ip_ingress_check.guard, line:43, column:21], Check: _  LESS THAN %each_any_ip_perm.fromPort))
                    Comparing Int((Path("/InputParameters/TcpBlockedPorts/2"), 90)) with Int((Path("/configuration/ipPermissions/1/fromPort"), 89)) failed
                    (DEFAULT: NO_MESSAGE)
Clause #4           FAIL(Clause(Location[file:any_ip_ingress_check.guard, line:44, column:21], Check: _  GREATER THAN %each_any_ip_perm.toPort))
                    Comparing Int((Path("/InputParameters/TcpBlockedPorts/2"), 90)) with Int((Path("/configuration/ipPermissions/1/toPort"), 109)) failed

                                            result: NON_COMPLIANT
                                            check_id: HUB_ID_2340
                                            message: Blocked TCP port was allowed in range
```