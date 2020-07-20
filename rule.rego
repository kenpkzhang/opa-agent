package opa_cdk

import input 

# deny if it creates more than 10 EC2 instances
deny_too_many_ec2 {                             
    instances := [res | res:=input.Resources[_]; res.Type == "AWS::EC2::Instance"]   
    count(instances) > 10 
}

# deny if ssh is enabled
deny_ssh_enabled {                             
    input.Resources[_].Properties.SecurityGroupIngress[_].ToPort == 22
}

