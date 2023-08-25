# lzsigma

Simple Sigma rule parser

```go
package main

import (
	"flag"
	"fmt"

	lzsigma "github.com/nopfault/lzsigma"
)

func main() {

	var rule string

	flag.StringVar(&rule, "r", "", "Sigma rule file (required) [URL | FILE]")
	flag.Parse()

	var sigmaRule lzsigma.SigmaRule = lzsigma.SigmaRule{Source: rule}

	fmt.Println(sigmaRule.Parse())

}
```

Running it by

```bash
go run main.go -r https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/network/zeek/zeek_dce_rpc_mitre_bzar_execution.yml
```

Getting parset `SigmaRule` object:

```
{MITRE BZAR Indicators for Execution b640c0b8-87f8-4daa-aef8-95a24261dd1d test Windows DCE-RPC functions which indicate an execution techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE [] @neu5ron, SOC Prime 2020/03/19 2021/11/27 [attack.execution attack.t1047 attack.t1053.002 attack.t1569.002] {zeek dce_rpc} map[condition:1 of op* op1:map[endpoint:JobAdd operation:atsvc] op10:map[endpoint:svcctl operation:StartServiceW] op2:map[endpoint:ITaskSchedulerService operation:SchRpcEnableTask] op3:map[endpoint:ITaskSchedulerService operation:SchRpcRegisterTask] op4:map[endpoint:ITaskSchedulerService operation:SchRpcRun] op5:map[endpoint:IWbemServices operation:ExecMethod] op6:map[endpoint:IWbemServices operation:ExecMethodAsync] op7:map[endpoint:svcctl operation:CreateServiceA] op8:map[endpoint:svcctl operation:CreateServiceW] op9:map[endpoint:svcctl operation:StartServiceA]] [Windows administrator tasks or troubleshooting Windows management scripts or software] medium}
```



