#!/bin/bash
echo "Policy Validator [beta v1]"
echo "1. Validate KubeArmor Policy"
echo "2. Validate Cilium Policy"
echo -n "Enter your choice [1/2]: "
read choice

#simple function to show progress bar 
progressBar() {

	loopBreak=0
	j=1
	sp="/-\|"
	echo -n " "
	while [ true ]
	do 
	  echo -ne  "\b\r${sp:j++%${#sp}:1}"
	  sleep 0.1
	  ((loopBreak++))
	  if [[ 'loopBreak' -ge 200 ]]
	  then
	  	break 
	  fi
	done
	echo -ne "\r "
}

#reads the kubearmor security policies from all namespaces and call respective functions for network,process, etc
readKSP() {
	kspName=$(kubectl get ksp -A -o=jsonpath='{.items['$i'].metadata.name}')
	kspNameSpace=$(kubectl get ksp -A -o=jsonpath='{.items['$i'].metadata.namespace}')
	progressBar
	
	if [[ ! -z $(kubectl get ksp -A -o=jsonpath='{.items['$i'].spec.process}') ]]
    then
    	#kubectl get ksp -A -o=jsonpath='{.items['$i'].spec}'
        processKSP $kspName $kspNameSpace 
    elif [[ ! -z $(kubectl get ksp -A -o=jsonpath='{.items['$i'].spec.capabilities}') ]]
    then
    	#kubectl get ksp -A -o=jsonpath='{.items['$i'].spec}'
        capabilitiesKSP $kspName $kspNameSpace 
    elif [[ ! -z $(kubectl get ksp -A -o=jsonpath='{.items['$i'].spec.network}') ]]
    then
    	#kubectl get ksp -A -o=jsonpath='{.items['$i'].spec}'
        networkKSP $kspName $kspNameSpace 
    elif [[ ! -z $(kubectl get ksp -A -o=jsonpath='{.items['$i'].spec.file}') ]]
    then
    	#kubectl get ksp -A -o=jsonpath='{.items['$i'].spec}'
        fileKSP $kspName $kspNameSpace 
    else
    	echo "Unknown Error. Gracefully Exiting program"
    	exit 2
    fi
}

#main function for KSP with rule: process 
processKSP() {
	echo
	action=$(kubectl -n $kspNameSpace get ksp $kspName -o=jsonpath='{.spec.process.action}')
	echo $action
	labelNumber=$(kubectl -n $kspNameSpace get ksp $kspName -o=jsonpath='{.spec.selector.matchLabels}' | awk -F"{" '{print NF-1}')
	#echo $labelNumber
	for ((ilabel=0;ilabel<labelNumber;ilabel++)) 
	do
		labelVal=$(kubectl -n $kspNameSpace get ksp $kspName -o=jsonpath='{.spec.selector.matchLabels}' | sed 's/"//g' | sed 's/:/=/g' | cut -d '{' -f2 | cut -d '}' -f1)
		if [[ 'ilabel + 1' -ge labelNumber ]]
    	then
        	true
    	else
        	labelVal=labelVal+","
    	fi
	done
	#echo $labelVal
	kubectl -n $kspNameSpace get ksp $kspName
	if [[ ! -z $(kubectl -n $kspNameSpace get ksp $kspName -o=jsonpath='{.spec.process.matchPaths}') ]]
	then
		processPathKSP $kspName $kspNameSpace $labelVal $action
	elif [[ ! -z $(kubectl -n $kspNameSpace get ksp $kspName -o=jsonpath='{.spec.process.matchDirectories}') ]]
    then
    	#kubectl get ksp -A -o=jsonpath='{.items['$i'].spec}'
        processDirKSP $kspName $kspNameSpace $labelVal $action
    else
    	echo "Unknown Error."
    fi
	
	
}


#sub function for process, rule matchPaths
processPathKSP() {
	echo
	pathNumber=$(kubectl -n $kspNameSpace get ksp $kspName -o=jsonpath='{.spec.process.matchPaths}' | awk -F"{" '{print NF-1}')
	#echo $pathNumber

	pathVal=$(kubectl -n $kspNameSpace get ksp $kspName -o=jsonpath='{.spec.process.matchPaths}' | cut -d ':' -f2 | cut -d '}' -f1 | sed 's/"//g')
	#echo $pathVal
	#nodeName=$(kubectl -n $kspNameSpace get pod -o wide -l$labelVal -o=jsonpath='{.spec.nodeName}')
	#echo $nodeName
	#kubectl -n $kspNameSpace get pod -o wide -l$labelVal

	resultVal=$(kubectl -n $kspNameSpace exec -it $(kubectl -n $kspNameSpace get pod -l$labelVal -o name | cut -d / -f 2) -- bash -c "$pathVal" 2>/dev/null) 
	echo $resultVal
	if [ "$action" = "Block" ]
	then
		if [[ $resultVal == *"Permission denied"* ]]
		then
			echo "Access to process $pathVal is denied"
    		echo "Policy $kspName ($kspNameSpace) is validated successfully"
		else
    		echo "Access to process $pathVal is granted"
    		echo "Policy $kspName ($kspNameSpace) failed"
		fi
	fi

}

processDirKSP() {
	echo
	dirNumber=$(kubectl -n $kspNameSpace get ksp $kspName -o=jsonpath='{.spec.process.matchDirectories}' | awk -F"{" '{print NF-1}')
	#echo $dirNumber

	dirVal=$(kubectl -n $kspNameSpace get ksp $kspName -o=jsonpath='{.spec.process.matchDirectories}' | cut -d ':' -f2 | cut -d '}' -f1 | sed 's/"//g')
	echo $dirVal
	#nodeName=$(kubectl -n $kspNameSpace get pod -o wide -l$labelVal -o=jsonpath='{.spec.nodeName}')
	#echo $nodeName
	#kubectl -n $kspNameSpace get pod -o wide -l$labelVal

	resultVal=$(kubectl -n $kspNameSpace exec -it $(kubectl -n $kspNameSpace get pod -l$labelVal -o name | cut -d / -f 2) -- bash -c "ls $dirVal |  shuf -n 1" 2>/dev/null) 
	echo $resultVal
	if [ "$action" = "Block" ]
	then
		if [[ $resultVal == *"Permission denied"* ]]
		then
			echo "Access to directory $dirVal is denied"
    		echo "Policy $kspName ($kspNameSpace) is validated successfully"
		else
    		echo "Access to directory $dirVal is granted"
    		echo "Policy $kspName ($kspNameSpace) failed"
		fi
	fi

}



fileKSP() {
	echo
	echo $kspName $kspNameSpace 
	echo "file invoked"

}
capabilitiesKSP() {
	echo
	echo $kspName $kspNameSpace 
	echo "capabilities invoked"

}
networkKSP() {
	echo
	echo $kspName $kspNameSpace 
	echo "network invoked"

}


createTestCase() {

	echo $policy | jq '.items[]'
	if [[ ! -z $(echo $policy | jq '.items[].spec.file') ]]
	then
		echo "it worked"
	else
		echo "oh no"
	fi
}

if [ $choice == 1 ]
then
	echo  "Reading KubeArmor Policies from Cluster"
	countKSP=$(kubectl get ksp -A | wc -l)
	countKSP=$(expr $countKSP - 1 )
	echo "Found $countKSP KubeArmor Security Policies"
	echo "Generating TestCases... Please wait "
	for ((i=0;i<countKSP;i++)) 
	do
		#echo $i
		readKSP $i 
	done

else
	echo  "Reading Cilium Policies from Cluster. Please wait"
fi

