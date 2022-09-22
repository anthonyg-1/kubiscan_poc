#!/bin/bash

func_dependencies () {
	sudo apt update && apt upgrade -y

	sudo apt install docker.io -y

	sudo systemctl enable docker

	sudo systemctl start docker
	
	func_install_kubectl
}

func_install_kubectl () {
	curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

	sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

	kubectl version --client
	
	func_install_minikube
}

func_install_minikube () {
	curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube_latest_amd64.deb

	sudo dpkg -i minikube_latest_amd64.deb && sudo usermod -aG docker $USER && newgrp docker

	func_download_kubiscan_kubigoat
}

func_download_kubiscan_kubigoat () {
	git clone https://github.com/madhuakula/kubernetes-goat.git && git clone https://github.com/cyberark/KubiScan.git

	touch token_creation.txt

	echo "cat << EOF | kubectl create -f -

	apiVersion: v1

	kind: Secret

	metadata:

	  name: secret_name

	  annotations:

	    kubernetes.io/service-account.name: service_account_name

	type: kubernetes.io/service-account-token

	EOF" >> token_creation.txt

	
	touch commands.txt

	echo "alias kubiscan='python3 /home/ubuntu/KubiScan/KubiScan.py'" >> commands.txt

}


func_dependencies
