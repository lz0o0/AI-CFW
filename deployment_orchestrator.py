#!/usr/bin/env python3
"""
CFW防火墙系统自动化部署工具

支持多种部署环境：
1. 物理服务器部署
2. 虚拟机部署  
3. Docker容器部署
4. 云平台部署
5. 边缘设备部署
"""

import os
import sys
import json
import platform
import subprocess
import ipaddress
import socket
from pathlib import Path
from enum import Enum

class DeploymentType(Enum):
    """部署类型枚举"""
    PHYSICAL = "physical"      # 物理服务器
    VIRTUAL = "virtual"        # 虚拟机
    DOCKER = "docker"          # Docker容器
    KUBERNETES = "kubernetes"  # Kubernetes集群
    CLOUD_AWS = "aws"          # AWS云平台
    CLOUD_AZURE = "azure"      # Azure云平台
    CLOUD_GCP = "gcp"          # Google Cloud Platform
    EDGE = "edge"              # 边缘设备

class NetworkMode(Enum):
    """网络模式枚举"""
    BRIDGE = "bridge"          # 桥接模式
    ROUTER = "router"          # 路由模式
    TRANSPARENT = "transparent" # 透明代理
    HOST = "host"              # 主机模式

class CFWDeploymentOrchestrator:
    """CFW部署编排器"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.deployment_config = {}
        self.system_info = self._gather_system_info()
        
    def _gather_system_info(self):
        """收集系统信息"""
        info = {
            "os": platform.system(),
            "os_version": platform.release(),
            "architecture": platform.machine(),
            "python_version": sys.version,
            "cpu_count": os.cpu_count(),
            "hostname": socket.gethostname()
        }
        
        # 检测虚拟化环境
        info["is_virtual"] = self._detect_virtualization()
        
        # 检测容器环境
        info["is_container"] = self._detect_container()
        
        # 检测云平台
        info["cloud_platform"] = self._detect_cloud_platform()
        
        return info
    
    def _detect_virtualization(self):
        """检测虚拟化环境"""
        try:
            # 检查常见虚拟化标识
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read()
                    if any(vendor in cpuinfo.lower() for vendor in ["vmware", "virtualbox", "kvm", "xen"]):
                        return True
            
            # 检查DMI信息
            if os.path.exists("/sys/class/dmi/id/product_name"):
                with open("/sys/class/dmi/id/product_name", "r") as f:
                    product = f.read().strip().lower()
                    if any(vm in product for vm in ["vmware", "virtualbox", "kvm", "virtual"]):
                        return True
                        
            return False
        except:
            return False
    
    def _detect_container(self):
        """检测容器环境"""
        # 检查Docker环境
        if os.path.exists("/.dockerenv"):
            return "docker"
        
        # 检查Kubernetes环境
        if os.environ.get("KUBERNETES_SERVICE_HOST"):
            return "kubernetes"
        
        # 检查cgroup
        try:
            with open("/proc/1/cgroup", "r") as f:
                cgroup = f.read()
                if "docker" in cgroup or "containerd" in cgroup:
                    return "docker"
        except:
            pass
        
        return None
    
    def _detect_cloud_platform(self):
        """检测云平台"""
        try:
            # AWS检测
            if self._check_metadata_service("http://169.254.169.254/latest/meta-data/"):
                return "aws"
            
            # Azure检测
            if self._check_metadata_service("http://169.254.169.254/metadata/instance?api-version=2021-02-01"):
                return "azure"
            
            # GCP检测
            if self._check_metadata_service("http://metadata.google.internal/computeMetadata/v1/"):
                return "gcp"
                
        except:
            pass
        
        return None
    
    def _check_metadata_service(self, url):
        """检查云平台元数据服务"""
        try:
            import urllib.request
            urllib.request.urlopen(url, timeout=2)
            return True
        except:
            return False
    
    def recommend_deployment_type(self):
        """推荐部署类型"""
        print("🔍 分析系统环境...")
        print(f"操作系统: {self.system_info['os']} {self.system_info['os_version']}")
        print(f"架构: {self.system_info['architecture']}")
        print(f"CPU核心: {self.system_info['cpu_count']}")
        
        recommendations = []
        
        # 基于环境特征推荐
        if self.system_info["cloud_platform"]:
            recommendations.append({
                "type": f"cloud_{self.system_info['cloud_platform']}",
                "reason": f"检测到{self.system_info['cloud_platform'].upper()}云环境",
                "priority": 1
            })
        
        if self.system_info["is_container"] == "docker":
            recommendations.append({
                "type": "docker",
                "reason": "检测到Docker容器环境",
                "priority": 2
            })
        
        if self.system_info["is_container"] == "kubernetes":
            recommendations.append({
                "type": "kubernetes", 
                "reason": "检测到Kubernetes集群环境",
                "priority": 1
            })
        
        if self.system_info["is_virtual"]:
            recommendations.append({
                "type": "virtual",
                "reason": "检测到虚拟化环境",
                "priority": 3
            })
        else:
            recommendations.append({
                "type": "physical",
                "reason": "检测到物理服务器环境",
                "priority": 3
            })
        
        # 基于硬件性能推荐
        if self.system_info["cpu_count"] <= 2:
            recommendations.append({
                "type": "edge",
                "reason": "CPU核心数较少，适合边缘部署",
                "priority": 4
            })
        
        # 排序推荐
        recommendations.sort(key=lambda x: x["priority"])
        
        print("\n📋 推荐的部署方式:")
        for i, rec in enumerate(recommendations[:3], 1):
            print(f"{i}. {rec['type']}: {rec['reason']}")
        
        return recommendations[0]["type"] if recommendations else "physical"
    
    def configure_deployment(self, deployment_type, network_mode):
        """配置部署参数"""
        print(f"\n⚙️ 配置{deployment_type}部署...")
        
        config = {
            "deployment_type": deployment_type,
            "network_mode": network_mode,
            "system_info": self.system_info
        }
        
        # 网络配置
        config["network"] = self._configure_network(network_mode)
        
        # 性能配置
        config["performance"] = self._configure_performance(deployment_type)
        
        # 安全配置
        config["security"] = self._configure_security(deployment_type)
        
        # 监控配置
        config["monitoring"] = self._configure_monitoring(deployment_type)
        
        self.deployment_config = config
        return config
    
    def _configure_network(self, network_mode):
        """配置网络参数"""
        network_config = {
            "mode": network_mode,
            "interfaces": self._detect_network_interfaces()
        }
        
        if network_mode == NetworkMode.BRIDGE.value:
            network_config.update({
                "bridge_name": "cfw-br0",
                "enable_stp": False,
                "forward_delay": 0
            })
        elif network_mode == NetworkMode.ROUTER.value:
            network_config.update({
                "enable_forwarding": True,
                "enable_nat": True,
                "wan_interface": "eth0",
                "lan_interface": "eth1"
            })
        elif network_mode == NetworkMode.TRANSPARENT.value:
            network_config.update({
                "capture_interface": "eth0",
                "enable_promiscuous": True,
                "buffer_size": 1024000
            })
        
        return network_config
    
    def _detect_network_interfaces(self):
        """检测网络接口"""
        interfaces = []
        try:
            if self.system_info["os"] == "Linux":
                result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ': ' in line and 'eth' in line:
                        interface = line.split(':')[1].strip().split('@')[0]
                        interfaces.append(interface)
            elif self.system_info["os"] == "Windows":
                result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True)
                # 解析Windows网络接口
                pass
        except:
            interfaces = ["eth0", "eth1"]  # 默认接口
        
        return interfaces
    
    def _configure_performance(self, deployment_type):
        """配置性能参数"""
        cpu_count = self.system_info["cpu_count"]
        
        if deployment_type in ["edge"]:
            # 边缘设备配置
            return {
                "max_worker_threads": min(2, cpu_count),
                "queue_size": 1000,
                "enable_caching": True,
                "cache_size": 500
            }
        elif deployment_type in ["docker", "kubernetes"]:
            # 容器配置
            return {
                "max_worker_threads": min(4, cpu_count),
                "queue_size": 5000,
                "enable_caching": True,
                "cache_size": 1000
            }
        else:
            # 服务器配置
            return {
                "max_worker_threads": min(8, cpu_count),
                "queue_size": 10000,
                "enable_caching": True,
                "cache_size": 2000
            }
    
    def _configure_security(self, deployment_type):
        """配置安全参数"""
        return {
            "enable_ssl_verification": True,
            "enable_threat_detection": True,
            "enable_sensitive_data_protection": True,
            "alert_on_suspicious_activity": True,
            "log_security_events": True
        }
    
    def _configure_monitoring(self, deployment_type):
        """配置监控参数"""
        return {
            "enable_metrics": True,
            "metrics_interval": 60,
            "enable_health_check": True,
            "health_check_port": 8080,
            "log_level": "INFO"
        }
    
    def generate_deployment_files(self):
        """生成部署文件"""
        deployment_type = self.deployment_config["deployment_type"]
        
        if deployment_type == "docker":
            self._generate_docker_files()
        elif deployment_type == "kubernetes":
            self._generate_kubernetes_files()
        elif deployment_type in ["cloud_aws", "cloud_azure", "cloud_gcp"]:
            self._generate_cloud_files()
        else:
            self._generate_standard_files()
    
    def _generate_docker_files(self):
        """生成Docker部署文件"""
        print("📦 生成Docker部署文件...")
        
        # Dockerfile
        dockerfile_content = '''FROM python:3.11-slim

# 安装系统依赖
RUN apt-get update && apt-get install -y \\
    libpcap-dev \\
    tcpdump \\
    iptables \\
    iproute2 \\
    bridge-utils \\
    && rm -rf /var/lib/apt/lists/*

# 创建应用目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 设置网络权限
RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/python

# 创建必要目录
RUN mkdir -p logs ssl_certs

# 暴露端口
EXPOSE 8080 8443

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
  CMD python -c "import requests; requests.get('http://localhost:8080/health')"

# 启动命令
CMD ["python", "main.py", "start", "--config", "config/firewall_config_extended.json"]
'''
        
        with open(self.project_root / "Dockerfile", "w") as f:
            f.write(dockerfile_content)
        
        # docker-compose.yml
        compose_content = '''version: '3.8'

services:
  cfw-firewall:
    build: .
    image: cfw:latest
    container_name: cfw-firewall
    restart: unless-stopped
    network_mode: host
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
      - ./ssl_certs:/app/ssl_certs
    environment:
      - CFW_LOG_LEVEL=INFO
      - CFW_NETWORK_MODE=transparent
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:8080/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # 可选：添加监控服务
  prometheus:
    image: prom/prometheus:latest
    container_name: cfw-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    container_name: cfw-grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-storage:/var/lib/grafana

volumes:
  grafana-storage:
'''
        
        with open(self.project_root / "docker-compose.yml", "w") as f:
            f.write(compose_content)
        
        print("✅ Docker文件生成完成")
    
    def _generate_kubernetes_files(self):
        """生成Kubernetes部署文件"""
        print("☸️ 生成Kubernetes部署文件...")
        
        k8s_dir = self.project_root / "k8s"
        k8s_dir.mkdir(exist_ok=True)
        
        # ConfigMap
        configmap_content = '''apiVersion: v1
kind: ConfigMap
metadata:
  name: cfw-config
  namespace: security
data:
  firewall_config_extended.json: |
    {
      "log_level": "INFO",
      "interface": "eth0",
      "dpi": {
        "enable": true,
        "enable_threat_detection": true
      },
      "sensitive_data_handling": {
        "strategy": "steganography",
        "alert_settings": {
          "enable_popup": false
        }
      }
    }
'''
        
        with open(k8s_dir / "configmap.yaml", "w") as f:
            f.write(configmap_content)
        
        # DaemonSet
        daemonset_content = '''apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cfw-firewall
  namespace: security
  labels:
    app: cfw-firewall
spec:
  selector:
    matchLabels:
      app: cfw-firewall
  template:
    metadata:
      labels:
        app: cfw-firewall
    spec:
      hostNetwork: true
      hostPID: true
      nodeSelector:
        cfw-enabled: "true"
      tolerations:
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: NoSchedule
      containers:
      - name: cfw
        image: cfw:latest
        imagePullPolicy: Always
        securityContext:
          privileged: true
          capabilities:
            add: ["NET_ADMIN", "NET_RAW", "SYS_ADMIN"]
        env:
        - name: CFW_NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: CFW_POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        - name: logs
          mountPath: /app/logs
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: cfw-config
      - name: logs
        hostPath:
          path: /var/log/cfw
          type: DirectoryOrCreate
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
'''
        
        with open(k8s_dir / "daemonset.yaml", "w") as f:
            f.write(daemonset_content)
        
        # Service
        service_content = '''apiVersion: v1
kind: Service
metadata:
  name: cfw-service
  namespace: security
  labels:
    app: cfw-firewall
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 8080
    targetPort: 8080
    protocol: TCP
  - name: metrics
    port: 9090
    targetPort: 9090
    protocol: TCP
  selector:
    app: cfw-firewall
'''
        
        with open(k8s_dir / "service.yaml", "w") as f:
            f.write(service_content)
        
        print("✅ Kubernetes文件生成完成")
    
    def _generate_cloud_files(self):
        """生成云平台部署文件"""
        cloud_platform = self.deployment_config["deployment_type"].replace("cloud_", "")
        print(f"☁️ 生成{cloud_platform.upper()}部署文件...")
        
        cloud_dir = self.project_root / "cloud" / cloud_platform
        cloud_dir.mkdir(parents=True, exist_ok=True)
        
        if cloud_platform == "aws":
            self._generate_aws_files(cloud_dir)
        elif cloud_platform == "azure":
            self._generate_azure_files(cloud_dir)
        elif cloud_platform == "gcp":
            self._generate_gcp_files(cloud_dir)
    
    def _generate_aws_files(self, cloud_dir):
        """生成AWS部署文件"""
        # CloudFormation模板
        cf_template = '''{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "CFW Firewall Deployment on AWS",
  "Parameters": {
    "InstanceType": {
      "Type": "String",
      "Default": "c5n.large",
      "Description": "EC2 instance type"
    },
    "KeyPairName": {
      "Type": "AWS::EC2::KeyPair::KeyName",
      "Description": "EC2 Key Pair for SSH access"
    }
  },
  "Resources": {
    "CFWSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Security group for CFW Firewall",
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIp": "0.0.0.0/0"
          },
          {
            "IpProtocol": "tcp",
            "FromPort": 8080,
            "ToPort": 8080,
            "CidrIp": "10.0.0.0/8"
          }
        ]
      }
    },
    "CFWInstance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "ami-0abcdef1234567890",
        "InstanceType": {"Ref": "InstanceType"},
        "KeyName": {"Ref": "KeyPairName"},
        "SecurityGroupIds": [{"Ref": "CFWSecurityGroup"}],
        "IamInstanceProfile": {"Ref": "CFWInstanceProfile"},
        "UserData": {
          "Fn::Base64": {
            "Fn::Join": ["", [
              "#!/bin/bash\\n",
              "yum update -y\\n",
              "yum install -y python3 git\\n",
              "cd /opt\\n",
              "git clone https://github.com/your-repo/CFW-Scripts.git\\n",
              "cd CFW-Scripts\\n",
              "python3 deploy_cfw.py\\n"
            ]]
          }
        }
      }
    }
  }
}'''
        
        with open(cloud_dir / "cloudformation.json", "w") as f:
            f.write(cf_template)
        
        # Terraform配置
        tf_config = '''provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region"
  default     = "us-west-2"
}

variable "instance_type" {
  description = "EC2 instance type"
  default     = "c5n.large"
}

resource "aws_security_group" "cfw_sg" {
  name_prefix = "cfw-firewall-"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "cfw_instance" {
  ami           = "ami-0abcdef1234567890"
  instance_type = var.instance_type
  
  vpc_security_group_ids = [aws_security_group.cfw_sg.id]
  
  user_data = file("${path.module}/install-cfw.sh")
  
  tags = {
    Name = "CFW-Firewall"
    Type = "Security"
  }
}

output "instance_public_ip" {
  value = aws_instance.cfw_instance.public_ip
}'''
        
        with open(cloud_dir / "main.tf", "w") as f:
            f.write(tf_config)
    
    def _generate_azure_files(self, cloud_dir):
        """生成Azure部署文件"""
        # ARM模板
        arm_template = '''{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vmSize": {
      "type": "string",
      "defaultValue": "Standard_D4s_v3",
      "metadata": {
        "description": "VM size"
      }
    }
  },
  "resources": [
    {
      "type": "Microsoft.Compute/virtualMachines",
      "apiVersion": "2019-07-01",
      "name": "cfw-vm",
      "location": "[resourceGroup().location]",
      "properties": {
        "hardwareProfile": {
          "vmSize": "[parameters('vmSize')]"
        },
        "osProfile": {
          "computerName": "cfw-vm",
          "adminUsername": "azureuser",
          "customData": "[base64(concat('#cloud-config\\npackages:\\n  - python3\\n  - git\\nruncmd:\\n  - cd /opt\\n  - git clone https://github.com/your-repo/CFW-Scripts.git\\n  - cd CFW-Scripts\\n  - python3 deploy_cfw.py'))]"
        }
      }
    }
  ]
}'''
        
        with open(cloud_dir / "azuredeploy.json", "w") as f:
            f.write(arm_template)
    
    def _generate_gcp_files(self, cloud_dir):
        """生成GCP部署文件"""
        # Deployment Manager配置
        dm_config = '''resources:
- name: cfw-instance
  type: compute.v1.instance
  properties:
    zone: us-central1-a
    machineType: zones/us-central1-a/machineTypes/n2-standard-4
    disks:
    - deviceName: boot
      type: PERSISTENT
      boot: true
      autoDelete: true
      initializeParams:
        sourceImage: projects/ubuntu-os-cloud/global/images/family/ubuntu-2004-lts
    networkInterfaces:
    - network: global/networks/default
      accessConfigs:
      - name: External NAT
        type: ONE_TO_ONE_NAT
    metadata:
      items:
      - key: startup-script
        value: |
          #!/bin/bash
          apt-get update
          apt-get install -y python3 git
          cd /opt
          git clone https://github.com/your-repo/CFW-Scripts.git
          cd CFW-Scripts
          python3 deploy_cfw.py
    tags:
      items:
      - cfw-firewall
'''
        
        with open(cloud_dir / "deployment.yaml", "w") as f:
            f.write(dm_config)
    
    def _generate_standard_files(self):
        """生成标准部署文件"""
        print("📄 生成标准部署文件...")
        
        # 系统服务文件
        if self.system_info["os"] == "Linux":
            service_content = '''[Unit]
Description=CFW Firewall Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/CFW-Scripts
ExecStart=/usr/bin/python3 main.py start --config config/firewall_config_extended.json
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
'''
            
            service_dir = Path("/etc/systemd/system")
            if service_dir.exists():
                with open(service_dir / "cfw-firewall.service", "w") as f:
                    f.write(service_content)
                print("✅ systemd服务文件已生成")
        
        # 安装脚本
        install_script = '''#!/bin/bash

set -e

echo "🚀 CFW防火墙系统安装脚本"
echo "========================="

# 检查root权限
if [[ $EUID -ne 0 ]]; then
   echo "❌ 此脚本需要root权限运行"
   exit 1
fi

# 检查系统
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo "❌ 无法识别的操作系统"
    exit 1
fi

echo "📋 系统信息: $OS $VER"

# 安装依赖
echo "📦 安装系统依赖..."
if [[ $OS == *"Ubuntu"* ]] || [[ $OS == *"Debian"* ]]; then
    apt-get update
    apt-get install -y python3 python3-pip git libpcap-dev
elif [[ $OS == *"CentOS"* ]] || [[ $OS == *"Red Hat"* ]]; then
    yum update -y
    yum install -y python3 python3-pip git libpcap-devel
else
    echo "⚠️ 未完全支持的系统，请手动安装依赖"
fi

# 创建目录
echo "📁 创建应用目录..."
mkdir -p /opt/CFW-Scripts
cd /opt/CFW-Scripts

# 下载代码（如果不存在）
if [[ ! -f "main.py" ]]; then
    echo "📥 下载CFW代码..."
    # git clone https://github.com/your-repo/CFW-Scripts.git .
    echo "请手动复制CFW代码到 /opt/CFW-Scripts"
fi

# 安装Python依赖
echo "🐍 安装Python依赖..."
python3 -m pip install -r requirements.txt

# 运行部署脚本
echo "🔧 执行自动部署..."
python3 deploy_cfw.py

# 配置服务
if [[ -f "/etc/systemd/system/cfw-firewall.service" ]]; then
    echo "🔄 配置系统服务..."
    systemctl daemon-reload
    systemctl enable cfw-firewall
    echo "✅ 服务配置完成，可以使用 'systemctl start cfw-firewall' 启动"
fi

echo "🎉 CFW防火墙系统安装完成！"
echo ""
echo "下一步:"
echo "1. 编辑配置文件: /opt/CFW-Scripts/config/firewall_config_extended.json"
echo "2. 启动服务: systemctl start cfw-firewall"
echo "3. 查看状态: systemctl status cfw-firewall"
echo "4. 查看日志: journalctl -u cfw-firewall -f"
'''
        
        with open(self.project_root / "install.sh", "w") as f:
            f.write(install_script)
        
        # 设置执行权限
        os.chmod(self.project_root / "install.sh", 0o755)
        
        print("✅ 标准部署文件生成完成")
    
    def save_deployment_config(self):
        """保存部署配置"""
        config_path = self.project_root / "deployment_config.json"
        with open(config_path, "w") as f:
            json.dump(self.deployment_config, f, indent=2)
        print(f"✅ 部署配置已保存到: {config_path}")
    
    def deploy(self):
        """执行部署流程"""
        print("🚀 CFW防火墙系统智能部署向导")
        print("=" * 50)
        
        # 推荐部署类型
        recommended_type = self.recommend_deployment_type()
        
        # 用户选择
        print(f"\n🎯 推荐部署类型: {recommended_type}")
        choice = input("是否使用推荐配置? (y/n): ").strip().lower()
        
        if choice != 'y':
            print("\n可选部署类型:")
            types = [t.value for t in DeploymentType]
            for i, t in enumerate(types, 1):
                print(f"{i}. {t}")
            
            try:
                selected = int(input("请选择部署类型 (1-8): ")) - 1
                deployment_type = types[selected]
            except (ValueError, IndexError):
                deployment_type = recommended_type
        else:
            deployment_type = recommended_type
        
        # 网络模式选择
        print("\n🌐 选择网络模式:")
        modes = [m.value for m in NetworkMode]
        for i, m in enumerate(modes, 1):
            print(f"{i}. {m}")
        
        try:
            selected = int(input("请选择网络模式 (1-4): ")) - 1
            network_mode = modes[selected]
        except (ValueError, IndexError):
            network_mode = NetworkMode.TRANSPARENT.value
        
        # 配置部署
        self.configure_deployment(deployment_type, network_mode)
        
        # 生成部署文件
        self.generate_deployment_files()
        
        # 保存配置
        self.save_deployment_config()
        
        print(f"\n🎉 {deployment_type}部署配置完成！")
        print("\n📋 生成的文件:")
        
        if deployment_type == "docker":
            print("- Dockerfile")
            print("- docker-compose.yml")
        elif deployment_type == "kubernetes":
            print("- k8s/configmap.yaml")
            print("- k8s/daemonset.yaml") 
            print("- k8s/service.yaml")
        elif "cloud_" in deployment_type:
            cloud = deployment_type.replace("cloud_", "")
            print(f"- cloud/{cloud}/ (云平台部署文件)")
        else:
            print("- install.sh")
            print("- /etc/systemd/system/cfw-firewall.service")
        
        print("- deployment_config.json")
        
        print("\n📚 参考文档: docs/DEPLOYMENT_OPTIONS.md")


def main():
    """主函数"""
    orchestrator = CFWDeploymentOrchestrator()
    orchestrator.deploy()


if __name__ == "__main__":
    main()
